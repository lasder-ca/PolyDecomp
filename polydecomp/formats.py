from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from .model import Finding

_MAX_STRING_COUNT = 2_000
_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


@dataclass(slots=True)
class FormatInfo:
    name: str
    architecture: str | None = None
    metadata: dict[str, object] | None = None


def _u16(data: bytes, offset: int, endian: str = "<") -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from(f"{endian}H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str = "<") -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from(f"{endian}I", data, offset)[0]


def _looks_like_java_class(data: bytes, suffix: str) -> bool:
    if not data.startswith(b"\xca\xfe\xba\xbe"):
        return False
    if suffix == ".class":
        return True
    # CAFEBABE is also the big-endian fat Mach-O magic. Java class files place
    # minor/major u16 versions immediately after the magic; supported/known
    # class-file majors are well above the tiny architecture-count field used
    # by fat Mach-O. Keep a conservative upper bound so malformed data fails
    # into generic/fat inspection rather than being over-classified as Java.
    major = _u16(data, 6, ">")
    return major is not None and 45 <= major <= 100


def detect_format(data: bytes, suffix: str = "") -> FormatInfo:
    suffix = suffix.lower()
    if data.startswith(b"MZ"):
        pe_offset = _u32(data, 0x3C)
        meta: dict[str, object] = {}
        arch = None
        if pe_offset is not None and pe_offset + 6 <= len(data) and data[pe_offset : pe_offset + 4] == b"PE\0\0":
            machine = _u16(data, pe_offset + 4)
            machine_names = {0x014C: "x86", 0x8664: "x86_64", 0xAA64: "arm64", 0x01C4: "arm"}
            arch = machine_names.get(machine, f"machine-0x{machine:04x}" if machine is not None else None)
            meta["pe_offset"] = pe_offset
            if machine is not None:
                meta["machine"] = machine
        return FormatInfo("PE", arch, meta)

    if data.startswith(b"\x7fELF") and len(data) >= 20:
        elf_class = {1: "32-bit", 2: "64-bit"}.get(data[4], "unknown")
        endian = "<" if data[5] == 1 else ">" if data[5] == 2 else "<"
        machine = _u16(data, 18, endian)
        machines = {3: "x86", 40: "arm", 62: "x86_64", 183: "arm64", 243: "riscv"}
        return FormatInfo("ELF", machines.get(machine), {"class": elf_class, "machine": machine})

    if _looks_like_java_class(data, suffix):
        return FormatInfo("Java class")

    magic4 = data[:4]
    macho = {
        b"\xfe\xed\xfa\xce": ("32-bit", ">"),
        b"\xce\xfa\xed\xfe": ("32-bit", "<"),
        b"\xfe\xed\xfa\xcf": ("64-bit", ">"),
        b"\xcf\xfa\xed\xfe": ("64-bit", "<"),
        b"\xca\xfe\xba\xbe": ("fat", ">"),
    }
    if magic4 in macho:
        width, endian = macho[magic4]
        cpu = _u32(data, 4, endian) if width != "fat" else None
        metadata: dict[str, object] = {"class": width}
        if width == "fat":
            architecture_count = _u32(data, 4, ">")
            if architecture_count is not None:
                metadata["architecture_count"] = architecture_count
        elif cpu is not None:
            metadata["cpu_type"] = cpu
        return FormatInfo("Mach-O", None, metadata)

    if data.startswith(b"\x00asm"):
        version = _u32(data, 4) if len(data) >= 8 else None
        return FormatInfo("WebAssembly", "wasm32", {"version": version})
    if data.startswith(b"\x1bLua"):
        version = data[4] if len(data) > 4 else None
        return FormatInfo("Lua bytecode", None, {"version_byte": version})
    if suffix == ".pyc" and len(data) >= 16:
        return FormatInfo("Python bytecode", None, {"magic_hex": data[:4].hex(), "header_hex": data[:16].hex()})
    if suffix in {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".lua", ".java", ".rs", ".go"}:
        return FormatInfo("Source text", None, {"language_hint": suffix.lstrip(".")})
    if _looks_text(data):
        return FormatInfo("Text")
    return FormatInfo("Unknown binary")


def _looks_text(data: bytes) -> bool:
    sample = data[:4096]
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    printable = sum(byte in b"\t\n\r" or 0x20 <= byte <= 0x7E or byte >= 0x80 for byte in sample)
    return printable / len(sample) >= 0.90


def extract_strings(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for match in _ASCII_RE.finditer(data):
        findings.append(Finding("string", match.group().decode("ascii", errors="replace"), match.start(), {"encoding": "ascii"}))
        if len(findings) >= _MAX_STRING_COUNT:
            return findings
    for match in _UTF16LE_RE.finditer(data):
        findings.append(Finding("string", match.group().decode("utf-16le", errors="replace"), match.start(), {"encoding": "utf-16le"}))
        if len(findings) >= _MAX_STRING_COUNT:
            break
    return findings
