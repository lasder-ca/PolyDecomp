from __future__ import annotations

import struct

from .model import Finding


class JavaClassError(ValueError):
    pass


def _need(data: bytes, offset: int, length: int) -> None:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise JavaClassError("truncated Java class file")


def _u16(data: bytes, offset: int) -> int:
    _need(data, offset, 2)
    return struct.unpack_from(">H", data, offset)[0]


def inspect_java_class(data: bytes, *, max_constants: int = 20_000) -> tuple[dict[str, object], list[Finding]]:
    if not data.startswith(b"\xca\xfe\xba\xbe"):
        raise JavaClassError("invalid Java class magic")
    _need(data, 0, 10)
    minor = _u16(data, 4)
    major = _u16(data, 6)
    constant_pool_count = _u16(data, 8)
    if constant_pool_count == 0 or constant_pool_count > max_constants:
        raise JavaClassError("constant pool count exceeds safety limit")

    findings: list[Finding] = []
    offset = 10
    index = 1
    while index < constant_pool_count:
        _need(data, offset, 1)
        tag = data[offset]
        offset += 1

        if tag == 1:  # CONSTANT_Utf8
            length = _u16(data, offset)
            offset += 2
            _need(data, offset, length)
            raw = data[offset : offset + length]
            value = raw.decode("utf-8", errors="replace")
            findings.append(Finding("java-utf8", value, offset, {"constant_pool_index": index}))
            offset += length
        elif tag in {3, 4}:  # Integer, Float
            _need(data, offset, 4)
            offset += 4
        elif tag in {5, 6}:  # Long, Double occupy two entries
            _need(data, offset, 8)
            offset += 8
            index += 1
        elif tag in {7, 8, 16, 19, 20}:  # Class, String, MethodType, Module, Package
            _need(data, offset, 2)
            offset += 2
        elif tag in {9, 10, 11, 12, 17, 18}:  # refs, NameAndType, Dynamic, InvokeDynamic
            _need(data, offset, 4)
            offset += 4
        elif tag == 15:  # MethodHandle
            _need(data, offset, 3)
            offset += 3
        else:
            raise JavaClassError(f"unknown constant-pool tag {tag} at index {index}")
        index += 1

    return {
        "minor_version": minor,
        "major_version": major,
        "constant_pool_count": constant_pool_count,
        "constant_pool_bytes": offset - 10,
    }, findings
