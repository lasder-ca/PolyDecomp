from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from polydecomp.engine import analyze_file
from polydecomp.formats import detect_format, extract_strings
from polydecomp.java_class import inspect_java_class
from polydecomp.source_outline import outline_source


class FormatTests(unittest.TestCase):
    def test_detects_pe_architecture(self) -> None:
        data = bytearray(256)
        data[:2] = b"MZ"
        data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        data[0x80:0x84] = b"PE\0\0"
        data[0x84:0x86] = (0x8664).to_bytes(2, "little")
        info = detect_format(bytes(data), ".exe")
        self.assertEqual(info.name, "PE")
        self.assertEqual(info.architecture, "x86_64")

    def test_class_suffix_wins_over_fat_macho_magic(self) -> None:
        info = detect_format(b"\xca\xfe\xba\xbe\x00\x00\x00=", ".class")
        self.assertEqual(info.name, "Java class")

    def test_java_version_disambiguates_without_suffix(self) -> None:
        info = detect_format(b"\xca\xfe\xba\xbe\x00\x00\x00=", "")
        self.assertEqual(info.name, "Java class")

    def test_fat_macho_architecture_count_remains_macho(self) -> None:
        info = detect_format(b"\xca\xfe\xba\xbe\x00\x00\x00\x02", "")
        self.assertEqual(info.name, "Mach-O")
        self.assertEqual(info.metadata, {"class": "fat", "architecture_count": 2})

    def test_extracts_ascii_and_utf16_strings(self) -> None:
        findings = extract_strings(b"xx HELLO yy\x00W\x00O\x00R\x00L\x00D\x00")
        values = {finding.value for finding in findings}
        self.assertIn("HELLO", values)
        self.assertIn("WORLD", values)


class JavaTests(unittest.TestCase):
    def test_reads_utf8_constant(self) -> None:
        data = b"\xca\xfe\xba\xbe" + b"\x00\x00\x00=" + b"\x00\x02" + b"\x01\x00\x05Hello"
        meta, findings = inspect_java_class(data)
        self.assertEqual(meta["major_version"], 61)
        self.assertEqual(findings[0].value, "Hello")


class SourceTests(unittest.TestCase):
    def test_python_ast_outline(self) -> None:
        findings, warnings = outline_source("class A:\n    def method(self):\n        pass\n", "py")
        self.assertFalse(warnings)
        self.assertEqual({item.value for item in findings}, {"A", "method"})

    def test_engine_never_imports_python_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "executed.txt"
            target = Path(temp_dir) / "sample.py"
            target.write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\ndef safe():\n    return 1\n", encoding="utf-8")
            report = analyze_file(target)
            self.assertEqual(report.format, "Source text")
            self.assertFalse(marker.exists())
            self.assertIn("safe", {item.value for item in report.findings if item.kind == "symbol"})


if __name__ == "__main__":
    unittest.main()
