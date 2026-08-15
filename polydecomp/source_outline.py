from __future__ import annotations

import ast
import re

from .model import Finding

_MAX_OUTLINE_ITEMS = 2_000

_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "js": (
        re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
        re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)"),
    ),
    "mjs": (
        re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
        re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)"),
    ),
    "cjs": (
        re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
        re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)"),
    ),
    "ts": (
        re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
        re.compile(r"\b(?:class|interface|type|enum)\s+([A-Za-z_$][\w$]*)"),
    ),
    "tsx": (
        re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
        re.compile(r"\b(?:class|interface|type|enum)\s+([A-Za-z_$][\w$]*)"),
    ),
    "jsx": (
        re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
        re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)"),
    ),
    "go": (
        re.compile(r"(?m)^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("),
        re.compile(r"(?m)^\s*type\s+([A-Za-z_]\w*)\s+"),
    ),
    "rs": (
        re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]"),
        re.compile(r"\b(?:struct|enum|trait)\s+([A-Za-z_]\w*)"),
    ),
    "java": (
        re.compile(r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)"),
        re.compile(r"(?m)^\s*(?:public|protected|private|static|final|synchronized|abstract|native|strictfp|\s)+[\w<>\[\], ?]+\s+([A-Za-z_$][\w$]*)\s*\("),
    ),
    "lua": (
        re.compile(r"\bfunction\s+([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)\s*\("),
    ),
}


def outline_source(text: str, language_hint: str | None) -> tuple[list[Finding], list[str]]:
    if language_hint == "py":
        return _outline_python(text)
    patterns = _PATTERNS.get(language_hint or "", ())
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            name = match.group(1)
            key = (name, match.start(1))
            if key in seen:
                continue
            seen.add(key)
            line = text.count("\n", 0, match.start(1)) + 1
            findings.append(Finding("symbol", name, match.start(1), {"line": line, "language": language_hint}))
            if len(findings) >= _MAX_OUTLINE_ITEMS:
                return findings, ["source outline truncated at safety limit"]
    return findings, []


def _outline_python(text: str) -> tuple[list[Finding], list[str]]:
    try:
        tree = ast.parse(text, mode="exec")
    except SyntaxError as exc:
        return [], [f"Python parse error: line {exc.lineno}: {exc.msg}"]

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            findings.append(
                Finding(
                    "symbol",
                    node.name,
                    None,
                    {"line": node.lineno, "column": node.col_offset, "node": type(node).__name__, "language": "py"},
                )
            )
            if len(findings) >= _MAX_OUTLINE_ITEMS:
                return findings, ["source outline truncated at safety limit"]
    return findings, []
