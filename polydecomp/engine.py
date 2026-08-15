from __future__ import annotations

import hashlib
from pathlib import Path

from .formats import detect_format, extract_strings
from .java_class import JavaClassError, inspect_java_class
from .model import AnalysisReport
from .source_outline import outline_source

MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_ANALYSIS_BYTES = 16 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024


class AnalysisError(ValueError):
    pass


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_file(path_value: str | Path) -> AnalysisReport:
    path = Path(path_value).expanduser()
    try:
        stat = path.stat()
    except OSError as exc:
        raise AnalysisError(f"cannot stat input: {exc}") from exc
    if not path.is_file():
        raise AnalysisError("input is not a regular file")
    if stat.st_size > MAX_FILE_BYTES:
        raise AnalysisError(f"input exceeds {MAX_FILE_BYTES // (1024 * 1024)} MiB safety limit")

    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_ANALYSIS_BYTES + 1)
    except OSError as exc:
        raise AnalysisError(f"cannot read input: {exc}") from exc

    truncated = len(data) > MAX_ANALYSIS_BYTES
    if truncated:
        data = data[:MAX_ANALYSIS_BYTES]

    info = detect_format(data, path.suffix)
    report = AnalysisReport(
        path=str(path),
        size=stat.st_size,
        sha256=_hash_file(path),
        format=info.name,
        architecture=info.architecture,
        metadata=dict(info.metadata or {}),
    )
    if truncated:
        report.warnings.append(f"deep inspection limited to first {MAX_ANALYSIS_BYTES // (1024 * 1024)} MiB")

    if info.name == "Java class":
        try:
            java_meta, java_findings = inspect_java_class(data)
            report.metadata.update(java_meta)
            report.findings.extend(java_findings)
        except JavaClassError as exc:
            report.warnings.append(f"Java parser: {exc}")

    if info.name == "Source text":
        text = data.decode("utf-8", errors="replace")
        hint = str(report.metadata.get("language_hint") or "")
        outline, warnings = outline_source(text, hint)
        report.findings.extend(outline)
        report.warnings.extend(warnings)

    report.findings.extend(extract_strings(data))
    return report
