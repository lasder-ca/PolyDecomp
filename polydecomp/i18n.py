from __future__ import annotations

_STRINGS = {
    "en": {
        "title": "PolyDecomp",
        "open": "Open file",
        "export": "Export JSON",
        "language": "Language",
        "path": "Path",
        "format": "Format",
        "size": "Size",
        "sha256": "SHA-256",
        "architecture": "Architecture",
        "findings": "Findings",
        "warnings": "Warnings",
        "ready": "Choose a file to inspect.",
        "error": "Analysis error",
        "done": "Analysis complete.",
        "no_report": "Analyze a file before exporting.",
    },
    "ja": {
        "title": "PolyDecomp",
        "open": "ファイルを開く",
        "export": "JSONを書き出す",
        "language": "言語",
        "path": "パス",
        "format": "形式",
        "size": "サイズ",
        "sha256": "SHA-256",
        "architecture": "アーキテクチャ",
        "findings": "解析結果",
        "warnings": "警告",
        "ready": "解析するファイルを選択してください。",
        "error": "解析エラー",
        "done": "解析が完了しました。",
        "no_report": "先にファイルを解析してください。",
    },
}


def tr(language: str, key: str) -> str:
    table = _STRINGS.get(language, _STRINGS["en"])
    return table.get(key, _STRINGS["en"].get(key, key))
