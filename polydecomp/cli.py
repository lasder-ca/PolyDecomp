from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import AnalysisError, analyze_file


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="polydecomp", description="Static decompilation and inspection workbench")
    parser.add_argument("input", type=Path, help="file to inspect")
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    parser.add_argument("--output", type=Path, help="write JSON report to a file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = analyze_file(args.input)
    except AnalysisError as exc:
        print(f"polydecomp: {exc}", file=sys.stderr)
        return 2

    payload = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    if args.json or not args.output:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
