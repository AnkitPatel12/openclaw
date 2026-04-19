#!/usr/bin/env python3
"""Run a local ClawGuard scan and print JSON."""

from __future__ import annotations

import argparse
import json
import mimetypes
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan content with ClawGuard")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="Raw text to scan")
    source.add_argument("--file", help="Absolute path to a file to scan")
    parser.add_argument("--content-type", help="Optional MIME type override")
    parser.add_argument("--filename", help="Optional filename override")
    parser.add_argument("--tool-name", default="manual", help="Tool/source label")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(base_dir.parent))

    from clawguard.handler import scan_only  # noqa: PLC0415

    if args.text is not None:
        content = args.text
        content_type = args.content_type or "text/plain"
        filename = args.filename
    else:
        file_path = Path(args.file).expanduser().resolve()
        content = file_path.read_bytes()
        guessed_type, _ = mimetypes.guess_type(str(file_path))
        content_type = args.content_type or guessed_type
        filename = args.filename or file_path.name

    result = scan_only(
        content,
        content_type=content_type,
        filename=filename,
        tool_name=args.tool_name,
    )
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
