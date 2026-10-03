"""Command-line interface: python -m phishkit analyze FILE [FILE ...]"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import analyze
from .render import render_text
from .scoring import EXIT_CODES

EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishkit",
        description="Analyse .eml files for phishing indicators: SPF/DKIM/DMARC, sender "
                    "mismatches, suspicious URLs and attachment hashes.",
        epilog="Exit codes: 0 clean, 1 suspicious, 2 likely phishing, 3 error.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    an = sub.add_parser("analyze", help="analyse one or more .eml files")
    an.add_argument("files", nargs="+", metavar="FILE", help="path to an .eml file")
    an.add_argument("--json", action="store_true", help="print JSON instead of a text report")
    an.add_argument("--live", action="store_true",
                    help="re-verify SPF/DKIM/DMARC against live DNS (network access)")
    an.add_argument("--vt", action="store_true",
                    help="look up hashes and URLs on VirusTotal (needs VT_API_KEY)")
    an.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    color = not args.no_color and sys.stdout.isatty()
    reports, worst = [], 0
    for path in args.files:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"phishkit: cannot read {path}: {exc.strerror or exc}", file=sys.stderr)
            return EXIT_ERROR
        report = analyze(raw, live=args.live, vt=args.vt)
        worst = max(worst, EXIT_CODES[report.verdict])
        if args.json:
            data = report.to_dict()
            data["file"] = path
            reports.append(data)
        else:
            if len(args.files) > 1:
                print(f"=== {path} ===")
            print(render_text(report, color=color))

    if args.json:
        print(json.dumps(reports[0] if len(reports) == 1 else reports, indent=2, ensure_ascii=False))
    return worst
