"""Download a handful of real phishing emails from the public Phishing Pot corpus.

Source:  https://github.com/rf-peixoto/phishing_pot (honeypot-collected samples)
Licence: CC BY-NC 4.0, (c) rf-peixoto and contributors.

The files are saved to samples/corpus/, which is git-ignored on purpose: they are real
phishing emails that may contain live malicious links or attachments, so they are not
republished in this repository. PhishKit only parses them as text; nothing is opened
or executed.

Usage: python scripts/fetch_corpus.py
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/rf-peixoto/phishing_pot/main/email/"
FILES = [
    "sample-1.eml", "sample-10.eml", "sample-100.eml", "sample-101.eml", "sample-1001.eml",
    "sample-1002.eml", "sample-1003.eml", "sample-1004.eml", "sample-1006.eml", "sample-1012.eml",
]
OUT = Path(__file__).resolve().parent.parent / "samples" / "corpus"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        target = OUT / name
        if target.exists():
            print(f"skip {name} (already downloaded)")
            continue
        with urllib.request.urlopen(BASE + name, timeout=30) as response:
            target.write_bytes(response.read())
        print(f"saved samples/corpus/{name} ({target.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
