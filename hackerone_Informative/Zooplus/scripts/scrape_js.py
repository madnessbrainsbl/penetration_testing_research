#!/usr/bin/env python3
"""
Download a page and extract JS URLs.
Usage: python scrape_js.py --url https://www.zooplus.de/account/overview --limit 40
"""
import argparse
import re
import sys

import requests


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--limit", type=int, default=40)
    args = parser.parse_args()

    resp = requests.get(args.url, headers={"User-Agent": "Mozilla/5.0"})
    resp.raise_for_status()
    html = resp.text
    urls = list({m.group(0) for m in re.finditer(r'https?://[^"\\s]+\\.js[^"\\s]*', html)})
    for u in urls[: args.limit]:
        print(u)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

