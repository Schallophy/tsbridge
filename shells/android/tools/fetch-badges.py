#!/usr/bin/env python3
"""Fetch the myTeamSpeak badge artwork into `badges/`.

    tools/fetch-badges.py [out-dir]

The official client reads `https://badges-content.teamspeak.com/list` (a
protobuf list of uuid / name / url) and downloads the artwork at that url plus
`.svg`. This script does the same, so the checked-in set can be refreshed
without a browser: it pulls the list, scrapes the URLs out of the protobuf (the
UUID is part of the path, so no schema is needed), and writes one SVG per badge.

Existing files are not re-downloaded unless `--force` is given; the list only
grows, so a normal run adds the new badges and leaves the old bytes alone.
"""
import argparse
import os
import re
import sys
import time
import urllib.request

LIST = "https://badges-content.teamspeak.com/list"
HOST = re.compile(rb"https://badges-content\.teamspeak\.com/[0-9a-f-]{36}/[^\s\"<>]+")


def get(url, binary=True, attempts=3):
    last = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 - retried below
            last = e
            time.sleep(0.5 * (attempt + 1))
    raise SystemExit(f"{url}: {last}")


def main(out, force):
    os.makedirs(out, exist_ok=True)
    # The list is protobuf, but every entry carries its artwork URL as plain
    # bytes; the UUID is the path segment, so a regex is enough.
    raw = re.sub(rb"[^\x20-\x7e]", b"\n", get(LIST))
    urls = sorted(set(m.group(0).decode() for m in HOST.finditer(raw)))
    if not urls:
        raise SystemExit("no badge urls in the list")
    print(f"{len(urls)} badges listed")

    added = skipped = 0
    for url in urls:
        uuid = url.rsplit("/", 2)[-2]
        path = os.path.join(out, uuid + ".svg")
        if os.path.exists(path) and not force:
            skipped += 1
            continue
        try:
            data = get(url + ".svg")
        except SystemExit as e:
            print(f"  failed {uuid}: {e}")
            continue
        with open(path, "wb") as f:
            f.write(data)
        added += 1
    print(f"{out}: {added} written, {skipped} already present")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("out", nargs="?", default="shells/android/badges")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    main(args.out, args.force)
    sys.exit(0)
