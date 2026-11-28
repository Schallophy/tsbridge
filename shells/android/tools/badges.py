#!/usr/bin/env python3
"""Turn `badges/*.svg` into Android VectorDrawables.

    tools/badges.py <svg-dir> <out-dir>

Each badge is named by its myTeamSpeak UUID, and the output keeps it:
`badge_<uuid with '-' -> '_'>.xml`. The shell looks a badge up by UUID, so the
name is the mapping — there is no table to keep in step.

The source files are the badge artwork myTeamSpeak serves, fetched once and
checked in (see `badges/README.md`). Not all of them are expressible as a
VectorDrawable: a rotated transform, an `objectBoundingBox` gradient or a
`fill:none` stroke is refused by `svg2vector.py` rather than approximated. Those
are reported and skipped — a missing badge is better than a wrong picture, and
the build must not fail because one of ninety badges uses a shape the converter
does not claim to handle.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import svg2vector  # noqa: E402


def main(src, out):
    os.makedirs(out, exist_ok=True)
    written = skipped = 0
    for name in sorted(os.listdir(src)):
        if not name.endswith(".svg"):
            continue
        uuid = name[: -len(".svg")]
        resource = "badge_" + uuid.replace("-", "_")
        try:
            text, warns = svg2vector.convert(os.path.join(src, name), uuid)
        except SystemExit as e:
            print(f"  skip {uuid}: {e}")
            skipped += 1
            continue
        with open(os.path.join(out, resource + ".xml"), "w") as f:
            f.write(text + "\n")
        for w in warns:
            print(f"  warn {uuid}: {w}")
        written += 1
    print(f"{out}: {written} badges, {skipped} skipped")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: badges.py <svg-dir> <out-dir>")
    main(sys.argv[1], sys.argv[2])
