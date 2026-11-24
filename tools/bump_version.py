#!/usr/bin/env python3
"""Incrémente la version de SYNTRAF (DefaultValues.SYNTRAF_VERSION dans lib/st_global.py).

    python tools/bump_version.py            # 0.45.3 -> 0.45.4 (fait à chaque commit par .githooks/pre-commit)
    python tools/bump_version.py --minor    # 0.45.3 -> 0.46.0 (version notable, à la main)
    python tools/bump_version.py --major    # 0.45.3 -> 1.0.0

Le hook s'active une fois par clone : git config core.hooksPath .githooks ; SYNTRAF_NO_BUMP=1 git commit ... le saute.
"""
import re
import sys
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "lib" / "st_global.py"
LINE = re.compile(r'^(\s*SYNTRAF_VERSION\s*=\s*")([0-9]+(?:\.[0-9]+)*)(")', re.M)


def next_version(version, part="patch"):
    major, minor, patch = (list(map(int, version.split("."))) + [0, 0])[:3]
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def bump(path=FILE, part="patch"):
    with open(path, encoding="utf-8", newline="") as f:  # garde les fins de ligne du fichier
        text = f.read()
    m = LINE.search(text)
    if not m:
        raise SystemExit(f"SYNTRAF_VERSION introuvable dans {path}")
    old = m.group(2)
    new = next_version(old, part)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text[:m.start(2)] + new + text[m.end(2):])
    return old, new


if __name__ == "__main__":
    part = "major" if "--major" in sys.argv else "minor" if "--minor" in sys.argv else "patch"
    old, new = bump(part=part)
    print(f"SYNTRAF {old} -> {new}")
