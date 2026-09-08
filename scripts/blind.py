#!/usr/bin/env python3
"""Blind the testbed for an honest agent experiment, and restore it after.

    python3 scripts/blind.py on     # hide the answers
    python3 scripts/blind.py off    # put everything back

The source is self-documenting to the point of giving the game away: comment
banners name BUG-001/002/003 directly above the vulnerable functions, inline
markers label the CHECK and the USE, and the driver comments explain the
mechanism. Measuring "bugs found" against that measures reading comprehension.

Rather than hand-authoring neutral replacements (fragile, and easy to miss a
hint), this strips C comments wholesale while preserving the exact line and
column count, so every line number in ground_truth.json still refers to the
same statement. It also moves the answer key and the README aside.

Restore is exact: originals are copied verbatim into .blind_stash/.
"""
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STASH = os.path.join(ROOT, ".blind_stash")
STRIP = ["host_twin/target.c", "host_twin/target.h",
         "host_twin/main.c", "host_twin/fuzz_entry.c"]
HIDE = ["ground_truth.json", "README.md"]


def strip_comments(src):
    """Replace comment bodies with spaces, keeping every newline. Character
    positions are preserved so nothing shifts."""
    out = []
    i, n = 0, len(src)
    state = "code"
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "*":
                state, i = "block", i + 2
                out.append("  ")
                continue
            if c == "/" and nxt == "/":
                state, i = "line", i + 2
                out.append("  ")
                continue
            if c in ('"', "'"):
                state, quote = "str", c
                out.append(c)
                i += 1
                continue
            out.append(c)
        elif state == "str":
            out.append(c)
            if c == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if c == quote:
                state = "code"
        elif state == "block":
            if c == "*" and nxt == "/":
                state, i = "code", i + 2
                out.append("  ")
                continue
            out.append("\n" if c == "\n" else " ")
        elif state == "line":
            if c == "\n":
                state = "code"
                out.append("\n")
            else:
                out.append(" ")
        i += 1
    return "".join(out)


def on():
    if os.path.isdir(STASH):
        sys.exit("already blinded -- run `blind.py off` first")
    os.makedirs(STASH)
    for rel in STRIP:
        src = os.path.join(ROOT, rel)
        shutil.copy2(src, os.path.join(STASH, os.path.basename(rel)))
        text = open(src).read()
        blinded = strip_comments(text)
        assert text.count("\n") == blinded.count("\n"), rel
        open(src, "w").write(blinded)
        print("stripped comments: %s" % rel)
    for rel in HIDE:
        p = os.path.join(ROOT, rel)
        if os.path.exists(p):
            shutil.move(p, os.path.join(STASH, rel))
            print("hidden: %s" % rel)
    print("\nBLINDED. Restore with: python3 scripts/blind.py off")


def off():
    if not os.path.isdir(STASH):
        sys.exit("not blinded -- nothing to restore")
    for rel in STRIP:
        shutil.copy2(os.path.join(STASH, os.path.basename(rel)), os.path.join(ROOT, rel))
        print("restored: %s" % rel)
    for rel in HIDE:
        p = os.path.join(STASH, rel)
        if os.path.exists(p):
            shutil.move(p, os.path.join(ROOT, rel))
            print("restored: %s" % rel)
    shutil.rmtree(STASH)
    print("\nRESTORED.")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("on", "off"):
        sys.exit(__doc__)
    (on if sys.argv[1] == "on" else off)()
