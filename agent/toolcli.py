#!/usr/bin/env python3
"""Command-line front end for the tool layer.

Dispatches through tools.call(), the same entry point pipeline.py uses, so an
external driver -- a human, a shell script, a Claude Code subagent -- exercises
exactly the contract the API loop exercises. There is no second code path to
keep in sync.

    python3 agent/toolcli.py                                   # list tools
    python3 agent/toolcli.py --stage chunk                     # one stage's tools
    python3 agent/toolcli.py list_functions '{"limit": 10}'
    python3 agent/toolcli.py function_info '{"name": "parse_config"}'
    python3 agent/toolcli.py symex_chunk '{"chunk": {...}}'
    python3 agent/toolcli.py validate_poc '{"poc_hex": "00c0003d41"}'

Arguments are a single JSON object. Use --file to read them from a file when a
chunk spec gets unwieldy for a shell quote.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stages  # noqa: E402
import tools   # noqa: E402


def _usage(stage=None):
    print(__doc__)
    names = stages.BY_NAME[stage]["tools"] if stage else sorted(tools.DISPATCH)
    print("tools%s:" % (" for stage %r" % stage if stage else ""))
    for n in names:
        d = tools.SCHEMAS.get(n, {}).get("description", "")
        print("  %-20s %s" % (n, d.split(". ")[0]))
    if not stage:
        print("\nstages: %s" % ", ".join(stages.BY_NAME))


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--stage":
        if len(argv) < 2 or argv[1] not in stages.BY_NAME:
            print("--stage needs one of: %s" % ", ".join(stages.BY_NAME),
                  file=sys.stderr)
            return 2
        _usage(argv[1])
        return 0
    if not argv or argv[0] in ("-h", "--help"):
        _usage()
        return 0

    name = argv[0]
    if name not in tools.DISPATCH:
        print("unknown tool %r. Run with --help for the list." % name,
              file=sys.stderr)
        return 2

    args = {}
    if len(argv) > 2 and argv[1] == "--file":
        with open(argv[2]) as f:
            args = json.load(f)
    elif len(argv) > 1:
        try:
            args = json.loads(argv[1])
        except json.JSONDecodeError as e:
            print("error: argument 2 must be a JSON object (%s)" % e,
                  file=sys.stderr)
            return 2

    out = tools.call(name, args)
    print(out if isinstance(out, str) else json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
