#!/usr/bin/env python3
"""Command-line front end for the tool layer.

Dispatches through tools.call(), the same entry point run_agent.py uses, so an
external driver (a human, a shell script, another agent) exercises exactly the
contract the LLM loop exercises -- there is no second code path to keep in sync.

    python3 agent/toolcli.py list_files
    python3 agent/toolcli.py read_source '{"path": "host_twin/target.c", "start": 40, "end": 60}'
    python3 agent/toolcli.py validate_poc '{"poc_hex": "00c0003d0000"}'
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tools  # noqa: E402


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        print("available tools:")
        for t in tools.SCHEMAS:
            print("  %-18s %s" % (t["name"], t["description"]))
        return 0

    name = sys.argv[1]
    try:
        args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    except json.JSONDecodeError as e:
        print("error: argument 2 must be a JSON object (%s)" % e, file=sys.stderr)
        return 2

    out = tools.call(name, args)
    print(out if isinstance(out, str) else json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
