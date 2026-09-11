#!/usr/bin/env python3
"""Baseline track 4: what directed symbolic execution finds on its own.

Calls the same engine the constraint stage calls, with the chunk written out by
hand -- a baseline must not depend on the agent layer to produce a number.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "agent"))
import tools  # noqa: E402

CHUNK = {"chunk_id": "baseline", "members": ["parse_config"],
         "entry": "parse_config",
         "args": [{"name": "in", "kind": "sym_buf", "size": 64},
                  {"name": "len", "kind": "concrete", "value": 64}]}

d = tools.call("symex_chunk", {"chunk": CHUNK, "budget_s": 120})
if d.get("error"):
    print("  FATAL: %s" % d["error"])
    sys.exit(1)
for r in d.get("results", []):
    print("  sink=%s dest_capacity=%s (%s)"
          % (r["sink"]["callee"], r.get("dest_capacity"), r.get("capacity_source")))
    print("  length_max=%s overflow=%s" % (r.get("length_max"), r.get("overflow")))
    if r.get("solved"):
        print("  SOLVED input: %s..." % list(r["solved"].values())[0][:24])
    if r.get("proved_unreachable"):
        print("  PROVED UNREACHABLE: %s" % r["proved_unreachable"])
if not d.get("results"):
    print("  NO SINK REACHED - harness problem, fix before adding an agent")
    sys.exit(1)
