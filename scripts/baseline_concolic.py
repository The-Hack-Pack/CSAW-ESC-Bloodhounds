#!/usr/bin/env python3
"""Baseline track 4b: what concolic execution finds from a garbage seed.

Starts from 64 bytes of 0x41 -- no magic value, no hint -- and reports what
branch negation recovers. Every generated input is replayed through the ASan
harness, so a crash here is an observation.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "agent"))
import tools  # noqa: E402

CHUNK = {"chunk_id": "baseline", "members": ["parse_config"],
         "entry": "parse_config", "poc_prefix_hex": "00",
         "args": [{"name": "in", "kind": "sym_buf", "size": 64},
                  {"name": "len", "kind": "seed_len"}]}

d = tools.call("concolic_chunk", {"chunk": CHUNK, "seeds": ["41" * 64],
                                  "generations": 3, "budget_s": 240})
if d.get("error"):
    print("  FATAL: %s" % d["error"])
    sys.exit(1)
print("  generations=%s blocks_covered=%s inputs_generated=%s"
      % (d.get("generation_count"), d.get("blocks_covered"), d.get("inputs_generated")))
crash = d.get("crashing_inputs") or []
if not crash:
    print("  no crashing input generated - check the seed and poc_prefix_hex")
    sys.exit(1)
for c in crash[:2]:
    ev = [l for l in (c.get("replay", {}).get("report", "")).splitlines()
          if "ERROR: AddressSanitizer" in l or "overflows this variable" in l]
    print("  CRASHING poc=%s (flipped at %s)" % (c["poc_hex"][:22] + "...", c["flipped_at"]))
    for l in ev[:2]:
        print("    %s" % l.strip()[:110])
