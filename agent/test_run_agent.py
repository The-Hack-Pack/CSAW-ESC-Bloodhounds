#!/usr/bin/env python3
"""Tests for run_agent.extract_findings_blob -- the guard that turns a model's
final message into a scorer-shaped findings file. Runs without the SDK.

    python3 agent/test_run_agent.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_agent import extract_findings_blob  # noqa: E402

_fails = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        _fails.append(name)


# fenced json object with prose around it (the common case)
t1 = 'Here is my report.\n```json\n{"findings": [{"id": "F-1", "function": "parse_config"}]}\n```\nDone.'
o1 = extract_findings_blob(t1)
check("fenced object: one finding", len(o1["findings"]) == 1)
check("fenced object: keeps function", o1["findings"][0]["function"] == "parse_config")

# bare array, no fence
t2 = 'Final answer: [{"id": "F-1"}, {"id": "F-2"}]'
o2 = extract_findings_blob(t2)
check("bare array: two findings", len(o2["findings"]) == 2)

# object with findings + rejected, inline
t3 = '{"findings": [{"id":"F-1"}], "rejected": [{"construct":"x"}]}'
o3 = extract_findings_blob(t3)
check("inline object: preserves rejected", o3.get("rejected") == [{"construct": "x"}])

# unparseable prose -> diagnostic, never a crash, raw preserved
t4 = "I could not find any bugs; here is my reasoning without JSON."
o4 = extract_findings_blob(t4)
check("prose: empty findings", o4["findings"] == [])
check("prose: flags parse_error", "parse_error" in o4)
check("prose: preserves raw", o4.get("raw", "").startswith("I could not"))

# last fenced block wins when several are present
t5 = '```json\n{"findings":[{"id":"draft"}]}\n```\nrevised:\n```json\n{"findings":[{"id":"final"},{"id":"final2"}]}\n```'
o5 = extract_findings_blob(t5)
check("multiple fences: last wins", [f["id"] for f in o5["findings"]] == ["final", "final2"])

print()
if _fails:
    print(f"FAIL: {len(_fails)} assertion(s): {', '.join(_fails)}")
    sys.exit(1)
print("PASS: all assertions held")
