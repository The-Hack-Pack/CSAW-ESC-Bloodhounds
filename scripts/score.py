#!/usr/bin/env python3
"""Score an agent run against the answer key (README step 17).

    python3 scripts/score.py agent/artifacts/findings.json

Matches on the function name at the defect site, which is stable across
line-number drift. Reports bugs found (weighted by difficulty), false
positives against the documented decoys, and PoC-gate coverage.

One structural caveat this prints explicitly: a planted bug whose answer-key
entry carries no `poc` cannot be proven through validate_poc, because the gate
only recognises a sanitizer abort. An agent obeying the "no finding without a
validated PoC" rule therefore cannot report it, and the achievable maximum is
below 3/3. That is a property of the testbed, not of the agent.
"""
import json
import os
import sys

WEIGHT = {"easy": 1, "medium": 2, "hard": 3}


def main():
    gt_path = "ground_truth.json"
    # The pipeline writes to agent/artifacts/; the pre-pipeline runs wrote to
    # agent/findings.json. Prefer the new location, fall back to the old.
    defaults = ["agent/artifacts/findings.json", "agent/findings.json"]
    fi_path = (sys.argv[1] if len(sys.argv) > 1
               else next((d for d in defaults if os.path.exists(d)), defaults[0]))
    gt = json.load(open(gt_path))
    fi = json.load(open(fi_path))
    findings = fi.get("findings", [])
    rejected = fi.get("rejected", [])

    reported_fns = {(f.get("function") or "").strip() for f in findings}
    decoy_fns = {"rfid_isr", "eeprom_write"}

    print("=" * 66)
    print("BUGS")
    print("=" * 66)
    got = maxw = 0
    unprovable = []
    for b in gt["bugs"]:
        fn = b["site"]["function"]
        w = WEIGHT[b["difficulty"]]
        maxw += w
        hit = fn in reported_fns
        provable = "poc" in b
        if not provable:
            unprovable.append(b["id"])
        if hit:
            got += w
        seen = any(fn in (r.get("construct", "") + r.get("why_not_a_bug", "")) for r in rejected)
        state = "FOUND" if hit else ("SEEN-BUT-NOT-REPORTED" if seen else "MISSED")
        print("  %-8s %-17s %-6s w=%d  %s%s" % (
            b["id"], fn, b["difficulty"], w, state,
            "" if provable else "   [no PoC in answer key -> gate cannot validate]"))

    print()
    print("=" * 66)
    print("FALSE POSITIVES (decoys reported as vulnerabilities)")
    print("=" * 66)
    fps = [f for f in findings if (f.get("function") or "") in decoy_fns]
    if fps:
        for f in fps:
            print("  %s reported %s -- decoy" % (f.get("id"), f.get("function")))
    else:
        print("  none")

    print()
    print("=" * 66)
    print("POC GATE")
    print("=" * 66)
    unval = [f.get("id") for f in findings if not f.get("validated")]
    print("  findings reported : %d" % len(findings))
    print("  carrying a PoC    : %d" % (len(findings) - len(unval)))
    if unval:
        print("  UNVALIDATED       : %s  <-- rule violation" % ", ".join(unval))

    print()
    print("=" * 66)
    print("SCORE")
    print("=" * 66)
    ceiling = maxw - sum(WEIGHT[b["difficulty"]] for b in gt["bugs"] if "poc" not in b)
    print("  weighted        : %d/%d" % (got, maxw))
    print("  achievable max  : %d/%d  (bugs the gate can actually prove)" % (ceiling, maxw))
    print("  against ceiling : %s" % ("%d/%d" % (got, ceiling) if ceiling else "n/a"))
    print("  false positives : %d" % len(fps))
    print("  tool calls      : %s" % fi.get("tool_calls_used", "n/a"))
    if unprovable:
        print()
        print("  NOTE: %s unprovable under the PoC gate (no reproducer in the" % ", ".join(unprovable))
        print("        answer key; impact is not a memory-safety abort). Reporting it")
        print("        would require breaking the no-unvalidated-findings rule.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
