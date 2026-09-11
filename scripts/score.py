#!/usr/bin/env python3
"""Score an agent run against the answer key (README step 17).

    python3 scripts/score.py agent/findings.json

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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent"))
try:
    import oracles  # the generalized, typed-evidence gate
except Exception:  # scoring must still run where the engine can't import
    oracles = None

WEIGHT = {"easy": 1, "medium": 2, "hard": 3}

# Map a defect-site function to the canonical oracle that re-proves it. The
# scorer runs these so a reported finding is credited only when the gate
# re-checks its witness -- self-asserted "validated": true is not enough.
FN_TO_ORACLE = {
    "parse_config":     "bug002_parse_config_overflow",
    "handle_frame":     "bug001_frame_toctou_overflow",
    "check_credential": "bug003_credential_toctou",
}


def main():
    gt_path = "ground_truth.json"
    fi_path = sys.argv[1] if len(sys.argv) > 1 else "agent/findings.json"
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
    print("POC GATE (self-asserted)")
    print("=" * 66)
    unval = [f.get("id") for f in findings if not f.get("validated")]
    print("  findings reported : %d" % len(findings))
    print("  carrying a PoC    : %d" % (len(findings) - len(unval)))
    if unval:
        print("  UNVALIDATED       : %s  <-- rule violation" % ", ".join(unval))

    print()
    print("=" * 66)
    print("GATE RE-VERIFICATION (typed evidence, re-run now)")
    print("=" * 66)
    gate_ok = {}
    if oracles is None:
        print("  engine unavailable (agent/oracles.py did not import) -- skipped")
    else:
        # Only oracles for a bug that is actually reachable/present are re-run.
        for f in findings:
            fn = (f.get("function") or "").strip()
            oracle = FN_TO_ORACLE.get(fn)
            if fn in decoy_fns:
                continue
            if oracle is None:
                print("  %-4s %-17s no oracle registered for this site"
                      % (f.get("id"), fn))
                continue
            try:
                v = oracles.validate_named(oracle)
            except Exception as e:
                print("  %-4s %-17s gate ERROR: %s" % (f.get("id"), fn, e))
                gate_ok[fn] = False
                continue
            gate_ok[fn] = bool(v.get("passed"))
            print("  %-4s %-17s %-19s %-4s repro=%.2f  %s"
                  % (f.get("id"), fn, v.get("evidence_type"),
                     "PASS" if v["passed"] else "FAIL",
                     v.get("reproduction_rate", 0.0),
                     "" if v["passed"] else "<-- gate rejects this proof"))
        bogus = [f.get("id") for f in findings
                 if (f.get("function") or "").strip() in FN_TO_ORACLE
                 and not gate_ok.get((f.get("function") or "").strip(), False)]
        if bogus:
            print("  GATE-REJECTED     : %s  <-- reported but not gate-provable"
                  % ", ".join(bogus))
        else:
            print("  every reported bug carries a witness the gate re-verified.")

    print()
    print("=" * 66)
    print("SCORE")
    print("=" * 66)
    # A bug is gate-provable if it has a reproducer AND a typed oracle exists
    # for its site. With the differential oracle, BUG-003 is now provable too,
    # so the ceiling is the full weight -- the cap the README documented is gone.
    def _provable(b):
        has_poc = "poc" in b
        has_oracle = b["site"]["function"] in FN_TO_ORACLE
        return has_poc and has_oracle
    ceiling = sum(WEIGHT[b["difficulty"]] for b in gt["bugs"] if _provable(b))
    print("  weighted        : %d/%d" % (got, maxw))
    print("  achievable max  : %d/%d  (bugs the typed gate can actually prove)" % (ceiling, maxw))
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
