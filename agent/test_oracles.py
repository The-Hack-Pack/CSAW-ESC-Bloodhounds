#!/usr/bin/env python3
"""
Tests for the typed-evidence validation engine (agent/oracles.py).

Run inside the analysis container after building the twin:

    make -s -C host_twin all
    python3 agent/test_oracles.py

The point of these tests is not just that the three planted bugs validate --
it is that the gate *rejects* non-proofs. A gate that always says PASS proves
nothing. So every positive case is paired with a negative one:

  * the crash oracle fails on a benign input
  * the crash oracle fails when the report names the wrong site
  * the differential oracle fails when the control is already insecure
    (concurrency not isolated)
  * the differential oracle fails when the test never reproduces
  * an unknown evidence type is a hard fail, not a crash

Exit code 0 iff every assertion holds.
"""
import sys

import oracles

PASS, FAIL = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m"
_fails = []


def check(name, cond):
    print(f"  [{PASS if cond else FAIL}] {name}")
    if not cond:
        _fails.append(name)


def section(t):
    print(f"\n== {t} ==")


# ---------------------------------------------------------------- positives
def test_planted_bugs_validate():
    section("planted bugs validate through the gate")
    for oracle in ("bug002_parse_config_overflow",
                   "bug001_frame_toctou_overflow",
                   "bug003_credential_toctou"):
        v = oracles.validate_named(oracle)
        check(f"{oracle}: passed", v["passed"] is True)
        check(f"{oracle}: reproduction_rate > 0", v["reproduction_rate"] > 0)
        check(f"{oracle}: has evidence_type", bool(v["evidence_type"]))
        check(f"{oracle}: artifacts recorded", bool(v["artifacts"]))


def test_bug003_is_a_real_pair():
    section("BUG-003 differential oracle records both sides")
    v = oracles.validate_named("bug003_credential_toctou")
    d = v["detail"]
    check("control secure on every trial", d["control_insecure_trials"] == 0)
    check("test insecure on at least one trial", d["test_insecure_trials"] > 0)
    check("planted role recorded as non-admin",
          "0x00" in (v["artifacts"]["state"] or {}).get("authorised_role", ""))
    check("both commands stored",
          "control" in v["artifacts"]["command"]
          and "test" in v["artifacts"]["command"])


# ---------------------------------------------------------------- negatives
def test_crash_gate_rejects_benign():
    section("crash gate rejects a benign input")
    # a 1-byte even-tagged input routes to parse_config with len<3 -> returns -1
    v = oracles.validate({"type": "crash", "poc_hex": "00", "expect_site": "parse_config"})
    check("benign input does not pass", v["passed"] is False)
    check("reproduction_rate is 0", v["reproduction_rate"] == 0.0)


def test_crash_gate_rejects_wrong_site():
    section("crash gate rejects a crash at the wrong site")
    # real BUG-002 crash, but claim it is in the wrong function
    v = oracles.validate({"type": "crash",
                          "poc_hex": "00c0004041" * 1 + "41" * 63,
                          "expect_site": "handle_frame"})
    check("crash at wrong site does not pass", v["passed"] is False)
    check("reason mentions the site mismatch", "site" in v["reason"].lower())


def test_differential_fails_when_control_insecure():
    section("differential oracle fails when the control is already insecure")
    # Use the CONCURRENT (insecure) command as the control too. Now the control
    # is insecure, so concurrency cannot be isolated -> must FAIL.
    v = oracles.validate({
        "type": "differential_oracle",
        "control": {"cmd": ["target_asan", "cred", "2000", "1"]},
        "test": {"cmd": ["target_asan", "cred", "2000", "1"]},
        "insecure_when": {"rc_in": [1], "count_regex": r"granted admin (\d+) time", "count_gt": 0},
        "trials": 3,
    })
    check("does not pass", v["passed"] is False)
    check("reason flags an insecure control",
          "control already insecure" in v["reason"].lower())
    check("control_secure is False", v["detail"]["control_secure"] is False)


def test_differential_fails_when_test_never_reproduces():
    section("differential oracle fails when the test never reproduces")
    # Both sides benign (the sequential control). Control secure, but the test
    # never shows the insecure state -> no differential -> FAIL.
    v = oracles.validate({
        "type": "differential_oracle",
        "control": {"cmd": ["target_asan", "cred-baseline", "500"]},
        "test": {"cmd": ["target_asan", "cred-baseline", "500"]},
        "insecure_when": {"rc_in": [1], "count_regex": r"escalation\(s\)", "count_gt": 0},
        "trials": 3,
    })
    check("does not pass", v["passed"] is False)
    check("control is secure", v["detail"]["control_secure"] is True)
    check("test never reproduced", v["detail"]["test_insecure_trials"] == 0)


def test_unknown_type_is_hard_fail():
    section("unknown evidence type is a hard fail")
    v = oracles.validate({"type": "wishful_thinking"})
    check("does not pass", v["passed"] is False)
    check("reason names the unknown type", "unknown evidence type" in v["reason"])


def main():
    test_planted_bugs_validate()
    test_bug003_is_a_real_pair()
    test_crash_gate_rejects_benign()
    test_crash_gate_rejects_wrong_site()
    test_differential_fails_when_control_insecure()
    test_differential_fails_when_test_never_reproduces()
    test_unknown_type_is_hard_fail()

    print()
    if _fails:
        print(f"{FAIL}: {len(_fails)} assertion(s) failed: {', '.join(_fails)}")
        return 1
    print(f"{PASS}: all assertions held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
