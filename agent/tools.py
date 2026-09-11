#!/usr/bin/env python3
"""
The toolkit the agent is allowed to call.

Design rule from the AIxCC post-mortems: every tool returns *evidence*, never
a verdict. The model reasons; the tools ground. A finding is only a finding
once validate_poc() returns crashed=True.
"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracles  # noqa: E402  -- the generalized, typed-evidence gate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TWIN = os.path.join(ROOT, "host_twin")


def _run(cmd, cwd=None, timeout=120, stdin_bytes=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, timeout=timeout, input=stdin_bytes,
                           capture_output=True)
        return {
            "rc": p.returncode,
            "stdout": p.stdout.decode(errors="replace")[-8000:],
            "stderr": p.stderr.decode(errors="replace")[-8000:],
        }
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": f"timeout after {timeout}s"}


# ----------------------------------------------------------------- inspection
def read_source(path: str, start: int = 1, end: int = 400) -> str:
    """Read a slice of a source file. Paths are relative to the repo root."""
    full = os.path.normpath(os.path.join(ROOT, path))
    if not full.startswith(ROOT):
        return "error: path escapes repo root"
    with open(full) as f:
        lines = f.readlines()
    sel = lines[max(0, start - 1):end]
    return "".join(f"{i:5d}\t{l}" for i, l in enumerate(sel, start=max(1, start)))


def list_files() -> str:
    out = []
    for base, _, files in os.walk(ROOT):
        if any(s in base for s in (".git", "__pycache__")):
            continue
        for f in files:
            out.append(os.path.relpath(os.path.join(base, f), ROOT))
    return "\n".join(sorted(out))


# -------------------------------------------------------------------- dynamic
def build(target: str = "all") -> dict:
    """Build the host twin. target: all|target_tsan|target_asan|fuzz_stdin."""
    return _run(["make", "-s", target], cwd=TWIN)


def run_tsan(iters: int = 40, widen: int = 1) -> dict:
    """Run the concurrent workload under ThreadSanitizer. Returns raw output."""
    return _run([os.path.join(TWIN, "target_tsan"), "race", str(iters), str(widen)])


def run_interleaving(iters: int = 20, widen: int = 1) -> dict:
    """Run under ASan with the scheduler window widened -- turns a race into a
    deterministic crash if one exists."""
    return _run([os.path.join(TWIN, "target_asan"), "race", str(iters), str(widen)])


def run_cred_race(iters: int = 20, widen: int = 1) -> dict:
    """Drive the credential store with a concurrent second I2C writer and count
    how often check_credential grants admin for a record whose stored role is
    NOT admin. Returns the sequential control alongside it: the control must be
    0, so the pair isolates concurrency as the cause rather than a bad record.
    Evidence, not a verdict -- a nonzero count with a zero control is a
    privilege escalation, and the exit code is 1 when it happens."""
    base = _run([os.path.join(TWIN, "target_asan"), "cred-baseline", "500"])
    race = _run([os.path.join(TWIN, "target_asan"), "cred", str(iters), str(widen)])
    return {
        "sequential_control": base["stdout"].strip(),
        "control_rc": base["rc"],
        "concurrent": race["stdout"].strip(),
        "concurrent_rc": race["rc"],
        "escalated": race["rc"] == 1 and base["rc"] == 0,
    }


def validate_poc(poc_hex: str) -> dict:
    """THE CRASH GATE. Feed a candidate input to the ASan harness. A finding
    without crashed=True is a hypothesis, not a vulnerability. This recognises
    exactly one class of proof -- a memory-safety abort from stdin. For
    non-crash proofs (privilege escalation, races) use validate_evidence or
    run_oracle."""
    data = bytes.fromhex(poc_hex)
    r = _run([os.path.join(TWIN, "fuzz_stdin")], stdin_bytes=data)
    combined = r["stdout"] + r["stderr"]
    crashed = "AddressSanitizer" in combined or r["rc"] < 0
    return {
        "crashed": crashed,
        "signal_or_rc": r["rc"],
        "sanitizer_report": combined[:4000] if crashed else "",
    }


def validate_evidence(evidence: dict) -> dict:
    """THE GENERALIZED GATE. Validate a finding through typed evidence and get
    back a machine-readable verdict (passed, reproduction_rate, artifacts).

    `evidence` is a dict with a `type` field, one of:
      crash               {poc_hex|cmd, expect_site?}
      race_report         {cmd?, expect_site?}
      security_oracle     {cmd, insecure_when}
      trace_assertion     {cmd, assert_regex, forbid_regex?}
      differential_oracle {control:{cmd}, test:{cmd}, insecure_when, trials?}

    A differential oracle passes only when the control is secure on every
    trial AND the test reproduces the insecure state -- so a bug whose control
    is already insecure is a hard FAIL, not a pass. This is how non-crash
    findings such as BUG-003 privilege escalation become gate-enforced rather
    than self-asserted."""
    return oracles.validate(evidence)


def run_oracle(name: str) -> dict:
    """Run one of the canonical per-bug evidence specs (oracles.ORACLES) and
    return the gate verdict. Names: bug001_frame_toctou_overflow,
    bug002_parse_config_overflow, bug003_credential_toctou. Use this to obtain
    a reproducible witness the scorer will re-check."""
    return oracles.validate_named(name)


# ------------------------------------------------------------------- symbolic
def symbolic_solve(input_len: int = 64) -> dict:
    """Ask angr for an input reaching the parse_config memcpy with an
    oversized length. Use when fuzzing stalls on a magic value."""
    return _run(["python3", os.path.join(ROOT, "agent", "solve_parse_config.py"),
                 os.path.join(TWIN, "target_plain"), str(input_len)], timeout=600)


# ------------------------------------------------------------- tool schemas
SCHEMAS = [
    {"name": "list_files", "description": "List every file in the target repo.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "read_source", "description": "Read numbered lines from a source file.",
     "input_schema": {"type": "object", "properties": {
         "path": {"type": "string"}, "start": {"type": "integer"},
         "end": {"type": "integer"}}, "required": ["path"]}},
    {"name": "build", "description": "Build the instrumented binaries.",
     "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}}},
    {"name": "run_tsan", "description": "Run the workload under ThreadSanitizer to surface data races.",
     "input_schema": {"type": "object", "properties": {
         "iters": {"type": "integer"}, "widen": {"type": "integer"}}}},
    {"name": "run_interleaving", "description": "Run under ASan with a widened race window to turn a race into a deterministic crash.",
     "input_schema": {"type": "object", "properties": {
         "iters": {"type": "integer"}, "widen": {"type": "integer"}}}},
    {"name": "symbolic_solve", "description": "Use angr to solve for an input that reaches the parse_config memcpy with an oversized length.",
     "input_schema": {"type": "object", "properties": {"input_len": {"type": "integer"}}}},
    {"name": "run_cred_race", "description": "Drive the I2C credential store with a concurrent writer and report whether check_credential grants admin for a non-admin record, against a sequential control.",
     "input_schema": {"type": "object", "properties": {
         "iters": {"type": "integer"}, "widen": {"type": "integer"}}}},
    {"name": "validate_poc", "description": "The crash gate. Runs a hex-encoded input against the ASan harness and reports whether it actually crashed. Use for memory-safety bugs reachable from stdin.",
     "input_schema": {"type": "object", "properties": {"poc_hex": {"type": "string"}},
                      "required": ["poc_hex"]}},
    {"name": "validate_evidence", "description": "The generalized gate. Validate a finding through typed evidence (crash, race_report, security_oracle, trace_assertion, differential_oracle) and get a machine-readable verdict with reproduction rate and stored artifacts. Use for non-crash proofs such as privilege escalation, where a differential control/test pair isolates concurrency as the cause.",
     "input_schema": {"type": "object", "properties": {
         "evidence": {"type": "object", "description": "Evidence spec with a 'type' field; see the tool docstring for per-type fields."}},
                      "required": ["evidence"]}},
    {"name": "run_oracle", "description": "Run a canonical per-bug evidence spec by name and return the gate verdict. Names: bug001_frame_toctou_overflow, bug002_parse_config_overflow, bug003_credential_toctou.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}},
                      "required": ["name"]}},
]

DISPATCH = {
    "list_files": lambda **k: list_files(),
    "read_source": read_source,
    "build": build,
    "run_tsan": run_tsan,
    "run_interleaving": run_interleaving,
    "symbolic_solve": symbolic_solve,
    "run_cred_race": run_cred_race,
    "validate_poc": validate_poc,
    "validate_evidence": lambda **k: validate_evidence(k.get("evidence", k)),
    "run_oracle": run_oracle,
}


def call(name: str, args: dict):
    fn = DISPATCH.get(name)
    if fn is None:
        return {"error": f"unknown tool {name}"}
    try:
        return fn(**args)
    except Exception as e:  # tools must never kill the loop
        return {"error": f"{type(e).__name__}: {e}"}


if __name__ == "__main__":
    print(json.dumps(call("run_tsan", {"iters": 40, "widen": 1}), indent=2)[:1500])
