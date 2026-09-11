#!/usr/bin/env python3
"""
The proof layer: run the thing for real.

Symbolic and concolic results are claims about a model of the program. This
module is where a claim becomes an observation -- a signal, a sanitizer report
naming a function and a line, or a differential count against a control. It is
deliberately the least clever code in the pipeline.

Three kinds of proof, because the pipeline produces three kinds of claim:

  input        a byte string that must crash the instrumented harness
  interference an overflow that only exists because a concurrent writer moved a
               shared value between a check and a use; no single input proves
               it, so the proof is a widened-window run plus an unwidened
               reproduction
  oracle       a privilege/logic outcome no sanitizer can see, proved by a
               differential against a sequential control that must read zero
"""
import json
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TWIN = os.path.join(ROOT, "host_twin")


def _run(cmd, timeout=120, stdin_bytes=None, cwd=None, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, cwd=cwd, timeout=timeout, input=stdin_bytes,
                           capture_output=True, env=e)
        return {"rc": p.returncode,
                "stdout": p.stdout.decode(errors="replace")[-8000:],
                "stderr": p.stderr.decode(errors="replace")[-8000:]}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": "timeout after %ss" % timeout}
    except OSError as e2:
        return {"rc": -1, "stdout": "", "stderr": "%s: %s" % (type(e2).__name__, e2)}


def _sanitizer_lines(text):
    """The lines worth quoting as evidence: the error kind and the frames that
    name target source, not the 40 lines of libsanitizer boilerplate."""
    keep = []
    for ln in text.splitlines():
        s = ln.strip()
        if ("ERROR: AddressSanitizer" in s or "ERROR: ThreadSanitizer" in s
                or "SUMMARY:" in s or "WARNING: ThreadSanitizer" in s
                or "overflows this variable" in s or "Location is" in s):
            keep.append(s)
        elif s.startswith("#") and ".c:" in s:
            keep.append(s)
    return keep[:14]


def validate_poc(poc_hex, harness=None, timeout=60):
    """THE GATE. A finding without crashed=true is a hypothesis."""
    harness = harness or os.path.join(TWIN, "fuzz_stdin")
    if not os.path.exists(harness):
        return {"crashed": False, "error": "harness not built: %s" % harness}
    try:
        data = bytes.fromhex(poc_hex.replace(" ", ""))
    except ValueError as e:
        return {"crashed": False, "error": "bad hex: %s" % e}
    r = _run([harness], stdin_bytes=data, timeout=timeout)
    combined = r["stdout"] + r["stderr"]
    crashed = "AddressSanitizer" in combined or r["rc"] < 0
    return {"crashed": crashed, "signal_or_rc": r["rc"],
            "poc_hex": poc_hex, "poc_bytes": len(data),
            "evidence": _sanitizer_lines(combined),
            "sanitizer_report": combined[:4000] if crashed else ""}


def prove_interference(mode="race", iters=20, widen=1, unwidened_iters=0,
                       timeout=300):
    """Proof for an interference claim: widen the window to make the race
    deterministic, then -- if asked -- reproduce it with the window closed, so
    the finding cannot be dismissed as an artifact of the test hook."""
    asan = os.path.join(TWIN, "target_asan")
    if not os.path.exists(asan):
        return {"error": "target_asan not built"}
    out = {"mode": mode}
    r = _run([asan, mode, str(iters), str(widen)], timeout=timeout)
    combined = r["stdout"] + r["stderr"]
    out["widened"] = {"rc": r["rc"], "crashed": "AddressSanitizer" in combined or r["rc"] < 0,
                      "evidence": _sanitizer_lines(combined)}
    if unwidened_iters:
        r2 = _run([asan, mode, str(unwidened_iters), "0"], timeout=timeout)
        c2 = r2["stdout"] + r2["stderr"]
        out["unwidened"] = {"rc": r2["rc"], "iters": unwidened_iters,
                            "crashed": "AddressSanitizer" in c2 or r2["rc"] < 0,
                            "evidence": _sanitizer_lines(c2)}
        out["natural_scheduling_confirmed"] = out["unwidened"]["crashed"]
    return out


def prove_oracle(iters=20, widen=1, control_checks=500, timeout=300):
    """Proof for a claim no sanitizer can see. The control must read zero:
    it is the pair (0 sequential, >0 concurrent) that isolates concurrency as
    the cause rather than a bad record."""
    asan = os.path.join(TWIN, "target_asan")
    if not os.path.exists(asan):
        return {"error": "target_asan not built"}
    base = _run([asan, "cred-baseline", str(control_checks)], timeout=timeout)
    race = _run([asan, "cred", str(iters), str(widen)], timeout=timeout)
    return {"sequential_control": base["stdout"].strip(), "control_rc": base["rc"],
            "concurrent": race["stdout"].strip(), "concurrent_rc": race["rc"],
            "escalated": race["rc"] == 1 and base["rc"] == 0,
            "control_is_clean": base["rc"] == 0}


def run_tsan(iters=40, widen=1, timeout=300):
    t = os.path.join(TWIN, "target_tsan")
    if not os.path.exists(t):
        return {"error": "target_tsan not built"}
    r = _run([t, "race", str(iters), str(widen)], timeout=timeout)
    combined = r["stdout"] + r["stderr"]
    broken = ("unexpected memory mapping" in combined
              or "FATAL: ThreadSanitizer" in combined)
    return {"rc": r["rc"],
            "race_reported": "WARNING: ThreadSanitizer" in combined,
            # A TSan that cannot map shadow memory prints nothing and looks
            # exactly like a clean run. Never let that read as "no race".
            "harness_broken": broken,
            "evidence": _sanitizer_lines(combined),
            "raw": combined[:4000]}


def build(target="all", cwd=None):
    return _run(["make", "-s", target], cwd=cwd or TWIN, timeout=600)


def emulate_firmware(cmd=None, timeout=120):
    """Boot the Xtensa firmware under qemu-system-xtensa.

    Separate from everything else on purpose: angr has no Xtensa lifter, so
    stages 2-5 never run on this binary. It is a fidelity check -- does the
    defect the twin proved also reach on the real target -- not an analysis
    step. Reports honestly when the emulator is not present rather than
    returning a silent negative.
    """
    qemu = None
    for c in ("qemu-system-xtensa", "/opt/qemu/bin/qemu-system-xtensa"):
        r = _run(["which", c], timeout=10)
        if r["rc"] == 0:
            qemu = r["stdout"].strip()
            break
    if qemu is None:
        return {"available": False,
                "reason": "qemu-system-xtensa is not in this image; it lives in "
                          "the esp32 service (docker/Dockerfile.esp32). Run "
                          "`make esp32-qemu` there.",
                "affects_findings": False}
    r = _run(cmd or [qemu, "--version"], timeout=timeout)
    return {"available": True, "qemu": qemu, "rc": r["rc"],
            "stdout": r["stdout"][:4000], "stderr": r["stderr"][:2000]}


if __name__ == "__main__":
    import sys
    fn = sys.argv[1] if len(sys.argv) > 1 else "validate_poc"
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    print(json.dumps(globals()[fn](**args), indent=2))
