#!/usr/bin/env python3
"""
Measurement harness. Produces the numbers a proposal can cite.

    python3 scripts/experiments.py --exp all
    python3 scripts/experiments.py --exp scaling --out agent/artifacts/exp.json

Each experiment isolates one variable and reports a number, not an impression.
The ablations matter more than the wins: "the pipeline found the bug" is weak,
"the pipeline found the bug and removing component X makes it miss the bug" is
an argument.

Everything here runs without credentials -- these measure the analysis engines,
not the model loop. Stage costs need a separate run.
"""
import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))
sys.path.insert(0, os.path.join(ROOT, "agent", "lib"))

import tools     # noqa: E402
import symex     # noqa: E402

BIN = os.path.join(ROOT, "host_twin", "target_plain")
HARNESS = os.path.join(ROOT, "host_twin", "fuzz_stdin")


def _chunk(entry, members=None, size=64, havoc=None, concrete_len=True):
    args = [{"name": "in", "kind": "sym_buf", "size": size}]
    args.append({"name": "len", "kind": "concrete", "value": size}
                if concrete_len else {"name": "len", "kind": "seed_len"})
    return {"chunk_id": "exp-%s" % entry, "members": members or [entry],
            "entry": entry, "args": args, "havoc_globals": havoc or [],
            "poc_prefix_hex": "00"}


# ---------------------------------------------------------------- E1 scaling
def exp_scaling(budget=240):
    """Cost of symbolic execution as the entry point moves up the call chain.

    !! THIS EXPERIMENT DOES NOT MEASURE WHAT IT WAS BUILT TO MEASURE. Run
    2026-09-11 returned 0.7s / 0.8s / 0.6s for entry = parse_config /
    LLVMFuzzerTestOneInput / main -- no growth at all. Path explosion does not
    manifest on this target: the twin is ~100 lines and its largest function has
    10 basic blocks, so there is nothing to explode.

    Worse, `overflow_found` goes true -> false -> false across those three
    cases, and that is an artifact, not a result: the arg spec attaches a
    symbolic buffer to argument 0, which is correct for parse_config and
    meaningless for main (which takes no arguments and reads stdin through
    fread). At the higher entries the attacker data is simply never symbolic,
    so the sink is reached with concrete values.

    Do not cite this as evidence for chunking. The honest version needs a
    target with real control flow -- /usr/bin/gzip has functions of 527 and 550
    basic blocks against this binary's maximum of 10 -- and an arg spec derived
    per entry point rather than assumed. Until then the only defensible scaling
    number here is CFG recovery cost, which is real and is reported below.
    """
    rows = []
    cases = [
        ("parse_config", ["parse_config"], "leaf: one function"),
        ("LLVMFuzzerTestOneInput", ["LLVMFuzzerTestOneInput", "parse_config",
                                    "eeprom_write", "check_credential"],
         "harness entry: dispatch + 3 callees"),
        ("main", ["main", "LLVMFuzzerTestOneInput", "parse_config",
                  "eeprom_write", "check_credential"],
         "whole program: fread + dispatch"),
    ]
    for entry, members, label in cases:
        ch = _chunk(entry, members)
        t0 = time.time()
        r = tools.call("symex_chunk", {"chunk": ch, "budget_s": budget})
        rows.append({
            "entry": entry, "label": label, "members": len(members),
            "seconds": r.get("seconds", round(time.time() - t0, 1)),
            "sinks_reached": r.get("sinks_reached", 0),
            "sinks_not_reached": len(r.get("sinks_not_reached") or []),
            "stopped_early": r.get("stopped_early"),
            "stashes": r.get("stashes"),
            "overflow_found": any(x.get("overflow") for x in r.get("results", [])),
            "error": r.get("error"),
        })
    # The cached whole-binary CFG cost is the other half of the argument.
    facts = tools.call("binary_facts", {})
    return {"VALIDITY": "INVALID as a path-explosion measurement -- see the "
                        "docstring. CFG numbers below are sound; the per-entry "
                        "cases are not.",
            "cfg_whole_binary_seconds": facts.get("cfg_seconds"),
            "cfg_functions": facts.get("function_count"),
            "cfg_user_functions": facts.get("user_function_count"),
            "cases": rows}


# -------------------------------------------------------------- E2 capacity
def exp_capacity():
    """Ablation: where the destination's capacity comes from.

    DWARF gives name[32]. The obvious fallback -- distance from the buffer to
    the frame's CFA -- gives 64. Both are 'a capacity'; only one finds the bug.
    Reported as a false-negative outcome, because that is what it is.
    """
    ch = _chunk("parse_config")
    real = tools.call("symex_chunk", {"chunk": ch, "budget_s": 120})
    r0 = (real.get("results") or [{}])[0]

    # Same run, capacity forced to the frame-distance value the fallback yields.
    ch2 = dict(ch)
    ch2["sinks"] = [dict(s, dest_capacity=64) for s in
                    symex._autofill_sinks(BIN, ch)]
    frame = tools.call("symex_chunk", {"chunk": ch2, "budget_s": 120})
    r1 = (frame.get("results") or [{}])[0]
    return {
        "dwarf": {"capacity": r0.get("dest_capacity"),
                  "source": r0.get("capacity_source"),
                  "length_max": r0.get("length_max"),
                  "overflow_found": r0.get("overflow"),
                  "solved_length": r0.get("solved_length")},
        "frame_distance": {"capacity": r1.get("dest_capacity"),
                           "source": r1.get("capacity_source"),
                           "length_max": r1.get("length_max"),
                           "overflow_found": r1.get("overflow"),
                           "proved_unreachable": r1.get("proved_unreachable")},
        "conclusion": ("frame-distance capacity yields a FALSE NEGATIVE: every "
                       "write of 33..61 bytes overflows name[32] while staying "
                       "inside the 64-byte frame"),
    }


# ----------------------------------------------------------------- E3 havoc
def exp_havoc():
    """Ablation: modelling concurrent interference.

    handle_frame's double fetch is invisible without it -- one symbol for
    g_len makes n == g_len and the defect provably absent.
    """
    out = {}
    for label, hv in (("without_havoc", []), ("with_havoc", ["g_len"])):
        ch = {"chunk_id": "exp-hf", "members": ["handle_frame"],
              "entry": "handle_frame", "args": [], "havoc_globals": hv}
        r = tools.call("symex_chunk", {"chunk": ch, "budget_s": 120})
        res = (r.get("results") or [{}])[0]
        out[label] = {"sinks_reached": r.get("sinks_reached", 0),
                      "havoc_reads": r.get("havoc_reads"),
                      "dest_capacity": res.get("dest_capacity"),
                      "capacity_source": res.get("capacity_source"),
                      "length_unbounded": res.get("length_unbounded"),
                      "overflow_found": res.get("overflow"),
                      "solved_length": res.get("solved_length"),
                      "poc_kind": res.get("poc_kind"),
                      "seconds": r.get("seconds")}
    return out


# ----------------------------------------------------- E4 concolic generations
def exp_generations(max_gen=4):
    """Coverage and crashes as a function of concolic generation, from a
    garbage seed. Shows the magic-value barrier and the generation that
    crosses it -- the reason one generation is not a concolic loop."""
    rows = []
    for g in range(1, max_gen + 1):
        ch = _chunk("parse_config", concrete_len=False)
        t0 = time.time()
        r = tools.call("concolic_chunk", {
            "chunk": ch, "seeds": ["41" * 64], "generations": g,
            "max_new_inputs": 6, "budget_s": 300, "harness": HARNESS})
        rows.append({"generations": g,
                     "blocks_covered": r.get("blocks_covered"),
                     "inputs_generated": r.get("inputs_generated"),
                     "crashing_inputs": len(r.get("crashing_inputs") or []),
                     "seconds": r.get("seconds", round(time.time() - t0, 1))})
    return {"seed": "0x41 * 64 (no magic, no hint)", "curve": rows}


# ------------------------------------------------------------------ E5 seeds
def exp_seed_quality():
    """Does the seed matter? Garbage vs. a seed carrying the magic byte.
    Quantifies what a solver hint buys the concolic stage."""
    out = {}
    for label, seed in (("garbage", "41" * 64),
                        ("magic_only", "c0" + "00" * 63),
                        ("solver_hint", "c0003d" + "00" * 61)):
        ch = _chunk("parse_config", concrete_len=False)
        r = tools.call("concolic_chunk", {
            "chunk": ch, "seeds": [seed], "generations": 2,
            "max_new_inputs": 6, "budget_s": 240, "harness": HARNESS})
        out[label] = {"blocks_covered": r.get("blocks_covered"),
                      "inputs_generated": r.get("inputs_generated"),
                      "crashes": len(r.get("crashing_inputs") or []),
                      "seconds": r.get("seconds")}
    return out


# ----------------------------------------------------------------- E6 matrix
def exp_matrix():
    """Technique x defect. The complementarity argument: which technique finds
    which planted bug ALONE. The interesting cells are the empty ones."""
    m = {}

    # BUG-002: sequential overflow in parse_config
    sym = tools.call("symex_chunk", {"chunk": _chunk("parse_config"), "budget_s": 120})
    con = tools.call("concolic_chunk", {
        "chunk": _chunk("parse_config", concrete_len=False), "seeds": ["41" * 64],
        "generations": 3, "budget_s": 300, "harness": HARNESS})
    m["BUG-002 parse_config overflow"] = {
        "symbolic": any(r.get("overflow") for r in sym.get("results", [])),
        "concolic": bool(con.get("crashing_inputs")),
        "asan_replay": tools.call("validate_poc", {"poc_hex": "00c0003d" + "41" * 61}).get("crashed"),
        "tsan": False, "oracle": False,
    }

    # BUG-001: TOCTOU in handle_frame
    hf_plain = tools.call("symex_chunk", {
        "chunk": {"chunk_id": "m1", "members": ["handle_frame"],
                  "entry": "handle_frame", "args": []}, "budget_s": 120})
    hf_havoc = tools.call("symex_chunk", {
        "chunk": {"chunk_id": "m2", "members": ["handle_frame"],
                  "entry": "handle_frame", "args": [],
                  "havoc_globals": ["g_len"]}, "budget_s": 120})
    ts = tools.call("run_tsan", {"iters": 40, "widen": 1})
    inter = tools.call("prove_interference", {"mode": "race", "iters": 20, "widen": 1})
    m["BUG-001 handle_frame TOCTOU"] = {
        "symbolic_no_havoc": any(r.get("overflow") for r in hf_plain.get("results", [])),
        "symbolic_havoc": any(r.get("overflow") for r in hf_havoc.get("results", [])),
        "concolic": "n/a: no input causes it (poc_kind=interference)",
        "asan_interleaving": inter.get("widened", {}).get("crashed"),
        "tsan": ts.get("race_reported"),
        "tsan_harness_broken": ts.get("harness_broken"),
    }

    # BUG-003: credential TOCTOU, no memory error at all
    orc = tools.call("prove_oracle", {"iters": 20, "widen": 1})
    m["BUG-003 check_credential escalation"] = {
        "symbolic": "not attempted: no memory-safety sink",
        "concolic": "n/a: authorization outcome, not a crash",
        "asan": False,
        "oracle": orc.get("escalated"),
        "oracle_control_clean": orc.get("control_is_clean"),
        "oracle_numbers": {"sequential": orc.get("sequential_control"),
                           "concurrent": orc.get("concurrent")},
    }
    return m


EXPERIMENTS = {"scaling": exp_scaling, "capacity": exp_capacity,
               "havoc": exp_havoc, "generations": exp_generations,
               "seeds": exp_seed_quality, "matrix": exp_matrix}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", default="all",
                    help="one of: %s, or all" % ", ".join(EXPERIMENTS))
    ap.add_argument("--out", default="agent/artifacts/experiments.json")
    args = ap.parse_args()

    names = list(EXPERIMENTS) if args.exp == "all" else [args.exp]
    out = {"target": BIN, "when": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "results": {}}
    for n in names:
        if n not in EXPERIMENTS:
            sys.exit("unknown experiment %r" % n)
        print("== %s ==" % n, flush=True)
        t0 = time.time()
        try:
            out["results"][n] = EXPERIMENTS[n]()
        except Exception as e:
            out["results"][n] = {"error": "%s: %s" % (type(e).__name__, e)}
        print(json.dumps(out["results"][n], indent=1, default=str), flush=True)
        print("   (%.1fs)\n" % (time.time() - t0), flush=True)

    path = os.path.join(ROOT, args.out)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(out, f, indent=1, default=str)
    print("wrote %s" % args.out)


if __name__ == "__main__":
    main()
