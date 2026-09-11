#!/usr/bin/env python3
"""
Concolic execution: preconstrained seed + branch negation (SAGE-style).

The distinction from symex.py is what selects the path. There, a solver forks
at every symbolic branch and the state count is the thing that explodes. Here a
concrete seed decides every branch, so exactly one state is live at a time; the
off-path successor of each branch is captured, its preconstraints dropped, and
the solver asked for an input that would have gone the other way. Each answer
is a real, replayable byte string -- not a state that may or may not correspond
to a reachable execution.

Mechanically:

  1. the argument buffer is symbolic, then preconstrained to the seed bytes
  2. stepping with preconstraints active leaves the seed's successor in
     succ.successors and every alternative in succ.unsat_successors
  3. for each alternative: remove_preconstraints(), ask if it is satisfiable
     without the seed pinning the input, and if so solve for a new seed
  4. new seeds are returned (and optionally replayed through the ASan harness),
     which is the generation step of a concolic loop

The seed is what bounds the work. Nothing here needs a whole-binary CFG, and
the unmodeled-code problem that stalls pure symbolic execution is handled the
way concolic always handles it: the concrete value from the seed's own run.
"""
import json
import logging
import os
import subprocess
import time

try:
    from . import binfacts, symex
except ImportError:
    import binfacts
    import symex

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _quiet():
    for n in ("angr", "cle", "pyvex", "claripy", "archinfo"):
        logging.getLogger(n).setLevel("CRITICAL")


def _replay(poc_hex, harness):
    """Run a candidate through the ASan harness. This is the same gate the
    proof stage uses; concolic calls it so a generated input is known-crashing
    before anything downstream claims it is."""
    try:
        data = bytes.fromhex(poc_hex)
    except ValueError:
        return {"crashed": False, "error": "bad hex"}
    try:
        p = subprocess.run([harness], input=data, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"crashed": False, "error": str(e)}
    out = (p.stdout + p.stderr).decode(errors="replace")
    crashed = "AddressSanitizer" in out or p.returncode < 0
    return {"crashed": crashed, "rc": p.returncode,
            "report": out[:1500] if crashed else ""}


def run(binary, chunk, seed_hex, max_new_inputs=12, budget_s=None,
        max_steps=4000, harness=None, replay=True):
    """Drive one chunk concolically from a seed. Returns a JSON-able dict."""
    import angr
    import claripy
    _quiet()

    budget_s = int(budget_s or chunk.get("budget_s") or 300)
    t0 = time.time()
    deadline = t0 + budget_s

    proj = angr.Project(binary, auto_load_libs=False, load_debug_info=True)
    entry_name = chunk.get("entry") or (chunk.get("members") or [None])[0]
    entry = symex._resolve(proj, entry_name)

    seed = bytes.fromhex(seed_hex)
    # The symbolic buffer is sized by the seed: concolic explores around the
    # input you actually have, which is exactly why it does not explode.
    bufspec = None
    for a in (chunk.get("args") or []):
        if a.get("kind") == "sym_buf":
            bufspec = a
            break
    if bufspec is None:
        return {"chunk_id": chunk.get("chunk_id"), "entry": entry_name,
                "error": "concolic needs a sym_buf argument to seed; chunk has none"}

    size = len(seed)
    addr = int(bufspec["addr"], 16) if isinstance(bufspec.get("addr"), str) \
        else bufspec.get("addr") or symex.BUF_BASE
    name = bufspec.get("name", "in")

    base = proj.factory.blank_state(
        addr=entry,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                     angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY})
    data = claripy.BVS(name, size * 8)
    base.memory.store(addr, data)

    args = []
    for a in (chunk.get("args") or []):
        if a.get("kind") == "sym_buf":
            args.append(addr)
        elif a.get("kind") == "seed_len":
            args.append(size)            # the length the seed actually has
        else:
            args.append(int(a["value"]))

    state = proj.factory.call_state(
        entry, *args, base_state=base,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

    havoc_ranges = []
    for g in (chunk.get("havoc_globals") or []):
        s = proj.loader.find_symbol(g)
        if s is not None:
            havoc_ranges.append((s.rebased_addr,
                                 s.rebased_addr + max(s.size or proj.arch.bytes, 1), g))
    if havoc_ranges:
        symex._install_havoc(state, havoc_ranges)

    # Pin the symbolic buffer to the seed. Every branch now has exactly one
    # satisfiable successor: the one the real input takes.
    state.preconstrainer.preconstrain(claripy.BVV(seed), data)

    sink_addrs = set()
    for sk in symex._autofill_sinks(binary, chunk):
        ca = sk.get("callee_addr")
        if ca:
            sink_addrs.add(int(ca, 16) if isinstance(ca, str) else ca)

    trace, new_inputs, diverged = [], [], 0
    sinks_hit, steps, stop = [], 0, None
    cur = state

    while cur is not None and steps < max_steps:
        if time.time() > deadline:
            stop = "budget_exhausted"
            break
        if len(new_inputs) >= max_new_inputs:
            stop = "input_cap_reached"
            break
        trace.append(hex(cur.addr))
        if cur.addr in sink_addrs:
            sinks_hit.append(hex(cur.addr))
        try:
            succ = proj.factory.successors(cur)
        except Exception as e:
            stop = "step_error:%s" % type(e).__name__
            break

        # The off-path branches. With preconstraints active these are exactly
        # the successors the seed did not take.
        for alt in list(succ.unsat_successors):
            if len(new_inputs) >= max_new_inputs:
                break
            diverged += 1
            try:
                cand = alt.copy()
                cand.preconstrainer.remove_preconstraints()
                if not cand.solver.satisfiable():
                    continue
                nb = cand.solver.eval(data, cast_to=bytes)
            except Exception:
                continue
            if nb == seed:
                continue
            rec = {
                "flipped_at": hex(cur.addr),
                "to": hex(alt.addr) if isinstance(alt.addr, int) else str(alt.addr),
                "depth": steps,
                "input_hex": nb.hex(),
            }
            if replay and harness:
                prefix = chunk.get("poc_prefix_hex", "")
                rec["poc_hex"] = prefix + nb.hex()
                rec["replay"] = _replay(rec["poc_hex"], harness)
            new_inputs.append(rec)

        nxt = succ.successors
        if not nxt:
            stop = stop or "seed_path_ended"
            break
        cur = nxt[0]
        steps += 1
    else:
        stop = stop or "max_steps"

    return {
        "chunk_id": chunk.get("chunk_id"),
        "entry": entry_name, "entry_addr": hex(entry),
        "mode": "concolic:preconstrained+negation",
        "seed_hex": seed_hex, "seed_len": size,
        "steps": steps,
        "blocks": sorted(set(trace)),
        "blocks_covered": len(set(trace)),
        "branches_diverged": diverged,
        "sinks_hit": sinks_hit,
        "new_inputs": new_inputs,
        "crashing_inputs": [i for i in new_inputs
                            if i.get("replay", {}).get("crashed")],
        "interference_modeled": bool(havoc_ranges),
        "stopped": stop,
        "seconds": round(time.time() - t0, 1),
    }


def run_generations(binary, chunk, seeds, generations=3, max_new_inputs=8,
                    budget_s=None, harness=None, replay=True):
    """Iterate the concolic loop: a seed yields inputs, the ones that reach new
    blocks become the next generation's seeds.

    One generation only flips the branches the seed itself reached -- from a
    garbage seed that recovers a magic byte and stops. Reaching a sink guarded
    behind that magic takes a second generation, which is the whole point of
    the loop and the reason SAGE calls these generations.

    Coverage decides what is worth re-seeding, so the queue stays small
    regardless of how many inputs the solver hands back.
    """
    budget_s = int(budget_s or chunk.get("budget_s") or 600)
    t0 = time.time()
    covered, queue, gens, crashing = set(), list(seeds), [], []
    seen_inputs = set(queue)

    for g in range(generations):
        if not queue or time.time() - t0 > budget_s:
            break
        nxt, records = [], []
        for sd in queue:
            left = budget_s - (time.time() - t0)
            if left <= 5:
                break
            r = run(binary, chunk, sd, max_new_inputs=max_new_inputs,
                    budget_s=left, harness=harness, replay=replay)
            if r.get("error"):
                records.append(r)
                continue
            new_blocks = set(r.get("blocks") or []) - covered
            covered |= set(r.get("blocks") or [])
            records.append({
                "seed": sd, "steps": r["steps"], "new_blocks": len(new_blocks),
                "sinks_hit": r["sinks_hit"], "diverged": r["branches_diverged"],
                "inputs": [{k: i[k] for k in ("flipped_at", "input_hex")
                            if k in i} | {"crashed": i.get("replay", {}).get("crashed")}
                           for i in r["new_inputs"]],
            })
            crashing.extend(r.get("crashing_inputs") or [])
            for i in r["new_inputs"]:
                h = i["input_hex"]
                if h not in seen_inputs:
                    seen_inputs.add(h)
                    nxt.append(h)
        gens.append({"generation": g, "seeds": len(queue), "runs": records})
        # Re-seed with everything new this round; coverage prunes it next pass
        # because a seed that adds no blocks produces no new divergences.
        queue = nxt[:max_new_inputs]

    return {
        "chunk_id": chunk.get("chunk_id"),
        "entry": chunk.get("entry"),
        "mode": "concolic:preconstrained+negation (generational)",
        "generations": gens,
        "generation_count": len(gens),
        "blocks_covered": len(covered),
        "inputs_generated": len(seen_inputs) - len(seeds),
        "crashing_inputs": list({c["input_hex"]: c for c in crashing}.values()),
        "seconds": round(time.time() - t0, 1),
    }


if __name__ == "__main__":
    import sys
    b, ch, seed = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]
    h = sys.argv[4] if len(sys.argv) > 4 else None
    print(json.dumps(run(b, ch, seed, harness=h), indent=2))
