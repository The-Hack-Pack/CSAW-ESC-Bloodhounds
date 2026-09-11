#!/usr/bin/env python3
"""
Directed symbolic execution over one chunk.

This replaces solve_parse_config.py, which hardcoded find_symbol("parse_config"),
assumed the last `call` in the function was the sink, and read the length field
from a fixed bit-slice of the input. None of that survives contact with a
second target. Here the entry, the argument layout and the sinks all arrive in
the chunk spec, and the bug condition is read from the *registers at the call
site* rather than guessed from input byte offsets.

Scaling controls, because a chunk is still allowed to explode:

  scoped CFG     recovered over the chunk members' address ranges only
  LoopSeer       bounded unrolling, so a loop cannot fork forever
  LengthLimiter  hard cap on path length
  deadline       wall-clock budget enforced in the step loop
  state cap      active-state ceiling; exceeding it is reported, not hidden
  find=callee    exploration stops AT the sink, never inside it

A sink is evaluated by reading the calling convention's argument registers and
asking whether the length can exceed the destination's capacity. Capacity is
derived, in order of preference: the chunk's explicit value, the DWARF extent
of the stack local the destination resolves to, the size of the global it
points into, or the distance from the destination to the frame's CFA.
"""
import json
import logging
import os
import time

try:                      # works as `agent.lib.symex` and as a bare script
    from . import binfacts, dwarfinfo
except ImportError:
    import binfacts
    import dwarfinfo

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUF_BASE = 0x30000000          # symbolic argument buffers live here
BUF_STRIDE = 0x10000

# Argument registers by calling convention. Only the ones we can read at a
# call site; everything past this goes on the stack and is reported as unknown.
ARGREGS = {
    "AMD64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "X86": [],
    "ARMEL": ["r0", "r1", "r2", "r3"],
    "AARCH64": ["x0", "x1", "x2", "x3", "x4", "x5"],
    "MIPS32": ["a0", "a1", "a2", "a3"],
}

# Which argument index carries the destination and the length, per sink.
SINK_ABI = {
    "memcpy": (0, 2), "mempcpy": (0, 2), "memmove": (0, 2), "memset": (0, 2),
    "strncpy": (0, 2), "strncat": (0, 2), "strlcpy": (0, 2),
    "bcopy": (1, 2),
    "read": (1, 2), "pread": (1, 2), "recv": (1, 2), "fread": (0, 1),
    "snprintf": (0, 1), "vsnprintf": (0, 1),
    "malloc": (None, 0), "calloc": (None, 1), "realloc": (None, 1),
    "alloca": (None, 0),
    "strcpy": (0, None), "stpcpy": (0, None), "strcat": (0, None),
    "sprintf": (0, None), "gets": (0, None),
}


def _quiet():
    for n in ("angr", "cle", "pyvex", "claripy", "archinfo"):
        logging.getLogger(n).setLevel("CRITICAL")


def _resolve(proj, ref):
    """Symbol name or hex string -> address."""
    if isinstance(ref, int):
        return ref
    ref = str(ref)
    if ref.startswith("0x"):
        return int(ref, 16)
    s = proj.loader.find_symbol(ref)
    if s is not None:
        return s.rebased_addr
    f = proj.kb.functions.function(name=ref)
    if f is not None:
        return f.addr
    raise KeyError("cannot resolve %r to an address" % ref)


def _build_args(state, spec, proj):
    """Turn the chunk's arg spec into concrete call arguments plus the
    symbolic variables they are backed by."""
    import claripy
    args, symvars, layout = [], {}, []
    slot = 0
    for a in spec:
        kind = a.get("kind", "concrete")
        name = a.get("name") or "arg%d" % len(args)
        if kind == "sym_buf":
            size = int(a.get("size", 64))
            addr = int(a["addr"], 16) if isinstance(a.get("addr"), str) \
                else a.get("addr") or (BUF_BASE + slot * BUF_STRIDE)
            slot += 1
            bv = claripy.BVS(name, size * 8)
            state.memory.store(addr, bv)
            symvars[name] = bv
            layout.append({"name": name, "addr": hex(addr), "size": size})
            args.append(addr)
        elif kind == "sym_scalar":
            bits = int(a.get("bits", proj.arch.bits))
            bv = claripy.BVS(name, bits)
            symvars[name] = bv
            args.append(bv)
        else:
            args.append(int(a["value"]))
    return args, symvars, layout


def _capacity(proj, state, dest, cfa, entry_name, chunk_sink, binary):
    """How many bytes fit at `dest` before something else is hit.

    Returned with the method used, because an agent reading this needs to know
    whether 32 is a DWARF fact or a frame-distance estimate."""
    if chunk_sink.get("dest_capacity") is not None:
        return int(chunk_sink["dest_capacity"]), "chunk_spec"
    if state.solver.symbolic(dest):
        return None, "dest_symbolic"
    d = state.solver.eval(dest)

    # Global?
    obj = proj.loader.find_object_containing(d)
    if obj is not None:
        sym = proj.loader.find_symbol(d)
        if sym is not None and sym.size:
            return sym.size, "global_symbol:%s" % sym.name
        for s in proj.loader.main_object.symbols:
            if s.size and s.rebased_addr <= d < s.rebased_addr + s.size:
                return s.rebased_addr + s.size - d, "global_symbol:%s+%d" % (
                    s.name, d - s.rebased_addr)

    # Stack local, via DWARF CFA offsets. Exact extents come from
    # dwarfinfo (pyelftools), because cle drops array subrange counts and the
    # frame-distance fallback below overstates a small buffer's capacity by
    # however much of the frame follows it.
    if cfa is not None:
        off = d - cfa
        cap, lv = dwarfinfo.capacity_at(binary, entry_name, off)
        if cap:
            return cap, "dwarf_local:%s:%s[%d]" % (lv["name"], lv["type"], cap)
        if cfa > d:
            return cfa - d, "frame_distance_to_cfa"
    return None, "unknown"


def _autofill_sinks(binary, chunk):
    """Sinks the chunker did not spell out are taken from the cached whole-
    binary facts. An agent should never be hand-typing call-site addresses --
    it gets them wrong, and a wrong address is silently unreachable."""
    if chunk.get("sinks"):
        return chunk["sinks"]
    try:
        facts = binfacts.extract(binary)
    except Exception:
        return []
    out = []
    for m in (chunk.get("members") or [chunk.get("entry")]):
        fn = (facts.get("functions") or {}).get(m)
        for sk in (fn or {}).get("sinks", []):
            out.append(dict(sk))
    return out


def _install_havoc(state, ranges):
    """Return a fresh symbolic value on every read of a havoc'd global.

    This is how a double-fetch becomes visible to symbolic execution. Model
    g_len as one symbol and handle_frame's CHECK and USE read the same value,
    so `n == g_len` and there is provably no bug. The defect only exists
    because something else -- the RFID ISR on the other core -- can change it
    between the two reads, so each read must yield an independent value. Any
    overflow found this way is conditional on that interference, which is why
    the result records the havoc count: it is a claim about concurrency, and
    the concolic and proof stages have to back it up.
    """
    import angr
    import claripy
    counter = [0]

    def _cb(st):
        try:
            ins = getattr(st.inspect, "attrs", st.inspect)
            a = ins.mem_read_address
            if a is None or st.solver.symbolic(a):
                return
            addr = st.solver.eval(a)
            ln = ins.mem_read_length or st.arch.bytes
            if not isinstance(ln, int):
                ln = st.arch.bytes
            for lo, hi, name in ranges:
                if lo <= addr < hi:
                    fresh = claripy.BVS("havoc_%s_%d" % (name, counter[0]), ln * 8)
                    counter[0] += 1
                    ins.mem_read_expr = fresh
                    return
        except Exception:
            return

    state.inspect.b("mem_read", when=angr.BP_AFTER, action=_cb)
    return counter


def run(binary, chunk, budget_s=None, loop_bound=None, state_cap=400,
        max_path=2000, veritesting=False):
    """Explore one chunk to its sinks. Returns a JSON-able result dict."""
    import angr
    import claripy
    _quiet()

    budget_s = int(budget_s or chunk.get("budget_s") or 300)
    loop_bound = int(loop_bound or chunk.get("loop_bound") or 16)
    t0 = time.time()

    proj = angr.Project(binary, auto_load_libs=False, load_debug_info=True)
    arch = proj.arch.name
    entry_name = chunk.get("entry") or (chunk.get("members") or [None])[0]
    entry = _resolve(proj, entry_name)

    # Scoped CFG: the chunk's members only. The whole-binary CFG lives in the
    # binfacts cache and is never recomputed here.
    regions = []
    for m in (chunk.get("members") or [entry_name]):
        try:
            a = _resolve(proj, m)
            f = proj.kb.functions.function(addr=a)
            size = (f.size if f else None) or 0x400
        except KeyError:
            continue
        regions.append((a, a + max(size, 0x40)))
    cfg = proj.analyses.CFGFast(regions=regions, normalize=True) if regions else None

    state = proj.factory.blank_state(
        addr=entry,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                     angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY})
    args, symvars, layout = _build_args(state, chunk.get("args") or [], proj)
    state = proj.factory.call_state(
        entry, *args, base_state=state,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
    sp_entry = state.solver.eval(state.regs.sp)
    cfa = sp_entry + (proj.arch.bytes)      # CFA = sp at entry + return slot

    havoc_names = chunk.get("havoc_globals") or []
    havoc_ranges, havoc_resolved = [], []
    for g in havoc_names:
        sym = proj.loader.find_symbol(g)
        if sym is None:
            continue
        havoc_ranges.append((sym.rebased_addr,
                             sym.rebased_addr + max(sym.size or proj.arch.bytes, 1), g))
        havoc_resolved.append({"name": g, "addr": hex(sym.rebased_addr),
                               "size": sym.size})
    havoc_counter = _install_havoc(state, havoc_ranges) if havoc_ranges else [0]

    # Sinks: explore to the callee entry, where the argument registers hold
    # the call's actual arguments.
    sinks = _autofill_sinks(binary, chunk)
    find = {}
    for s in sinks:
        ca = s.get("callee_addr")
        if ca is None:
            continue
        find[int(ca, 16) if isinstance(ca, str) else ca] = s
    if not find:
        return {"chunk_id": chunk.get("chunk_id"),
                "error": "no sinks: none given in the chunk and none found in "
                         "the cached facts for %s" % (chunk.get("members") or []),
                "entry": entry_name}

    simgr = proj.factory.simulation_manager(state, save_unsat=False)
    et = angr.exploration_techniques
    if cfg is not None:
        try:
            simgr.use_technique(et.LoopSeer(cfg=cfg, bound=loop_bound,
                                           limit_concrete_loops=False))
        except Exception:
            pass
    simgr.use_technique(et.LengthLimiter(max_path))
    if veritesting:
        simgr.use_technique(et.Veritesting())

    deadline = time.time() + budget_s
    stop = None
    steps = 0

    def _until(sm):
        nonlocal stop
        if time.time() > deadline:
            stop = "budget_exhausted"
            return True
        if len(sm.active) > state_cap:
            stop = "state_cap_exceeded"
            return True
        return False

    try:
        simgr.explore(find=list(find.keys()), until=_until)
        steps = simgr._stashes and 0 or 0
    except Exception as e:
        return {"chunk_id": chunk.get("chunk_id"), "entry": entry_name,
                "error": "%s: %s" % (type(e).__name__, e),
                "seconds": round(time.time() - t0, 1)}

    results = []
    for st in simgr.found:
        sink = find.get(st.addr, {})
        callee = sink.get("callee", "?")
        regs = ARGREGS.get(arch, [])
        vals = {}
        for i, r in enumerate(regs[:4]):
            try:
                vals[r] = getattr(st.regs, r)
            except Exception:
                pass
        di, li = SINK_ABI.get(callee, (0, 2))
        dest = vals.get(regs[di]) if di is not None and di < len(regs) else None
        ln = vals.get(regs[li]) if li is not None and li < len(regs) else None

        entry_res = {
            "sink": {"callee": callee, "callee_addr": hex(st.addr),
                     "call_site": sink.get("call_block")},
            "reached": True,
            "call_site_observed": hex(st.history.jump_source or 0),
        }
        cap, how = (None, "no_dest")
        if dest is not None:
            cap, how = _capacity(proj, st, dest, cfa, entry_name, sink, binary)
            entry_res["dest"] = ("symbolic" if st.solver.symbolic(dest)
                                 else hex(st.solver.eval(dest)))
        entry_res["dest_capacity"] = cap
        entry_res["capacity_source"] = how

        if ln is None:
            entry_res["length"] = "not_in_registers"
            results.append(entry_res)
            continue

        sym = st.solver.symbolic(ln)
        entry_res["length_symbolic"] = sym
        if not sym:
            n = st.solver.eval(ln)
            entry_res["length"] = n
            entry_res["overflow"] = bool(cap is not None and n > cap)
        else:
            try:
                entry_res["length_max"] = st.solver.max(ln)
                entry_res["length_min"] = st.solver.min(ln)
            except Exception:
                pass
            if cap is None:
                entry_res["verdict"] = "length_attacker_controlled_capacity_unknown"
            else:
                cond = ln > cap
                if st.solver.satisfiable(extra_constraints=[cond]):
                    sol = st.copy()
                    sol.solver.add(cond)
                    entry_res["overflow"] = True
                    entry_res["solved"] = {
                        k: sol.solver.eval(v, cast_to=bytes).hex()
                        for k, v in symvars.items()
                    }
                    entry_res["solved_length"] = sol.solver.eval(ln)
                    # Where a proof would have to come from. A chunk with no
                    # symbolic argument has no input to solve for: the length
                    # became attacker-controlled through a havoc'd global, so
                    # the only possible proof is an interleaving, not a byte
                    # string. Saying so here stops the analyzer downstream
                    # from inventing a PoC that cannot exist.
                    entry_res["poc_kind"] = "input" if symvars else "interference"
                    if entry_res.get("length_max", 0) >= (1 << (proj.arch.bits - 1)):
                        entry_res["length_unbounded"] = True
                else:
                    # The negative result symbolic execution can give and
                    # fuzzing cannot: no input in this domain overflows.
                    entry_res["overflow"] = False
                    entry_res["proved_unreachable"] = (
                        "length > %d is UNSAT along this path; the guards on "
                        "the path bound it" % cap)
        results.append(entry_res)

    unreached = [hex(a) for a in find if not any(
        r["sink"]["callee_addr"] == hex(a) for r in results)]

    return {
        "chunk_id": chunk.get("chunk_id"),
        "entry": entry_name, "entry_addr": hex(entry),
        "arch": arch,
        "havoc_globals": havoc_resolved,
        "havoc_reads": havoc_counter[0],
        "interference_modeled": bool(havoc_resolved),
        "arg_layout": layout,
        "sinks_reached": len(results),
        "sinks_not_reached": unreached,
        "results": results,
        "stopped_early": stop,
        "stashes": {k: len(v) for k, v in simgr._stashes.items() if v},
        "seconds": round(time.time() - t0, 1),
        "budget_s": budget_s, "loop_bound": loop_bound,
    }


if __name__ == "__main__":
    import sys
    binary = sys.argv[1]
    chunk = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    print(json.dumps(run(binary, chunk), indent=2))
