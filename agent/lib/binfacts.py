#!/usr/bin/env python3
"""
Binary fact extraction -- the expensive step, computed once and cached.

A whole-binary CFGFast on the statically linked twin costs ~130s and recovers
7219 functions, of which 12 are yours. Every downstream stage needs these
facts and none can afford to recompute them, so this is the only module that
runs CFG recovery over the full address space; results are cached by binary
SHA-256 and every later query is a dict lookup. The scoped CFGs that symex and
concolic build per chunk cover one function's byte range and cost milliseconds.

Three things are extracted that the chunker cannot get any other way:

  user code      DWARF functions_debug_info separates the 12 functions that
                 came from your sources from the 7207 that came from libc.
                 Without it every ranking is dominated by __gconv_* noise.
  shared globals xrefs by destination give reader/writer sets per global. This
                 is the edge the call graph does not have: rfid_isr writes
                 g_len, handle_frame reads it, and no call edge connects them.
  stack layout   DWARF locals give CFA-relative offsets and array extents, so
                 a destination buffer's true capacity is a fact rather than an
                 agent's assertion.
"""
import hashlib
import json
import re
import logging
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CACHE = os.path.join(ROOT, "agent", "artifacts", "cache")

# Call targets where an attacker-controlled length or index becomes a memory
# write. Not a vulnerability list -- a list of places worth pointing symbolic
# execution at.
SINKS = {
    "memcpy", "mempcpy", "memmove", "memset", "bcopy", "bzero",
    "strcpy", "stpcpy", "strcat", "strncpy", "strncat", "strlcpy", "strlcat",
    "sprintf", "vsprintf", "snprintf", "vsnprintf",
    "gets", "fgets", "read", "pread", "recv", "recvfrom", "fread",
    "alloca", "malloc", "calloc", "realloc", "free",
    "sscanf", "scanf", "system", "execve", "popen",
}

# Used only when there is no debug info. Names that mean "this is runtime, not
# target code" on a static glibc build.
LIBC_PREFIXES = ("_dl_", "__gconv", "_nl_", "__libc", "_IO_", "__pthread",
                 "__printf", "__wcsmbs", "__intl", "__gettext", "_itoa",
                 "__tunable", "__rtld", "__elf", "_dlfo")


# glibc decorates its real implementations: memcpy is an IFUNC whose PLT stub
# resolves to __new_memcpy, and the selected variant may be
# __memcpy_avx_unaligned_erms. Sink detection that matches on the literal name
# finds nothing on a static build -- parse_config reported zero sinks until
# this existed.
_ISA_SUFFIX = re.compile(
    r"_(avx|avx2|avx512|sse|sse2|ssse3|evex|erms|unaligned|generic|rep|movsb|"
    r"stosb|nt|novec)([_0-9a-z]*)$")


def normalize_callee(name):
    n = (name or "").lstrip("_").split("@")[0].split(".")[0]
    for pfx in ("new_", "GI_", "libc_", "interceptor_"):
        if n.startswith(pfx):
            n = n[len(pfx):]
    prev = None
    while prev != n:
        prev = n
        n = _ISA_SUFFIX.sub("", n)
    return n


def _ifunc_map(proj):
    """GOT slot -> resolved name, from IRELATIVE relocation addends. On a
    static binary every libc call goes through one of these."""
    out = {}
    for r in proj.loader.main_object.relocs:
        a = getattr(r, "addend", None)
        if not a:
            continue
        sym = proj.loader.find_symbol(a)
        if sym is not None and sym.name:
            out[r.rebased_addr] = sym.name
    return out


def _resolve_stub(proj, addr, imap):
    """Follow a `jmp qword ptr [rip+X]` PLT stub to the name behind its GOT
    slot. Returns None when addr is not such a stub."""
    try:
        blk = proj.factory.block(addr)
        ins = blk.capstone.insns[-1]
        if ins.mnemonic != "jmp" or not ins.operands:
            return None
        mem = ins.operands[0].mem
        if mem is None:
            return None
        got = ins.address + ins.size + mem.disp
        return imap.get(got)
    except Exception:
        return None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def cache_path(binary):
    return os.path.join(CACHE, "cfg-%s.json" % sha256(binary)[:16])


def _type_size(t, depth=0):
    """Byte size of a cle DWARF type, best effort. ArrayType is the one that
    matters: it carries the capacity of a destination buffer."""
    if t is None or depth > 6:
        return None
    for attr in ("byte_size", "size"):
        v = getattr(t, attr, None)
        if isinstance(v, int) and v > 0:
            return v
    el = getattr(t, "element_type", None)
    cnt = getattr(t, "count", None)
    if el is not None and isinstance(cnt, int):
        es = _type_size(el, depth + 1)
        if es:
            return es * cnt
    return _type_size(getattr(t, "type", None), depth + 1)


def _type_name(t, depth=0):
    if t is None or depth > 6:
        return None
    n = getattr(t, "name", None)
    if n:
        return str(n)
    el = getattr(t, "element_type", None)
    if el is not None:
        return "%s[]" % (_type_name(el, depth + 1) or "?")
    return type(t).__name__


def extract(binary, force=False):
    """Run (or load) whole-binary CFG recovery. Returns the facts dict."""
    binary = os.path.abspath(binary)
    cp = cache_path(binary)
    if os.path.exists(cp) and not force:
        with open(cp) as f:
            d = json.load(f)
        d["cached"] = True
        return d

    import angr
    for n in ("angr", "cle", "pyvex", "claripy"):
        logging.getLogger(n).setLevel("CRITICAL")

    t0 = time.time()
    proj = angr.Project(binary, auto_load_libs=False, load_debug_info=True)
    cfg = proj.analyses.CFGFast(cross_references=True, normalize=True)
    elapsed = time.time() - t0

    mo = proj.loader.main_object
    cg = cfg.functions.callgraph
    imap = _ifunc_map(proj)

    # ---- user code, from DWARF when present -------------------------------
    fdi = getattr(mo, "functions_debug_info", None) or {}
    user_dbg = {}
    for addr, f in fdi.items():
        try:
            user_dbg[f.name] = {
                "source_file": f.source_file,
                "source_line": f.source_line,
                "low_pc": hex(f.low_pc), "high_pc": hex(f.high_pc),
                "locals": [
                    {"name": lv.name, "sort": lv.sort, "cfa_offset": lv.addr,
                     "type": _type_name(lv.type), "size": _type_size(lv.type),
                     "decl_line": lv.decl_line}
                    for lv in (f.local_variables or []) if lv.name
                ],
            }
        except Exception:
            continue
    have_dwarf = bool(user_dbg)
    source_files = sorted({v["source_file"] for v in user_dbg.values()
                           if v.get("source_file")})

    # ---- functions --------------------------------------------------------
    funcs = {}
    for addr, f in cfg.functions.items():
        if f.is_plt or f.is_syscall or f.is_simprocedure:
            continue
        name = f.name
        dbg = user_dbg.get(name)
        if have_dwarf:
            is_user = dbg is not None
        else:
            is_user = not name.startswith(LIBC_PREFIXES)

        sinks = []
        try:
            for site in f.get_call_sites():
                tgt = f.get_call_target(site)
                if tgt is None:
                    continue
                tf = cfg.functions.function(addr=tgt)
                raw = tf.name if tf else "sub_%x" % tgt
                if tf is None or raw.startswith("sub_"):
                    raw = _resolve_stub(proj, tgt, imap) or raw
                base = normalize_callee(raw)
                if base in SINKS:
                    sinks.append({"call_block": hex(site), "callee": base,
                                  "raw_callee": raw, "callee_addr": hex(tgt)})
        except Exception:
            pass

        funcs[name] = {
            "name": name, "addr": hex(addr), "size": f.size,
            "blocks": len(f.block_addrs_set), "is_user": is_user,
            "callers": sorted({cfg.functions.function(addr=c).name
                               for c in cg.predecessors(addr)
                               if cfg.functions.function(addr=c)}),
            "callees": sorted({cfg.functions.function(addr=c).name
                               for c in cg.successors(addr)
                               if cfg.functions.function(addr=c)}),
            "sinks": sinks, "reads": [], "writes": [], "refs": [],
        }
        if dbg:
            funcs[name].update(dbg)

    # ---- globals and their reader/writer sets -----------------------------
    cu_globals = set()
    for cu in (getattr(mo, "compilation_units", None) or []):
        for g in (cu.global_variables or []):
            if getattr(g, "name", None):
                cu_globals.add(g.name)

    globs = {}
    for s in mo.symbols:
        try:
            if not s.name or not s.size:
                continue
            if "OBJECT" not in str(getattr(s, "type", "")).upper():
                continue
            xs = proj.kb.xrefs.get_xrefs_by_dst(s.rebased_addr)
            if not xs:
                continue
            readers, writers, refs = set(), set(), set()
            for x in xs:
                fn = cfg.functions.floor_func(x.block_addr)
                if fn is None or fn.is_simprocedure:
                    continue
                ts = str(x.type_string).lower()
                if "write" in ts:
                    writers.add(fn.name)
                elif "offset" in ts:
                    # `lea rax, [rip+g_frame]` -- the address is taken, and
                    # what happens to it afterwards (memcpy destination, say)
                    # is invisible to the xref. Treat as a potential write:
                    # classifying it as a read is what hid g_frame and
                    # g_eeprom from the shared-global set.
                    refs.add(fn.name)
                else:
                    readers.add(fn.name)
            if not (readers or writers or refs):
                continue
            touchers = readers | writers | refs
            globs[s.name] = {
                "name": s.name, "addr": hex(s.rebased_addr), "size": s.size,
                "readers": sorted(readers), "writers": sorted(writers),
                "addr_taken_by": sorted(refs),
                "is_user": s.name in cu_globals if have_dwarf
                           else not s.name.startswith(LIBC_PREFIXES),
                # The property the chunker cares about: more than one function
                # touches it, and at least one of them can modify it --
                # directly, or through a pointer it took the address into.
                "shared": len(touchers) > 1 and bool(writers or refs),
            }
            for fn in readers:
                if fn in funcs and s.name not in funcs[fn]["reads"]:
                    funcs[fn]["reads"].append(s.name)
            for fn in writers:
                if fn in funcs and s.name not in funcs[fn]["writes"]:
                    funcs[fn]["writes"].append(s.name)
            for fn in refs:
                if fn in funcs and s.name not in funcs[fn]["refs"]:
                    funcs[fn]["refs"].append(s.name)
        except Exception:
            continue

    shared_user = sorted(g for g, v in globs.items() if v["shared"] and v["is_user"])

    # ---- interest score. An ordering, not a verdict: it decides what the
    # chunker sees first, never what it concludes.
    for name, fn in funcs.items():
        score = 0
        if fn["is_user"]:
            score += 10
        score += 3 * len(fn["sinks"])
        score += 4 * len({*fn["reads"], *fn["writes"], *fn["refs"]} & set(shared_user))
        if fn.get("locals"):
            score += len([lv for lv in fn["locals"]
                          if lv.get("size") and lv["size"] > 8])
        fn["score"] = score

    facts = {
        "binary": binary, "sha256": sha256(binary), "arch": str(proj.arch.name),
        "bits": proj.arch.bits, "entry": hex(proj.entry), "pic": bool(mo.pic),
        "has_debug_info": have_dwarf, "source_files": source_files,
        "cfg_seconds": round(elapsed, 1),
        "function_count": len(funcs),
        "user_function_count": sum(1 for f in funcs.values() if f["is_user"]),
        "functions": funcs, "globals": globs,
        "shared_globals": shared_user,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    os.makedirs(CACHE, exist_ok=True)
    with open(cp, "w") as f:
        json.dump(facts, f, indent=1)
    facts["cached"] = False
    return facts


if __name__ == "__main__":
    import sys
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    d = extract(argv[0] if argv else os.path.join(ROOT, "host_twin", "target_plain"),
                force="--force" in sys.argv)
    print(json.dumps({k: v for k, v in d.items()
                      if k not in ("functions", "globals")}, indent=2))
    print("\nuser functions by score:")
    for f in sorted([x for x in d["functions"].values() if x["is_user"]],
                    key=lambda x: -x["score"]):
        print("  %-20s %-9s score=%-3s sinks=%-18s reads=%-20s writes=%-14s ref=%s"
              % (f["name"], f["addr"], f["score"],
                 ",".join(sorted({s["callee"] for s in f["sinks"]})) or "-",
                 ",".join(f["reads"]) or "-", ",".join(f["writes"]) or "-",
                 ",".join(f["refs"]) or "-"))
    print("\nshared user globals:")
    for g in d["shared_globals"]:
        v = d["globals"][g]
        print("  %-14s %-10s size=%-4s readers=%-22s writers=%-18s addr_taken=%s"
              % (g, v["addr"], v["size"], ",".join(v["readers"]) or "-",
                 ",".join(v["writers"]) or "-", ",".join(v["addr_taken_by"]) or "-"))
