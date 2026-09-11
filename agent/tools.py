#!/usr/bin/env python3
"""
The toolkit every stage calls. One dispatch table, two drivers.

Design rule, unchanged from the original scaffold: every tool returns
*evidence*, never a verdict. The model reasons; the tools ground. What changed
is that nothing is hardcoded to one function or one binary any more -- the
target arrives as an argument, the facts come from a cache, and the sinks come
from the facts.

Both drivers go through call(): pipeline.py (the Anthropic API loop) and
toolcli.py (the CLI a Claude Code subagent drives). There is deliberately no
second code path to keep in sync.

Outputs are summarised or paginated at the boundary. The whole-binary facts for
the twin are 7219 functions; handing that to a model verbatim is both useless
and expensive, so list_functions ranks and truncates, and the caller asks for
detail on what it actually cares about.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent", "lib"))

import binfacts        # noqa: E402
import concolic        # noqa: E402
import dwarfinfo       # noqa: E402
import emulate         # noqa: E402
import symex           # noqa: E402

TWIN = os.path.join(ROOT, "host_twin")
ARTIFACTS = os.path.join(ROOT, "agent", "artifacts")
DEFAULT_BINARY = os.environ.get("ESC_TARGET", os.path.join(TWIN, "target_plain"))
DEFAULT_HARNESS = os.environ.get("ESC_HARNESS", os.path.join(TWIN, "fuzz_stdin"))


def _bin(b=None):
    b = b or DEFAULT_BINARY
    return b if os.path.isabs(b) else os.path.join(ROOT, b)


# ----------------------------------------------------------------- inspection
def list_files() -> str:
    out = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "__pycache__", "cache", "build")]
        for f in files:
            out.append(os.path.relpath(os.path.join(base, f), ROOT))
    return "\n".join(sorted(out))


def read_source(path: str, start: int = 1, end: int = 400) -> str:
    full = os.path.normpath(os.path.join(ROOT, path))
    if not full.startswith(ROOT):
        return "error: path escapes repo root"
    if not os.path.exists(full):
        return "error: no such file: %s" % path
    with open(full, errors="replace") as f:
        lines = f.readlines()
    sel = lines[max(0, start - 1):end]
    return "".join("%5d\t%s" % (i, l) for i, l in enumerate(sel, start=max(1, start)))


def binary_facts(binary: str = None, refresh: bool = False) -> dict:
    """Whole-binary CFG facts. Expensive once (~130s on a static binary),
    cached by SHA-256 afterwards. Returns the summary, not the 7219-function
    table -- use list_functions for that."""
    f = binfacts.extract(_bin(binary), force=refresh)
    return {k: v for k, v in f.items() if k not in ("functions", "globals")}


def list_functions(binary: str = None, user_only: bool = True, limit: int = 40,
                   min_score: int = 0, name_contains: str = None,
                   with_sinks_only: bool = False) -> dict:
    f = binfacts.extract(_bin(binary))
    rows = list(f["functions"].values())
    if user_only:
        rows = [r for r in rows if r.get("is_user")]
    if with_sinks_only:
        rows = [r for r in rows if r.get("sinks")]
    if name_contains:
        rows = [r for r in rows if name_contains.lower() in r["name"].lower()]
    rows = [r for r in rows if r.get("score", 0) >= min_score]
    rows.sort(key=lambda r: -r.get("score", 0))
    total = len(rows)
    return {
        "total_matching": total, "showing": min(total, limit),
        "user_function_count": f.get("user_function_count"),
        "function_count": f.get("function_count"),
        "functions": [{
            "name": r["name"], "addr": r["addr"], "size": r["size"],
            "blocks": r["blocks"], "score": r.get("score"),
            "sinks": sorted({s["callee"] for s in r.get("sinks", [])}),
            "reads": r.get("reads", []), "writes": r.get("writes", []),
            "addr_taken": r.get("refs", []),
            "callers": r.get("callers", [])[:6], "callees": r.get("callees", [])[:6],
            "source": (r.get("source_file") or "").split("/")[-1] or None,
            "line": r.get("source_line"),
        } for r in rows[:limit]],
    }


def function_info(binary: str = None, name: str = None, disasm: bool = False) -> dict:
    f = binfacts.extract(_bin(binary))
    r = f["functions"].get(name)
    if r is None:
        near = [n for n in f["functions"] if name and name.lower() in n.lower()][:8]
        return {"error": "no function %r" % name, "did_you_mean": near}
    out = dict(r)
    out["stack_layout"] = dwarfinfo.stack_layout(_bin(binary)).get(name)
    if disasm:
        out["disasm"] = disassemble(binary, name).get("disasm")
    return out


def global_info(binary: str = None, name: str = None, shared_only: bool = True) -> dict:
    f = binfacts.extract(_bin(binary))
    if name:
        g = f["globals"].get(name)
        return g or {"error": "no global %r" % name}
    rows = [v for v in f["globals"].values()
            if (v.get("shared") and v.get("is_user")) or not shared_only]
    rows.sort(key=lambda v: -(len(v["readers"]) + len(v["writers"]) + len(v["addr_taken_by"])))
    return {"count": len(rows), "globals": rows[:40]}


def stack_layout(binary: str = None, function: str = None) -> dict:
    lay = dwarfinfo.stack_layout(_bin(binary))
    if function:
        return lay.get(function) or {"error": "no DWARF layout for %r" % function}
    return {"functions": sorted(lay)}


def disassemble(binary: str = None, name: str = None, limit: int = 120) -> dict:
    import angr
    import logging
    for n in ("angr", "cle", "pyvex"):
        logging.getLogger(n).setLevel("CRITICAL")
    b = _bin(binary)
    proj = angr.Project(b, auto_load_libs=False, load_debug_info=True)
    try:
        addr = symex._resolve(proj, name)
    except KeyError as e:
        return {"error": str(e)}
    facts = binfacts.extract(b)
    size = (facts["functions"].get(name) or {}).get("size") or 0x200
    cfg = proj.analyses.CFGFast(regions=[(addr, addr + size)], normalize=True)
    fn = cfg.functions.function(addr=addr)
    lines = []
    for blk in sorted(fn.blocks, key=lambda x: x.addr):
        for i in blk.capstone.insns:
            lines.append("%#x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
            if len(lines) >= limit:
                break
    return {"function": name, "addr": hex(addr), "disasm": "\n".join(lines)}


# -------------------------------------------------------------------- analysis
def symex_chunk(chunk: dict, binary: str = None, budget_s: int = 300,
                loop_bound: int = 16, state_cap: int = 400,
                veritesting: bool = False) -> dict:
    """Directed symbolic execution over one chunk, stopping at its sinks."""
    return symex.run(_bin(binary), chunk, budget_s=budget_s,
                     loop_bound=loop_bound, state_cap=state_cap,
                     veritesting=veritesting)


def concolic_chunk(chunk: dict, seeds=None, binary: str = None,
                   generations: int = 3, max_new_inputs: int = 8,
                   budget_s: int = 600, harness: str = None,
                   replay: bool = True) -> dict:
    """Concolic execution: preconstrained seed, branch negation, generations.
    Every generated input is replayed through the ASan harness when one is
    available, so a returned crash is an observation and not a claim."""
    seeds = seeds or ["41" * 64]
    if isinstance(seeds, str):
        seeds = [seeds]
    return concolic.run_generations(
        _bin(binary), chunk, seeds, generations=generations,
        max_new_inputs=max_new_inputs, budget_s=budget_s,
        harness=harness or DEFAULT_HARNESS, replay=replay)


# ----------------------------------------------------------------------- proof
def validate_poc(poc_hex: str, harness: str = None) -> dict:
    return emulate.validate_poc(poc_hex, harness or DEFAULT_HARNESS)


def prove_interference(mode: str = "race", iters: int = 20, widen: int = 1,
                       unwidened_iters: int = 0) -> dict:
    return emulate.prove_interference(mode, iters, widen, unwidened_iters)


def prove_oracle(iters: int = 20, widen: int = 1, control_checks: int = 500) -> dict:
    return emulate.prove_oracle(iters, widen, control_checks)


def run_tsan(iters: int = 40, widen: int = 1) -> dict:
    return emulate.run_tsan(iters, widen)


def build(target: str = "all") -> dict:
    return emulate.build(target)


def emulate_firmware() -> dict:
    return emulate.emulate_firmware()


# ------------------------------------------------------------------- artifacts
def write_artifact(name: str, content) -> dict:
    """Persist a stage's output. Artifacts are the contract between stages:
    every stage reads the previous one's file, so any stage re-runs alone."""
    if "/" in name or name.startswith("."):
        return {"error": "artifact names are flat, e.g. chunks.json"}
    os.makedirs(ARTIFACTS, exist_ok=True)
    path = os.path.join(ARTIFACTS, name)
    if not isinstance(content, str):
        content = json.dumps(content, indent=1)
    with open(path, "w") as f:
        f.write(content)
    return {"wrote": os.path.relpath(path, ROOT), "bytes": len(content)}


def read_artifact(name: str) -> dict:
    path = os.path.join(ARTIFACTS, name)
    if not os.path.exists(path):
        return {"error": "no artifact %r" % name,
                "available": sorted(f for f in os.listdir(ARTIFACTS)
                                    if f.endswith(".json"))
                if os.path.isdir(ARTIFACTS) else []}
    with open(path, errors="replace") as f:
        body = f.read()
    try:
        return {"name": name, "content": json.loads(body)}
    except ValueError:
        return {"name": name, "content": body}


# --------------------------------------------------------------- tool schemas
def _s(name, desc, props=None, required=None):
    return {"name": name, "description": desc,
            "input_schema": {"type": "object", "properties": props or {},
                             **({"required": required} if required else {})}}


_BIN = {"binary": {"type": "string", "description":
                   "Path to the target ELF. Defaults to the configured target."}}
_CHUNK = {"type": "object", "description":
          "Chunk spec: {chunk_id, members[], entry, args[], sinks[] (optional, "
          "auto-filled from cached facts), havoc_globals[] (optional), "
          "poc_prefix_hex (optional), budget_s}. An arg is {name, kind} where "
          "kind is sym_buf (with size), sym_scalar, seed_len, or concrete "
          "(with value)."}

SCHEMAS = {t["name"]: t for t in [
    _s("list_files", "List every file in the repo."),
    _s("read_source", "Read numbered lines from a source file.",
       {"path": {"type": "string"}, "start": {"type": "integer"},
        "end": {"type": "integer"}}, ["path"]),
    _s("binary_facts", "Whole-binary CFG summary: arch, counts, shared globals, "
       "debug-info availability. Expensive on first call, cached after.",
       {**_BIN, "refresh": {"type": "boolean"}}),
    _s("list_functions", "Ranked function list. Defaults to user code only, "
       "which on a static binary is 12 functions out of 7219.",
       {**_BIN, "user_only": {"type": "boolean"}, "limit": {"type": "integer"},
        "min_score": {"type": "integer"}, "name_contains": {"type": "string"},
        "with_sinks_only": {"type": "boolean"}}),
    _s("function_info", "Everything known about one function: callers, callees, "
       "sinks with call-site addresses, globals read/written/address-taken, and "
       "its DWARF stack layout.",
       {**_BIN, "name": {"type": "string"}, "disasm": {"type": "boolean"}}, ["name"]),
    _s("global_info", "Globals with their reader/writer/address-taken sets. "
       "This is the relation the call graph does not have.",
       {**_BIN, "name": {"type": "string"}, "shared_only": {"type": "boolean"}}),
    _s("stack_layout", "Exact DWARF stack layout: locals, CFA offsets and true "
       "array extents. This is where a destination buffer's capacity comes from.",
       {**_BIN, "function": {"type": "string"}}),
    _s("disassemble", "Disassemble one function.",
       {**_BIN, "name": {"type": "string"}, "limit": {"type": "integer"}}, ["name"]),
    _s("symex_chunk", "Directed symbolic execution over one chunk. Explores to "
       "the chunk's sinks, reads the length and destination from the argument "
       "registers at the call, derives capacity from DWARF, and reports either a "
       "solved overflowing input or a proof that no such input exists.",
       {"chunk": _CHUNK, **_BIN, "budget_s": {"type": "integer"},
        "loop_bound": {"type": "integer"}, "state_cap": {"type": "integer"},
        "veritesting": {"type": "boolean"}}, ["chunk"]),
    _s("concolic_chunk", "Concolic execution over one chunk: preconstrain a "
       "symbolic input to a concrete seed, follow that single path, negate its "
       "branches to generate new seeds, and replay each through the ASan "
       "harness. Returns coverage, generated inputs and confirmed crashes.",
       {"chunk": _CHUNK, "seeds": {"type": "array", "items": {"type": "string"}},
        **_BIN, "generations": {"type": "integer"},
        "max_new_inputs": {"type": "integer"}, "budget_s": {"type": "integer"},
        "harness": {"type": "string"}, "replay": {"type": "boolean"}}, ["chunk"]),
    _s("validate_poc", "THE GATE. Run a hex input against the instrumented "
       "harness and report whether it actually crashed, with the sanitizer lines.",
       {"poc_hex": {"type": "string"}, "harness": {"type": "string"}}, ["poc_hex"]),
    _s("prove_interference", "Proof for a concurrency claim: run the concurrent "
       "workload under ASan with the race window widened, and optionally "
       "reproduce it unwidened so the finding is not an artifact of the hook.",
       {"mode": {"type": "string"}, "iters": {"type": "integer"},
        "widen": {"type": "integer"}, "unwidened_iters": {"type": "integer"}}),
    _s("prove_oracle", "Proof for a claim no sanitizer can see: a differential "
       "against a sequential control that must read zero.",
       {"iters": {"type": "integer"}, "widen": {"type": "integer"},
        "control_checks": {"type": "integer"}}),
    _s("run_tsan", "ThreadSanitizer over the concurrent workload. Reports "
       "harness_broken separately, because a TSan that cannot map shadow memory "
       "looks exactly like a clean run.",
       {"iters": {"type": "integer"}, "widen": {"type": "integer"}}),
    _s("build", "Build the instrumented binaries.", {"target": {"type": "string"}}),
    _s("emulate_firmware", "Boot the Xtensa firmware under qemu. Fidelity check "
       "only -- angr has no Xtensa lifter, so no symbolic stage runs on it."),
    _s("write_artifact", "Persist this stage's output artifact.",
       {"name": {"type": "string"}, "content": {}}, ["name", "content"]),
    _s("read_artifact", "Read a previous stage's artifact.",
       {"name": {"type": "string"}}, ["name"]),
]}

DISPATCH = {
    "list_files": lambda **k: list_files(), "read_source": read_source,
    "binary_facts": binary_facts, "list_functions": list_functions,
    "function_info": function_info, "global_info": global_info,
    "stack_layout": stack_layout, "disassemble": disassemble,
    "symex_chunk": symex_chunk, "concolic_chunk": concolic_chunk,
    "validate_poc": validate_poc, "prove_interference": prove_interference,
    "prove_oracle": prove_oracle, "run_tsan": run_tsan, "build": build,
    "emulate_firmware": emulate_firmware,
    "write_artifact": write_artifact, "read_artifact": read_artifact,
}


def schemas_for(names):
    return [SCHEMAS[n] for n in names if n in SCHEMAS]


def call(name: str, args: dict):
    fn = DISPATCH.get(name)
    if fn is None:
        return {"error": "unknown tool %r" % name,
                "available": sorted(DISPATCH)}
    try:
        return fn(**(args or {}))
    except TypeError as e:
        return {"error": "bad arguments for %s: %s" % (name, e),
                "schema": SCHEMAS.get(name, {}).get("input_schema")}
    except Exception as e:      # tools must never kill the loop
        return {"error": "%s: %s" % (type(e).__name__, e)}


if __name__ == "__main__":
    print(json.dumps(call("binary_facts", {}), indent=2))
