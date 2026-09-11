#!/usr/bin/env python3
"""
Symbolic execution probe.

Asks angr to produce an input that reaches the memcpy inside parse_config
with an attacker-controlled length. This is the shape of the call the LLM
agent makes when the fuzzer stalls on a structured/magic-value input --
exactly the Driller pattern from the survey.

Usage: python3 solve_parse_config.py ../host_twin/target_plain
"""
import logging
import sys

import angr
import claripy

logging.getLogger("angr").setLevel("ERROR")
logging.getLogger("cle").setLevel("ERROR")

BIN = sys.argv[1] if len(sys.argv) > 1 else "../host_twin/target_plain"
INPUT_LEN = int(sys.argv[2]) if len(sys.argv) > 2 else 64
BUF = 0x100000

proj = angr.Project(BIN, auto_load_libs=False)
sym_fn = proj.loader.find_symbol("parse_config")
if sym_fn is None:
    sys.exit("parse_config not found -- build with symbols (no -s/strip)")

# Symbolic input buffer, concrete length.
data = claripy.BVS("cfg", INPUT_LEN * 8)
state = proj.factory.call_state(sym_fn.rebased_addr, BUF, INPUT_LEN)
state.memory.store(BUF, data)

# Locate the memcpy call site inside parse_config.
cfg = proj.analyses.CFGFast(
    regions=[(sym_fn.rebased_addr, sym_fn.rebased_addr + sym_fn.size)]
)
fn = cfg.functions.get(sym_fn.rebased_addr)
targets = []
# Match a direct call across ISAs, not just x86. The reference machine was
# x86-64 ('call'); on Apple Silicon / any aarch64 host the same static binary
# emits 'bl' for the memcpy call, and the original 'call'-only match found
# nothing and aborted the whole angr track. Cover the common lifters angr
# supports so the solve reproduces regardless of who runs it.
CALL_MNEMONICS = {"call", "bl", "blr", "jal", "jalr", "blx", "callr"}
for blk in fn.blocks:
    for ins in blk.capstone.insns:
        if ins.mnemonic in CALL_MNEMONICS:
            targets.append(ins.address)

if not targets:
    sys.exit("no call site found in parse_config (checked mnemonics: %s)"
             % ", ".join(sorted(CALL_MNEMONICS)))

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=targets[-1], num_find=1)

if simgr.found:
    found = simgr.found[0]
    # Direct the solver at the bug condition, not just reachability:
    # the 16-bit length field (bytes 1..2, big-endian) must exceed the
    # 32-byte destination buffer.
    length_field = data[(INPUT_LEN - 1) * 8 - 1 : (INPUT_LEN - 3) * 8]
    found.solver.add(length_field > 32)
    if not found.solver.satisfiable():
        sys.exit("reachable, but length cannot exceed the destination")
    val = found.solver.eval(data, cast_to=bytes)
    nlen = int.from_bytes(val[1:3], "big")
    print(f"reached memcpy call at {targets[-1]:#x}")
    print(f"input      : {val[:8].hex()}... ({len(val)} bytes)")
    print(f"magic      : {val[0]:#04x}")
    print(f"length fld : {nlen} (destination is 32 bytes)")
    print("OVERFLOW" if nlen > 32 else "in-bounds -- add a constraint and re-solve")
else:
    print("no path found -- see README step 12 for the fallback")
