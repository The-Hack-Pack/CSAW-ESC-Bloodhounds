# What changed: single-loop agent → staged analysis pipeline

Comparison of `0d72f02` ("Make the testbed actually run") against `23ce72f`
("concolic exec prototype"). 27 files changed, 3168 insertions, 410 deletions.

The old agent layer was 431 lines across four files. It worked, and it found
all three planted bugs. It was also hardcoded to one function of one binary,
which is the property that made it a demo rather than a tool.

---

## At a glance

| | old (`0d72f02`) | new (`23ce72f`) |
|---|---|---|
| agent structure | 1 conversation, 1 tool set, 25 turns | 5 stages, 5 conversations, per-stage tool sets and budgets |
| tools | 8 | 18 |
| target | hardcoded `host_twin/` | any x86-64 ELF (`ESC_TARGET`) |
| symbolic entry | `find_symbol("parse_config")`, literal | chunk spec: entry, args, sinks |
| sink location | `targets[-1]` — last `call` in the function | call-site addresses from cached CFG facts |
| overflow condition | bit-slice of input bytes 1..2, big-endian | length register at the call site, per calling convention |
| destination capacity | not modelled; assumed 32 | derived from DWARF array extents |
| concolic execution | none | preconstrained seed + branch negation, generational |
| CFG cost | re-derived per invocation | whole-binary facts cached by binary SHA-256 |
| output | one text blob → `findings.json` | five JSON artifacts with declared contracts |
| drivers | 1 (API loop) | 2 (API loop; CLI for subagents) over one dispatch table |
| proof model | `validate_poc` only | input / interference / oracle |
| measurement | none | `scripts/experiments.py`, 6 experiments |

---

## 1. One loop became five stages

**Old.** `run_agent.py` (162 lines) held a single `SYSTEM` prompt, one tool set,
and a `while turns < budget` loop. The agent decided everything — what to read,
when to solve, when to validate — and the run's output was whatever text the
model emitted last, written verbatim to `findings.json`.

**New.** `stages.py` declares five stages, each a fresh conversation with a
narrow tool set, its own turn budget, and a named artifact it must write:

| stage | reads | writes | tools |
|---|---|---|---|
| chunk | — | `chunks.json` | 9 |
| constrain | `chunks.json` | `constraints.json` | 6 |
| analyze | chunks, constraints | `candidates.json` | 7 |
| concolic | chunks, candidates | `concolic.json` | 6 |
| prove | candidates, concolic, constraints | `findings.json` | 9 |

The tool sets are narrow deliberately. The chunker has no proof tools, so it
cannot drift into validating things; the prover has no symbolic tools, so it
cannot re-derive the claim it exists to test independently. Artifacts on disk
are the only channel between stages, which is what makes `--from analyze` work
— a stage does not care whether its input came from the previous stage, from a
subagent, or from a text editor.

The old loop's four prompt rules survive as `stages.SHARED_RULES`, with two
added: never invent an address (every one is available from a tool), and record
what you rejected and why.

## 2. The symbolic engine stopped being hardcoded

`solve_parse_config.py` (69 lines, deleted) contained three assumptions, each
of which fails on the second target:

```python
sym_fn = proj.loader.find_symbol("parse_config")     # the function, literally
targets.append(ins.address) ... find=targets[-1]      # last call == the sink
length_field = data[(INPUT_LEN-1)*8-1 : (INPUT_LEN-3)*8]   # length at bytes 1..2
```

`agent/lib/symex.py` (414 lines) replaces all three. The entry, argument layout
and sinks arrive in a chunk spec. Exploration stops at the *callee* address, so
the state lands where the calling convention's argument registers hold the real
arguments; `SINK_ABI` maps each sink to which argument is the destination and
which is the length. The bug condition is then a question about registers, not
about byte offsets in an input the analysis had to guess the format of.

Scaling controls that did not exist before: scoped CFG over the chunk's address
ranges, `LoopSeer` bounded unrolling, `LengthLimiter`, an active-state cap, and
a wall-clock deadline. A chunk that blows its budget reports
`stopped_early: budget_exhausted` rather than returning a silent negative.

## 3. Capacity became a fact instead of an assumption

The old solver asserted the destination was 32 bytes because the source says
`uint8_t name[32]`. Nothing in the analysis knew that.

`agent/lib/dwarfinfo.py` (183 lines, new) reads array extents from the DIE tree
with pyelftools. This exists because cle parses debug info but drops what
matters: `ArrayType.byte_size` is `None` and the element count lives in a
`DW_TAG_subrange_type` child DIE it does not expose.

The consequence is not cosmetic. Measured both ways on `parse_config`:

| capacity source | value | result |
|---|---|---|
| DWARF array extent | 32 | overflow found, solved at 46–47 bytes |
| distance to frame CFA | 64 | **false negative** — reports `proved_unreachable` |

The frame-distance figure is the obvious fallback and it is wrong in the
dangerous direction: every write of 33..61 bytes overflows `name[32]` while
staying inside the 64-byte frame, so the planted bug reads as absent.

## 4. Concolic execution is entirely new

There was no concolic stage before; `solve_parse_config.py`'s docstring claimed
"the Driller pattern" but implemented plain forward symbolic execution from a
blank `call_state`, with no seed, no trace and no branch negation.

`agent/lib/concolic.py` (282 lines) implements the real thing: the symbolic
buffer is preconstrained to a concrete seed, so stepping leaves the seed's
successor in `successors` and every alternative in `unsat_successors`; dropping
the preconstraints from an alternative and solving yields a replayable input.
One live state at a time. `run_generations()` re-seeds with inputs that reach
new blocks, because one generation only flips branches the seed itself reached.

Observed from a seed of 64 `0x41` bytes, no hints:

```
gen 0   flip @0x401a95  ->  c0 00 00 ...     recovers the 0xC0 magic byte
gen 1   flip @0x4155d0  ->  c0 0024 ...      CRASH, WRITE of size 36
gen 3   flip @0x401aa7  ->  c0 003d ...      CRASH, WRITE of size 61
```

Every generated input is replayed through the ASan harness inline, so a
returned crash is an observation rather than a claim.

## 5. Whole-binary facts, extracted once and cached

New: `agent/lib/binfacts.py` (349 lines). Whole-binary `CFGFast` on the twin
costs ~130 s and recovers 7219 functions; the old code never did this at all,
and could not have afforded to do it per query. Results are cached by binary
SHA-256, so every later lookup is a dict access and scoped per-chunk CFGs cost
milliseconds.

Three things it extracts that nothing in the old implementation had:

- **user code.** DWARF `functions_debug_info` separates the 12 functions that
  came from the target's sources from the 7207 that came from libc. Without it
  every ranking is dominated by `__gconv_*` noise.
- **shared globals.** Xrefs by destination give reader/writer sets per global.
  This is the relation a call graph does not contain: `rfid_isr` writes `g_len`,
  `handle_frame` reads it, and no call edge connects them. Address-taken (`lea`)
  references count as potential writes, which is what surfaces `g_frame` and
  `g_eeprom`.
- **stack layout.** Per-function locals with CFA offsets and true extents.

One defect fixed along the way: on a static glibc build every libc call goes
through an IRELATIVE PLT stub, so `memcpy` appears as `sub_401050`. Sink
detection that matches on the name found nothing — `parse_config` reported
**zero sinks** until stubs were followed through their GOT slot to
`__new_memcpy` and the glibc decoration normalized away.

## 6. Modelling interference made a whole defect class visible

New concept, no equivalent in the old implementation. A chunk may declare
`havoc_globals`; every read of a havoc'd global then returns an independent
fresh symbol.

This is what makes a double fetch visible to symbolic execution. Model `g_len`
as one symbol and `handle_frame`'s CHECK and USE read the same value, so
`n == g_len` and the defect is provably absent. Measured:

| | sinks reached | havoc reads | capacity | overflow |
|---|---|---|---|---|
| without havoc | 0 | 0 | — | — |
| with havoc on `g_len` | 1 | 2 | 16 (`local[16]`, DWARF) | yes, at 24 bytes |

Without havoc the sink is not even reached: `g_len` zero-fills and the `n == 0`
guard returns early.

Because this is the one place the pipeline could manufacture an impossible bug,
it is fenced. Havoc applies only to globals with a genuine concurrent writer,
results carry `poc_kind: "interference"` meaning *no byte string can prove
this*, and stage 5 must produce a scheduling argument instead.

## 7. Proof stopped being one-size-fits-all

The old `validate_poc` recognised exactly one thing: a sanitizer abort on a
stdin input. That is sufficient for `parse_config` and structurally incapable
of proving the other two defects.

`agent/lib/emulate.py` (166 lines) provides three proof kinds, because the
pipeline produces three kinds of claim:

| kind | proof | applies to |
|---|---|---|
| `input` | `validate_poc` — ASan abort on a byte string | `parse_config` |
| `interference` | widened-window crash **plus** an unwidened reproduction | `handle_frame` |
| `oracle` | differential against a sequential control that must read 0 | `check_credential` |

The interference proof's second half is new and matters: the old harness could
only crash with `g_widen_window` set, leaving the finding open to the objection
that it was an artifact of the test hook. The pipeline now reproduces the
`handle_frame` overflow at `widen=0` over 3×10⁶ iterations under natural
scheduling.

`run_tsan` additionally reports `harness_broken` separately, because a TSan
that cannot map shadow memory prints nothing and is otherwise indistinguishable
from a clean run.

## 8. Two drivers, one contract

**Old.** `run_agent.py` was the only way to run the agent. `toolcli.py` (41
lines) existed but exposed the same 8 tools with no notion of stages.

**New.** `pipeline.py` (261 lines) runs stages unattended against the API, and
`pipeline.py --brief <stage>` prints a self-contained brief for driving the
same stage as a Claude Code subagent through `toolcli.py --stage <name>`. Both
read `stages.py` and dispatch through `tools.call()`, so the paths cannot
drift. Credential failures now resolve to one actionable message across three
unrelated SDK exception types, including an expired OAuth refresh token
(`invalid_grant`), which previously surfaced as a 40-line traceback.

## 9. Measurement exists now

New: `scripts/experiments.py` (285 lines), six experiments, no credentials
required — they measure the analysis engines, not the model loop. Ablations
(capacity, havoc), a concolic generation curve, a seed-quality comparison, and
a technique × defect matrix. `scripts/run_all.sh` gained a concolic track
(`4b`) and its angr track now calls the generalized engine rather than the
deleted script.

---

## File map

| old | new |
|---|---|
| `agent/run_agent.py` (162) | `agent/pipeline.py` (261) + `agent/stages.py` (104) + `agent/prompts/*.md` (259) |
| `agent/solve_parse_config.py` (69) | `agent/lib/symex.py` (414) + `agent/lib/dwarfinfo.py` (183) |
| — | `agent/lib/concolic.py` (282) |
| — | `agent/lib/binfacts.py` (349) |
| `agent/tools.py` (159, 8 tools) | `agent/tools.py` (357, 18 tools) + `agent/lib/emulate.py` (166) |
| `agent/toolcli.py` (41) | `agent/toolcli.py` (76, stage-aware) |
| — | `scripts/experiments.py` (285), `scripts/baseline_{symex,concolic}.py` |

---

## Honest limits

Two things a reader should not take from the above.

**The model loop is unverified.** Every tool, both drivers and every artifact
contract run. No stage has completed a real conversation, because the mounted
OAuth profile's refresh token is expired — `pipeline.py` reaches the API and
fails cleanly. No `chunks.json` has yet been produced by an agent rather than
by hand.

**The scaling experiment is invalid** and is annotated as such in the source.
It was built to show path explosion justifying chunking, and it shows nothing:
0.7 s / 0.8 s / 0.6 s as the entry point moves from `parse_config` to
`LLVMFuzzerTestOneInput` to `main`. Path explosion does not manifest on a
~100-line target whose largest function has 10 basic blocks, and the
accompanying `overflow_found` change is an artifact of attaching a symbolic
buffer to argument 0 of functions that do not take one. The defensible scaling
number is CFG recovery cost. A real curve needs a real target —
`/usr/bin/gzip`, which the pipeline handles (625 functions, 8.6 s), has
functions of 527 and 550 basic blocks against this binary's maximum of 10.
