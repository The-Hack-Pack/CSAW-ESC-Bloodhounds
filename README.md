# ESC 2026 test environment — numbered setup

A working testbed for an LLM-agent firmware analysis system, built around a
target with **deliberately planted bugs** so you have ground truth to score
against. The challenge binaries aren't released until the final phase, so
your own target is the only way to measure anything before then.

The central trick: keep **two builds of the same logic**.

| | build | what works there |
|---|---|---|
| **host twin** | `gcc` on x86-64 | TSan, ASan, AFL++, angr, fast iteration |
| **firmware** | ESP-IDF on Xtensa | real dual-core + ISR context, fidelity check |

You develop against the twin because angr has no Xtensa lifter and TSan has no
bare-metal port. You confirm on the firmware. Don't skip the second half — a
finding that only exists in the twin isn't a finding.

---

## Phase 0 — containerize first (recommended)

Skip to Phase A if you want to run natively. But sanitizer behavior and race
timing are exactly the things that differ between machines, so pinning the
environment is worth the twenty minutes.

**0a. Apply the host sysctls.**
```bash
sudo bash docker/host-setup.sh
```
Two settings the container *cannot* set for itself. `vm.mmap_rnd_bits` defaults
to 32 on kernel 6.5+, which collides with the ASan/TSan shadow mapping — the
sanitizers abort at startup. `kernel.core_pattern` must be `core` or afl-fuzz
refuses to run. On Docker Desktop these belong to the Linux VM, not your
laptop; the script explains how to get a shell there.

**0b. Build and verify.**
```bash
make build
make verify
```
`make verify` runs the four-track sweep inside the container. The image's
entrypoint runs a preflight first and **fails loudly** if the sanitizers can't
map shadow memory — the failure mode otherwise is a container that silently
reports "no bugs found", which is indistinguishable from a working run.

**0c. Note two settings in `docker-compose.yml` that are not optional.**
`security_opt: seccomp=unconfined` (sanitizers call `personality()` to disable
ASLR and the default profile blocks it) and `cpus: "4"` (race reproducibility
depends on core count — an unpinned container makes your time-to-crash numbers
incomparable across machines).

`make help` lists the rest: `shell`, `fuzz-libfuzzer`, `fuzz-afl`, `symbolic`,
`agent`, `esp32-build`, `esp32-qemu`.

---

## Phase A — host twin (works today, no hardware, no ESP-IDF)

**1. Install the basics** (skip if you did Phase 0).
```bash
sudo apt install -y build-essential gcc make python3 python3-pip
```
GCC 13 ships both ThreadSanitizer and AddressSanitizer; no clang needed yet.

**2. Get the scaffold and build it.**
```bash
cd esc26-testbed/host_twin && make
```
Produces `target_tsan`, `target_asan`, `target_plain`, `fuzz_stdin`.

**3. Confirm all six detection tracks fire.**
```bash
./scripts/run_all.sh
```
You should see: a TSan data race on `g_len`, an ASan stack-buffer-overflow in
`handle_frame`, an overflow in `parse_config`, angr solving symbolically for an
oversized length field, angr *concolically* recovering the magic byte from a
garbage seed and producing a replayed crash, and the credential-store
escalation against a clean sequential control. If any track is silent, fix that
before adding an agent — you'd be measuring your harness, not your agent.

**4. Read the answer key, then set it aside.**
`ground_truth.json` lists three planted bugs and three decoys. The agent must
never see this file; `scripts/run_all.sh` and your scorer use it.

**5. Understand why BUG-001 needs its own machinery.**
`handle_frame` validates `g_len` into `n`, then passes `g_len` — not `n` — to
`memcpy`. The RFID ISR grows it inside that window. No amount of sequential
fuzzing finds this. That gap between "fuzzer finds it" and "doesn't" is the
whole argument for your multi-tool toolkit, and it's what you should measure
and report.

**6. Note the test hook.** `g_widen_window` inserts sleeps at the race window
so a PoC reproduces on demand. It exists so you can prove the bug is reachable
*before* asking an agent to find it. A real system replaces it with a
scheduler that fires the ISR at chosen program points — the Razzer approach.

---

## Phase B — analysis tooling

**7. Symbolic execution over a chunk.**
```bash
make facts                      # whole-binary CFG, ~130s, cached by SHA-256
make symbolic
```
`agent/lib/symex.py` takes a *chunk spec* — an entry, an argument layout, and
sinks — and explores to the sinks. Nothing is hardcoded to `parse_config`: the
destination and length are read from the argument registers **at the call
site**, and the destination's capacity comes from the DWARF extent of the stack
local it resolves to (`dwarf_local:name:uint8_t[][32]`), not from a guess.

Expect `dest_capacity=32`, `length_max=61`, `overflow=true`, and a solved input
beginning `c0003d`. Worth noting for the report: with an 8-byte buffer it
returns `proved_unreachable` instead — the source-length check ties `nlen` to
input size, so `nlen > 32` is UNSAT. That negative is a *proof*, and it is
something fuzzing cannot give you.

The capacity derivation is the part to get right. Using the distance from the
buffer to the frame's CFA — the obvious fallback — reports 64 bytes for
`parse_config`, which makes every overflow of 33..61 bytes look in-bounds and
hides the planted bug completely. `agent/lib/dwarfinfo.py` exists because cle
drops the array subrange count that makes 32 the right answer.

**8. Concolic execution from a seed.**
```bash
make concolic
```
`agent/lib/concolic.py` is the other half, and it is a genuinely different
technique — see *Symbolic vs concolic* below. Seeded with 64 bytes of `0x41`
and no hints, generation 0 recovers the `0xC0` magic by negating a branch,
generation 1 reaches the `memcpy`, and the inputs it generates are replayed
through the ASan harness automatically. Expect confirmed crashes at `nlen=36`
and `nlen=61`, each carrying the sanitizer report that names
`parse_config target.c:70` and `[32, 64) 'name'`.

**8b. The gate.** Every symbolic or concolic result must become a concrete,
replayable crash through `validate_poc`. This is the single most important
property of the system, and it is why the concolic stage replays inline and the
proof stage replays again independently.

**9. Add a real fuzzer.**
```bash
sudo apt install -y clang && make -C host_twin fuzz_libfuzzer
./host_twin/fuzz_libfuzzer -max_total_time=60 corpus/
```
Or AFL++ (`apt install afl++`, then `make -C host_twin fuzz_afl`). Record
time-to-first-crash for BUG-002 — that's your baseline number for showing what
the LLM adds.

**10. Add a decompiler track.** Install Ghidra 11.3 or newer, then
`analyzeHeadless <proj> esc26 -import host_twin/target_plain -postScript ...`.
Xtensa is **shipped in the box** from 11.3 onward, so no
`yetmorecode/ghidra-xtensa` module and no community esp32 module is required.
Verified end to end against the real firmware — `agent/ghidra/CountFuncs.java`
is a working post-script that prints the detected language and resolves the
planted-bug symbols:
```bash
analyzeHeadless /tmp/proj esc26 -import firmware/build/esc26_testbed.elf \
  -scriptPath agent/ghidra -postScript CountFuncs.java
# Using Language/Compiler: Xtensa:LE:32:default:default
# FUNCTIONS_FOUND=956   SYM handle_frame=400d60c0
```
Note the ELF lives in the `esp32-build` volume, not the bind mount. This used
to be flagged as the plan's largest unknown; it is settled.

---

## Phase C — ESP32 firmware build

**11. Install ESP-IDF and its QEMU.**
```bash
docker run -it --rm -v $PWD:/work espressif/idf:v5.3
# inside:
cd /work/firmware && idf.py set-target esp32 && idf.py build
python $IDF_PATH/tools/idf_tools.py install qemu-xtensa
idf.py qemu monitor
```
Espressif ships a QEMU fork with an `esp32` machine including eFuses, secure
boot and flash encryption. `firmware/main/app_main.c` is written against the
IDF v5.x API but **was not compiled** when this scaffold was generated —
expect to fix includes.

**12. Attach a debugger.**
```bash
idf.py qemu --gdb                                    # waits on :3333
xtensa-esp32-elf-gdb build/esc26_testbed.elf         # not xtensa-esp-elf-gdb
```
This is what makes step 13 possible: breakpoints are your interleaving
control on a target where you can't use TSan. Two things the docs get wrong
for IDF v5.3: the stub listens on **3333**, not qemu's usual 1234, and the
unversioned `xtensa-esp-elf-gdb` does not exist — the binary is
`xtensa-esp32-elf-gdb`.

**13. Build the interleaving driver.** Done — `firmware/interleave.gdb`:
```bash
xtensa-esp32-elf-gdb -batch -x interleave.gdb build/esc26_testbed.elf
```
It primes `g_len` with a legal 8-byte frame so the consumer passes its own
CHECK, breaks between the CHECK and the USE, fires `rfid_isr_handler(64)`
inside that window, and dumps the stack either side of the `memcpy`. The
0x41 run past offset 16 is the overflow. Deterministic, and no source
instrumentation — which is why it transfers to the real challenge firmware
where you can't add `usleep` calls.

**14. Confirm on hardware once you have the kit.** Flash the same firmware,
drive the MFRC522 IRQ line, and check the crash reproduces. For anything you
can't emulate faithfully (the RFID front end, the I2C EEPROM), run the CPU in
QEMU and forward peripheral accesses to the board — the Avatar² pattern.

---

## Phase D — agent layer

**15. Wire up the toolkit.**
```bash
python3 agent/toolcli.py                      # every tool
python3 agent/toolcli.py --stage chunk        # one stage's tools
python3 agent/toolcli.py function_info '{"name": "parse_config"}'
```
`agent/tools.py` is the contract, and `toolcli.py` and `pipeline.py` both
dispatch through `tools.call()` — there is no second code path. The design rule
is unchanged: **tools return evidence, never verdicts.** `validate_poc` is the
only thing that can promote a hypothesis to a finding.

**16. Run the pipeline.**
```bash
make pipeline                    # all five stages
make stage STAGE=constrain       # just one
make brief STAGE=concolic        # the brief, for driving a stage by hand
```
Five stages, each a fresh conversation with a narrow tool set, artifacts on
disk as the only channel between them — see *The pipeline* below. Resist the
urge to make it clever before it is reliable.

**17. Score it.** Compare `agent/artifacts/findings.json` against
`ground_truth.json`:
- bugs found / 3, weighted by difficulty
- false positives (did it report a decoy?)
- turns and tokens per bug found
- did every reported bug carry a validated PoC?

**18. Establish the baselines you'll be compared against.** Run each tool
*without* the agent and record what it finds alone. Your contribution is the
delta. In AIxCC, parallel fuzzing alone solved 54% of the bugs — if you don't
measure your own equivalent, a judge will reasonably ask whether the LLM did
anything.

---

## The pipeline

Five stages, each a fresh conversation with a narrow tool set. Artifacts on
disk are the only channel between them, which is what makes any stage
independently re-runnable — `--from analyze` does not care whether
`constraints.json` came from stage 2, from a subagent, or from your text editor.

| stage | agent | reads | writes | owns |
|---|---|---|---|---|
| 1 | **Chunker** | — | `chunks.json` | what to analyse, and why those functions belong together |
| 2 | **Constraint** | `chunks.json` | `constraints.json` | symbolic execution to the sinks; SAT/UNSAT per sink |
| 3 | **Analyzer** | 1, 2 | `candidates.json` | defect class, CWE, and what would prove it |
| 4 | **Concolic** | 1, 3 | `concolic.json` | seed-driven dynamic testing; replayed crashes |
| 5 | **Proof** | 3, 4, 2 | `findings.json` | what the pipeline is willing to claim |

The tool sets are narrow on purpose. The chunker has no proof tools, so it
cannot wander off validating things; the prover has no symbolic tools, so it
cannot re-derive the claim it is supposed to be testing independently.

**Two drivers, one contract.** `pipeline.py` runs the stages unattended against
the Anthropic API inside the container. `pipeline.py --brief <stage>` prints a
self-contained brief for driving the same stage as a Claude Code subagent,
executing tools through `toolcli.py`. Both read `stages.py` and dispatch
through `tools.call()`, so the two paths cannot drift.

### Why chunking is not optional

Whole-binary `CFGFast` on `host_twin/target_plain` takes **129 seconds and
recovers 7219 functions**, twelve of which are yours. That cost is paid once:
`agent/lib/binfacts.py` caches the facts by binary SHA-256, and every later
query is a dict lookup. A scoped CFG over one chunk's address range costs
milliseconds, and a chunk solves in **0.7 seconds**.

Three things the chunker gets that are not available any other way:

- **user code** — DWARF `functions_debug_info` separates your 12 functions from
  libc's 7207. Without it every ranking is dominated by `__gconv_*` noise.
- **shared globals** — xrefs by destination give reader/writer sets per global.
  This is the edge the call graph does not have: `rfid_isr` *writes* `g_len`,
  `handle_frame` *reads* it, and **no call edge connects them**. Grouping by
  call structure alone would never put them in the same chunk, and that pair is
  where the concurrency defect lives. Address-taken (`lea`) counts as a
  potential write, which is what surfaces `g_frame` and `g_eeprom`.
- **stack layout** — exact array extents, so a destination's capacity is a fact.

On a static glibc build every libc call goes through an IRELATIVE PLT stub, so
`memcpy` appears as `sub_401050`; `binfacts.py` follows the stub through its GOT
slot to `__new_memcpy` and normalizes the glibc decoration away. Before that,
`parse_config` reported **zero sinks**.

### Symbolic vs concolic

Both stages run angr; they are not the same technique, and the pipeline uses
each for what it is good at.

**Stage 2 (symbolic)** interprets over formulas. Inputs are symbols, every
symbolic branch forks, and an SMT solver prunes infeasible paths. Scaling
controls: a scoped CFG, `LoopSeer` bounded unrolling, `LengthLimiter`, an
active-state cap, a wall-clock deadline, and `find=` the callee address so
exploration stops **at** the sink and never inside it. It is the only stage that
can prove a *negative* — `proved_unreachable` means UNSAT, no input in this
domain reaches the bug.

**Stage 4 (concolic)** runs a concrete seed, follows the one path it takes, and
negates its branch conditions to generate new seeds. The symbolic buffer is
preconstrained to the seed, so each step leaves the seed's successor in
`successors` and every alternative in `unsat_successors`; dropping the
preconstraints and solving an alternative yields a real, replayable input. One
live state at a time, and every output is an actual execution rather than a
model state that may not correspond to one.

Observed on `parse_config`, from a seed of 64 `0x41` bytes with no hints:

```
gen 0  flip @0x401a95  ->  c0 00 00 ...      recovers the magic byte
gen 1  flip @0x4155d0  ->  c0 0024 ...       CRASH: WRITE of size 36
gen 3  flip @0x401aa7  ->  c0 003d ...       CRASH: WRITE of size 61
                                             [32, 64) 'name' overflows
```

23 blocks, 15 inputs, 5 confirmed crashes, 7.7 seconds. Note where two of the
flips land: *inside* `__memcpy_avx_unaligned_erms`, on its length dispatch.
Concolic steps into the sink where symbolic deliberately stops at it, and here
that is what produced the crash.

### Finding a double-fetch symbolically

`handle_frame` validates `g_len` into `n` and then passes `g_len` — not `n` — to
`memcpy`. Model `g_len` as a single symbol and there is provably no bug: the
CHECK and the USE read the same value, so `n == g_len`. The defect exists only
because the RFID ISR can change it between the two reads.

So a chunk may name `havoc_globals`, and every read of a havoc'd global returns
an independent fresh symbol. On `handle_frame` that yields `havoc_reads: 2` —
the two fetches — `dest_capacity: 16` (`local[16]`, from DWARF), an unbounded
length, and a satisfiable overflow at 24 bytes. Without havoc the sink is not
even reached, because `g_len` zero-fills and the `n == 0` guard returns early.

This is the one place the pipeline can manufacture a bug that cannot happen, so
it is fenced: havoc only applies to globals with a genuine concurrent writer,
results carry `poc_kind: "interference"` to say **no byte string can prove
this**, and stage 5 must produce a scheduling argument instead — a widened-window
ASan crash plus an attempt to reproduce it with the window closed.

---

## Phase E — extend

**19. Make the bugs harder.** The current three are a smoke test. Add a
priority-inversion deadlock, a DMA race, an EEPROM replay, and something that
needs multi-function reasoning to see. Bugs a single `read_source` call solves
don't demonstrate much.

**20. Then add the ambitious parts** — MCP tool exposure, parallel analysis
workers with a shared seed bus, an LLM seeding the fuzzer's corpus, ensemble
voting across models. Each of these should be justified by a number from step
17, not by being interesting.

---

## What was verified vs. not

*Updated 2026-09-08, after the environment was built and exercised on
Ubuntu 22.04 / Docker 29.8 / 20 cores. Seven defects found and fixed; see
the per-file notes in `docker/` for the reasoning behind each.*

Verified by execution, in the container: both images build; all six tracks of
`scripts/run_all.sh` fire (TSan race on `g_len`, ASan overflow in
`handle_frame`, ASan overflow in `parse_config`, symbolic execution deriving
`dest_capacity=32` from DWARF and solving the length field, concolic execution
recovering the `0xC0` magic from a garbage seed and producing replayed crashes
at `nlen=36` and `nlen=61`, and the credential escalation against a clean
sequential control); the PoC gate returns `crashed=true` for a crashing input
and `false` for a benign one; libFuzzer finds BUG-002 in ~19k executions and
AFL++ in ~20k, and both crash artifacts replay through `validate_poc` and
attribute to `parse_config:70`.

Verified for the pipeline (2026-09-11): whole-binary fact extraction (129s,
7219 functions, 12 identified as user code via DWARF, IFUNC stubs resolved
through the GOT); `symex_chunk` solving `parse_config` in 0.7s and returning
`proved_unreachable` for an 8-byte buffer; `symex_chunk` with
`havoc_globals:["g_len"]` reaching `handle_frame`'s memcpy with
`havoc_reads: 2` and a satisfiable 24-byte overflow against a DWARF capacity of
16; `concolic_chunk` producing 5 distinct ASan-confirmed crashes in 7.7s from a
seed of 64 `0x41` bytes; all 18 tools dispatching through `tools.call()`; both
drivers (`pipeline.py --list/--brief`, `toolcli.py --stage`) operating without
credentials.

Verified for Phase C: `docker/Dockerfile.esp32` builds (7.5 GB); the firmware
compiles clean on the first attempt — no include fixes were needed, contrary
to the warning this file used to carry; it boots under QEMU as a multicore app
and logs `esc26 testbed up`; and `firmware/interleave.gdb` reproduces BUG-001
on Xtensa through the gdbstub with **no source instrumentation** — 0x41 fills
32 bytes of a 16-byte buffer — which is the step-13 technique working as
designed.

Ghidra ships an Xtensa processor module natively as of 11.3, so the
`yetmorecode/ghidra-xtensa` fallback is not needed. Confirmed by running it,
not just by checking the module list: Ghidra 12.1.3 auto-detects the firmware
ELF as `Xtensa:LE:32:default`, analysis succeeds, and it recovers 956
functions with `handle_frame` at `400d60c0` and `rfid_isr_handler` at
`40082a10` — byte-identical to `xtensa-esp-elf-nm`. `agent/ghidra/CountFuncs.java`
is the post-script used. This was the plan's largest single unknown and it
resolves favorably.

**The agent layer was measured end to end (2026-09-08), substituting Claude
Code subagents for the API driver because a Claude.ai subscription does not
carry API access.** Those runs predate the five-stage pipeline and used the
single-loop agent; the scores below are the baseline the staged pipeline has to
beat, not a measurement of it. Two blinded runs, using `scripts/blind.py` to strip every
comment and stash this file plus the answer key. Run 1 scored 4/6 weighted --
the ceiling at the time, because BUG-003 was unprovable (below). Run 2, after
BUG-003 was given a concurrent writer, scored **6/6 weighted, 0 false
positives, 9 tool calls against a 25 budget**, with all three planted bugs
carrying validated proofs and all three decoys correctly rejected. Score any
run with `python3 scripts/score.py agent/findings.json`.

**BUG-003 was unreachable by every dynamic technique until 2026-09-08.**
Nothing in the harness or the firmware wrote `g_eeprom` while
`check_credential` sat between its check and its use, so `reachable_by:
["tsan", "interleaving_fuzz"]` in the answer key was aspirational, and the
answer key carried no `poc` for it at all. Worse, its impact is privilege
escalation rather than a crash, so `validate_poc` -- which only recognises a
sanitizer abort -- could never prove it. Any agent obeying the
no-unvalidated-findings rule was capped at 4/6. `run_cred_race()` now supplies
the concurrent writer, and the oracle is a **pair**: a sequential control that
must return 0 escalations in 500 checks, against a concurrent run that grants
admin for a record whose stored role is `0x00`. The concurrent count alone
proves nothing; it is the pair that isolates concurrency as the cause. Still
open: `validate_poc` has no oracle mode, so the toolkit now has two classes of
proof and only one gate enforces either.

**`g_widen_window` is not required for BUG-001.** `./host_twin/target_asan
race 3000000 0` crashes in `handle_frame` with the hook off -- verified 3/3.
The window is real, just narrow; the hook buys speed and determinism, not
reachability. Step 6 below overstates its role.

**`vm.mmap_rnd_bits=28` is required, not optional.** Without it TSan fails to
map shadow memory in roughly 2 runs out of 3 — measured at 28/30 for
`target_tsan` on a stock 6.8 kernel. It is intermittent, so a couple of clean
runs prove nothing; the whole four-track sweep can look healthy on one
invocation and report "no race" on the next. Run `sudo bash
docker/host-setup.sh` (or just `sudo sysctl -w vm.mmap_rnd_bits=28`) before
trusting the TSan track. The preflight now tests this by actually running TSan
six times and refuses to start otherwise; `ESC26_SKIP_TSAN_CHECK=1` downgrades
it to a warning if you only need the ASan/angr/fuzzing tracks.

Four corrections worth carrying forward:

- **The gdbstub is on :3333, not :1234.** ESP-IDF v5.3 launches qemu with
  `-gdb tcp::3333`. The compose port publish and the Makefile help text both
  said 1234 and were wrong.
- **Never build the host twin on the host.** Host and container write the same
  bind-mounted `host_twin/`, but link different sanitizer runtimes
  (`libasan.so.6` vs `.so.8`). Whichever built last wins and `make` then skips
  the rebuild. `scripts/run_all.sh` now fails loudly on this instead of
  reporting "no crash".
- **`kernel.core_pattern=core` litters the repo.** Once that sysctl is set,
  every ASan abort dumps a core into the bind-mounted working directory --
  728 KB of `core.*` and `crash-*` accumulated across one session. Both are
  now in `.dockerignore`.
- **Never test a sanitizer through a pipe.** `prog 2>&1 | grep -q ...` under
  `set -o pipefail` reports the *sanitizer's* nonzero exit, not grep's match,
  so a detected failure reads as "no failure". This bit both
  `scripts/run_all.sh` and `docker/entrypoint.sh`; both now capture output to
  a variable and match with `case`.
- **`parse_config` is eliminated from the firmware build.** It is called under
  `if (n)` with `n` hard-coded to 0, so dead-code removal drops it. Anything
  reasoning about the ELF (Ghidra, symbol-based tooling) will not find it —
  give `net_task` a real input path before relying on that.

Still not verified: hardware (step 14, needs the kit), and the five stages'
model loop end to end, which needs working credentials — `pipeline.py` reaches
the API and fails cleanly on an expired OAuth refresh token, but no stage has
yet completed a real conversation, so no `chunks.json` has been produced by an
agent rather than by hand. Everything below the model loop — all 18 tools, both
drivers, every artifact contract — runs. Everything in Phases 0, A, B, and C
now runs.
