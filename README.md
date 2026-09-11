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

**3. Confirm all four detection tracks fire.**
```bash
./scripts/run_all.sh
```
You should see: a TSan data race on `g_len`, an ASan stack-buffer-overflow in
`handle_frame`, an overflow in `parse_config`, and angr solving for an
oversized length field. If any track is silent, fix that before adding an
agent — you'd be measuring your harness, not your agent.

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

**7. Install angr.**
```bash
pip install --break-system-packages angr
python3 agent/solve_parse_config.py host_twin/target_plain 64
```
Expect it to recover the `0xC0` magic byte on its own and then, once you
constrain the length field above the 32-byte destination, hand you a crashing
input. Worth noting for the report: with an 8-byte input angr correctly proves
the bug *unreachable* — the source-length check ties `nlen` to input size. That
kind of negative result is something fuzzing can't give you.

**8. Close the loop.** Feed angr's solution back through `validate_poc`. Every
symbolic result must become a concrete, replayable crash. This is the PoC gate
and it's the single most important property of the system.

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
`scripts/esp32_interleave.sh` runs this non-interactively (boots qemu with the
gdbstub, waits for :3333, drives the script, tears qemu down):
```bash
docker compose -f docker/docker-compose.yml run --rm -T esp32 \
    bash /work/scripts/esp32_interleave.sh
```
Re-verified on arm64 this session (2026-09-11): firmware builds clean, boots
under qemu as a multicore app logging `esc26 testbed up`, and the driver fills
the 16-byte `local[]` with `0x41` past its bound after firing
`rfid_isr_handler(64)` inside the window — BUG-001 on Xtensa, no source
instrumentation.

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
pip install anthropic
export ANTHROPIC_API_KEY=...
python3 agent/tools.py     # smoke test: should print a TSan race report
```
`agent/tools.py` is the contract. Note the design rule: **tools return
evidence, never verdicts.** `validate_poc` is the only thing that can promote
a hypothesis to a finding.

**16. Run the loop.**
```bash
cd agent && python3 run_agent.py --budget 25
```
~100 lines of ReAct. Resist the urge to make it clever before it's reliable.

**17. Score it.** Compare `findings.json` against `ground_truth.json`:
- bugs found / 3, weighted by difficulty
- false positives (did it report a decoy?)
- turns and tokens per bug found
- did every reported bug carry a validated PoC?

**18. Establish the baselines you'll be compared against.** Run each tool
*without* the agent and record what it finds alone. Your contribution is the
delta. In AIxCC, parallel fuzzing alone solved 54% of the bugs — if you don't
measure your own equivalent, a judge will reasonably ask whether the LLM did
anything.

`scripts/baselines.sh` does this and writes a machine-readable
`agent/baselines.json`:
```bash
docker compose -f docker/docker-compose.yml run --rm -T analysis \
    bash scripts/baselines.sh agent/baselines.json
```
Measured (see `docs/EVIDENCE.md` for the full matrix): libFuzzer finds BUG-002
in ~15k executions; it never reaches BUG-001 (the stdin harness has no path to
`handle_frame`) and gets 0 escalations on BUG-003 in 20k sequential checks
(the escalation needs the concurrent writer); angr recovers the `0xC0` guard in
one directed solve; the typed gate reproduces all three. No single tool covers
all three — that gap is the argument for the toolkit.

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

Verified by execution, in the container: both images build; all four tracks of
`scripts/run_all.sh` fire (TSan race on `g_len`, ASan overflow in
`handle_frame`, ASan overflow in `parse_config`, angr recovering the `0xC0`
magic and solving the length field); the PoC gate returns `crashed=true` for a
crashing input and `false` for a benign one; libFuzzer finds BUG-002 in ~19k
executions and AFL++ in ~20k, and both crash artifacts replay through
`validate_poc` and attribute to `parse_config:70`; `run_agent.py` exits
cleanly when `ANTHROPIC_API_KEY` is unset, and the SDK accepts every parameter
it sends.

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
Code subagents for `run_agent.py` because a Claude.ai subscription does not
carry API access.** Two blinded runs, using `scripts/blind.py` to strip every
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
proves nothing; it is the pair that isolates concurrency as the cause.

**RESOLVED 2026-09-11 — the gate now has an oracle mode.** `agent/oracles.py`
is a typed-evidence validation engine: a finding declares evidence of type
`crash`, `race_report`, `security_oracle`, `trace_assertion`, or
`differential_oracle`, and the engine re-runs it for a machine-readable
verdict (`passed`, `reproduction_rate`, stored `artifacts`). BUG-003 is now a
first-class `differential_oracle` (`bug003_credential_toctou`): it passes only
when the sequential control is secure on every trial **and** the concurrent
test reproduces the escalation — so a control that is already insecure is a
hard FAIL, not a pass. `scripts/score.py` re-runs each finding's oracle at
score time, so a bug is credited on a witness the gate re-checks rather than a
self-asserted `"validated": true`. With this, all three planted bugs are
gate-provable and the 4/6 cap is gone (6/6 on run 2). The engine is wired into
the toolkit as `validate_evidence` and `run_oracle`, and `agent/test_oracles.py`
proves the gate *rejects* non-proofs (benign input, wrong crash site, an
already-insecure control, a non-reproducing test). `validate_poc` is unchanged
and remains the crash-only fast path.

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

One portability fix carried in since (2026-09-11, verified on Apple-Silicon /
Docker Desktop arm64): `agent/solve_parse_config.py` matched only the x86
`call` mnemonic to find the `memcpy` call site, so on an aarch64 host — where
the same static binary emits `bl` — the angr track found no call site and
printed nothing (baseline track 4 silently blank). It now matches `call`/`bl`/
`blr`/`jal`/`jalr` and recovers the `0xC0` magic plus an over-32 length field
on both arches. Everything in the four-track sweep now reproduces on
`ubuntu:24.04` under an arm64 Docker VM, including the TSan race (shadow
mapping succeeded without a `vm.mmap_rnd_bits` change on this kernel; keep the
sysctl step for x86 hosts, where it is still intermittent).

Still not verified: hardware (step 14, needs the kit), and `run_agent.py`'s
actual agent loop and scoring, which need an `ANTHROPIC_API_KEY`. Everything
else in Phases 0, A, B, and C now runs.
