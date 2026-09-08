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

**10. Add a decompiler track.** Install Ghidra 11.x, then
`analyzeHeadless <proj> esc26 -import host_twin/target_plain -postScript ...`.
For the Xtensa firmware you'll need a processor module — check whether your
Ghidra version ships Xtensa before relying on it, and fall back to
`yetmorecode/ghidra-xtensa` or the esp32 community modules if not. **Verify
this in week 1**; it's the largest single unknown in the plan.

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
idf.py qemu gdb
```
This is what makes step 13 possible: breakpoints are your interleaving
control on a target where you can't use TSan.

**13. Build the interleaving driver.** Set a breakpoint at the CHECK in
`handle_frame`, and on hit, script GDB to invoke `rfid_isr_handler` with an
oversized length before continuing. That's a deterministic race trigger with
no source instrumentation — the technique to write up, since it transfers
directly to the real challenge firmware where you can't add `usleep` calls.

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

Verified by execution: the host twin builds and the TSan race, both ASan
overflows, and the angr directed solve all reproduce; the angr solution
validates as a real crash through the PoC gate; the tool layer returns
`crashed=true` for the crashing input and `false` for a benign one; the
libFuzzer and AFL++ targets both build, and libFuzzer finds BUG-002 in ~5,400
executions; every apt package and pinned Python version in `docker/Dockerfile`
resolves on Ubuntu 24.04; `docker/entrypoint.sh` passes its own preflight; the
compose file and root Makefile parse.

Not verified: no Docker daemon was available, so the images were never
actually built — the Dockerfile layers were validated by replaying them
directly on an Ubuntu 24.04 host, which catches package-name and version
errors but not layer-ordering or COPY-path errors. Also unverified: the
ESP-IDF firmware (never compiled), all of Phase C, `docker/Dockerfile.esp32`,
Ghidra Xtensa support, and `run_agent.py` (no API key).
