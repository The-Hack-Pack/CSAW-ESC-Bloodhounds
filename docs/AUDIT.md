# Phase 1 Audit — ESC 2026 testbed

Audited at commit `0d72f02` (working tree clean at audit start). Environment:
macOS 15 / Apple Silicon, Docker Desktop 29.5 (arm64 Linux VM). No `AGENTS.md`
or equivalent repo-instruction file is present; guidance lives in `README.md`.

## What this repo is

An LLM-agent firmware-analysis testbed built around a **host twin**
(`host_twin/target.c`, x86/arm buildable) that mirrors an ESP32/FreeRTOS
firmware (`firmware/main/app_main.c`). Three bugs are planted with a withheld
answer key (`ground_truth.json`) so agent runs can be scored. Symbolic/concolic
execution (angr) is the headline technique; sanitizers, fuzzing, a GDB
interleaving driver, and an LLM loop are supporting components. This matches
the team's stated research direction (symbolic execution central, emulation
supporting).

## Architecture map

| Component | Files | Role |
|---|---|---|
| Host twin | `host_twin/target.c`, `.h`, `main.c`, `fuzz_entry.c`, `Makefile` | The code under test + drivers |
| ESP32 firmware | `firmware/main/app_main.c`, `CMakeLists.txt`, `sdkconfig` | Fidelity mirror on real Xtensa |
| Sanitizer tracks | `target_tsan` (TSan), `target_asan` (ASan) | Race + memory-safety detection |
| Fuzzing tracks | `fuzz_entry.c` → `fuzz_stdin`/`fuzz_libfuzzer`/`fuzz_afl` | libFuzzer / AFL++ baselines |
| angr script | `agent/solve_parse_config.py` | Directed symbolic solve for BUG-002 |
| GDB/QEMU interleaving | `firmware/interleave.gdb` | Deterministic BUG-001 witness on Xtensa |
| Agent/tool interface | `agent/tools.py`, `toolcli.py`, `run_agent.py` | ReAct loop + tool contract |
| Findings schema | `agent/findings.json`, `findings-run2.json` | Agent output |
| PoC validator | `tools.validate_poc` (+ new `agent/oracles.py`) | The gate |
| Scorer | `scripts/score.py` | Grade findings vs. answer key |
| Blinding | `scripts/blind.py` | Strip comments + hide key for honest runs |
| Baseline sweep | `scripts/run_all.sh` | Five-track "does the harness fire" check |
| Container | `docker/Dockerfile*`, `docker-compose.yml`, `entrypoint.sh` | Pinned environment + preflight |

**Planted bugs.** BUG-001: TOCTOU on `g_len` between the RFID ISR and
`handle_frame` → stack overflow (hard). BUG-002: trusted 16-bit length field in
`parse_config` → stack overflow, fuzzer/angr-reachable (easy). BUG-003: TOCTOU
on the I2C EEPROM credential store in `check_credential` → privilege
escalation, non-crash (medium). Decoys: `rfid_isr` clamp, `eeprom_write` bound
check, `g_widen_window` hook.

## Status of each component

**Implemented and verified (reproduced this audit, in-container):**
- Host-twin build; TSan race on `g_len`; ASan overflow in `handle_frame`
  (BUG-001) and `parse_config` (BUG-002); credential-race escalation pair
  (BUG-003) with a clean sequential control.
- Container image build + preflight; sanitizer shadow mapping worked on the
  arm64 VM without a `vm.mmap_rnd_bits` change (it is still needed on x86).
- Scorer runs and grades; blinding round-trips (by inspection of the script).

**Implemented but was silently broken on this host (now fixed):**
- angr track (`solve_parse_config.py`) — matched only the x86 `call` mnemonic,
  so on arm64 (`bl`) it found no call site and printed nothing. Repaired to be
  ISA-agnostic; now recovers `0xC0` + an over-32 length field.

**Implemented, unverified here (needs resources not on this host):**
- ESP32 firmware build + QEMU boot + `interleave.gdb` (README reports these
  verified on x86; not re-run — no ESP-IDF image pulled this session).
- libFuzzer/AFL++ time-to-crash numbers (not re-measured this session).
- `run_agent.py` live loop (needs `ANTHROPIC_API_KEY`; loop was exercised
  previously via Claude Code subagents, per README).

**Gap identified and closed (Priority A):**
- The gate recognised only crashes. BUG-003's escalation had no gate path;
  findings were graded on a self-asserted `"validated": true`. Addressed by
  `agent/oracles.py` (typed evidence) + scorer gate re-verification. See
  `docs/VALIDATION.md`.

**Claimed only in documentation / still open:**
- Hardware confirmation (step 14) — needs the kit.
- `parse_config` is dead-code-eliminated from the firmware ELF (README notes
  this); anything reasoning about the ELF will not see BUG-002 there.

## Trust-but-verify notes

- A green `run_all.sh` is not proof by itself: the script and preflight both
  guard against the "sanitizer failed to map shadow memory → silent no-op"
  mode, and against pipe-swallowed exit codes. Those guards are real and were
  observed firing in the code paths.
- `run_agent.py` writes the model's final text block straight to
  `findings.json`; the scorer expects JSON with a `findings` key. A malformed
  final message would produce an unscorable file. Low priority, but worth a
  guard later.
