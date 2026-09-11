# Experimental evidence — individual-tool baselines

Prototype evidence for the qualification report: what each technique finds
**alone**, measured in the pinned container (`ubuntu:24.04`, GCC 13 / Clang 18,
arm64 Docker VM). Reproduce with:

```bash
docker compose -f docker/docker-compose.yml run --rm -T analysis \
    bash scripts/baselines.sh agent/baselines.json
```

Machine-readable results land in `agent/baselines.json`. Numbers below are from
a 45 s/run budget; the exec count varies run to run, the reachability facts do
not.

## Bug × tool matrix

| Bug (difficulty) | Sequential fuzzing (libFuzzer) | angr (directed) | TSan | ASan + widened window | Differential oracle |
|---|---|---|---|---|---|
| **BUG-002** parse_config (easy) | **FOUND**, ~14.9k units to first crash, attributed to `parse_config` | recovers `0xC0` magic + over-32 length in one solve | — | — | crash gate: PASS |
| **BUG-001** handle_frame (hard) | **unreachable by construction** (harness never calls `handle_frame`/`run_race`); 0 crashes in 45 s | n/a on host twin | data race on `g_len` reported | ASan stack-overflow in `handle_frame` | crash gate: PASS (repro 1.00) |
| **BUG-003** check_credential (medium) | code reached, but **0 escalations in 20,000 sequential checks** | — | data race reported | — | **FOUND**: 5/5 test-insecure vs 0/5 control, repro 1.00 |

## What the numbers say

1. **Sequential fuzzing solves exactly the sequential bug.** libFuzzer finds
   BUG-002 on its own (~15k executions past the `0xC0` guard). This is the
   baseline the agent must beat, not match.

2. **The concurrency bugs are out of a lone fuzzer's reach.** BUG-001 is
   *structurally* unreachable from the stdin harness — no schedule of inputs
   drives the ISR/consumer race. BUG-003's code *is* reached, yet a single
   thread can never make a role-`0x00` record read back as admin: the
   escalation needs the concurrent EEPROM writer. Both are reachability facts,
   not budget artifacts — more fuzzing time changes neither.

3. **angr converts a probabilistic guard into a deterministic one.** The
   `0xC0` magic costs a blind fuzzer ~2^8 tries; a directed solve recovers it
   plus an overflowing length field in a single query. This is the
   symbolic-execution contribution the report centres on.

4. **The concurrency bugs belong to the interleaving + differential-oracle
   tracks.** TSan flags the `g_len` race; the widened-window ASan run turns
   BUG-001 into a deterministic crash; the differential oracle proves BUG-003's
   escalation with a secure control. None of these is a fuzzer.

**Takeaway for the paper:** no single tool covers all three planted bugs. A
fuzzer gets the easy one; symbolic execution cracks the guard; concurrency
proof needs interleaving control and a differential oracle. That coverage gap
is the argument for orchestrating a toolkit — and the yardstick the
LLM-orchestrated workflow's contribution (its delta over the best single tool)
must be measured against.

## Caveats (kept honest)

- These are *host-twin* measurements. BUG-001's Xtensa confirmation is the
  `interleave.gdb` witness (README step 13); hardware confirmation still needs
  the kit.
- "Unreachable by construction" is a property of the current fuzz harness. If
  `net_task`/`fuzz_entry` were given a path into `handle_frame`, the statement
  would need re-checking — the script re-derives it from the source each run.
- The agent-vs-baseline *delta* (README step 18's headline number) still needs
  a live `run_agent.py` run, which requires `ANTHROPIC_API_KEY`. The blinded
  subagent runs recorded in `agent/findings-run2.json` (6/6, 9 tool calls)
  stand in for it until then.
