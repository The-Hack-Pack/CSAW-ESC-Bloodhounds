# Typed-evidence validation gate

`agent/oracles.py` generalizes the PoC gate so that non-crash security
findings are proven by a reproducible witness, not asserted. It exists because
the original gate (`tools.validate_poc`) recognised exactly one class of proof
— a sanitizer abort from a stdin input — and BUG-003's impact is privilege
escalation under concurrency, which never crashes.

## Evidence types

A finding declares one evidence spec (a dict with a `type`). `oracles.validate`
dispatches and returns a uniform verdict.

| Type | Proves | Key fields |
|---|---|---|
| `crash` | a memory-safety abort | `poc_hex` or `cmd`; optional `expect_site` |
| `race_report` | a TSan data race at a site | `cmd?`, `expect_site?` (shadow-map failure → INCONCLUSIVE, not a false negative) |
| `security_oracle` | a single run shows an insecure state | `cmd`, `insecure_when` predicate |
| `trace_assertion` | a captured trace contains/omits a pattern | `cmd`, `assert_regex`, `forbid_regex?` |
| `differential_oracle` | insecurity attributable to a paired condition | `control{cmd}`, `test{cmd}`, `insecure_when`, `trials?` |

### Verdict shape

```
{ evidence_type, passed, reproduction_rate, trials, reason,
  artifacts: { command, input, schedule, trace, state }, detail: {...} }
```

`passed` is the machine-readable gate result. `reproduction_rate` is the
fraction of test trials that reproduced the insecure state. `artifacts` stores
the command, input, schedule, trace, and relevant state so a run is
replayable.

### The `insecure_when` predicate

AND-combined; an empty predicate is never insecure (fail-closed):

- `rc_in: [codes]` — the run's exit code is one of these
- `stdout_regex: "re"` — pattern occurs in stdout+stderr
- `count_regex: "re with one (group)"` + `count_gt: N` — parse an integer and
  require it `> N`

## The differential oracle

Passes **iff** across `trials`: the control is secure on *every* trial AND the
test is insecure on at least one. It **fails**, with an explicit reason, when
the control is itself insecure on any trial — because then concurrency (or
whatever the two runs differ by) is not isolated as the cause. This is the
"clear failure when the control is already insecure" property.

## BUG-003 as a differential oracle (`bug003_credential_toctou`)

- **Control** — `target_asan cred-baseline 500`: plants the record
  `5A 00 00 00` (a valid, **non-admin** credential) and calls
  `check_credential` 500× with no writer. Must grant admin **0** times.
- **Test** — `target_asan cred 2000 1`: same record, plus a concurrent second
  I2C writer flipping the role `0x00 ↔ 0xFF` inside the check/use window.
  Admin granted for the role-`0x00` record is the escalation; exit 1.
- **Invariant recorded in `artifacts.state`**: the planted record's authorised
  role is `0x00`; the escalation violates it. The clean 500/500 control is
  itself the proof that the record's authorised role is non-admin, so any
  admin grant in the test is unauthorised and concurrency-caused.

Measured (in-container, 5 trials): control secure 5/5, test insecure 5/5,
`reproduction_rate = 1.00`, `passed = true`.

## How it is wired in

- **Toolkit** (`agent/tools.py`): `validate_poc` (crash, unchanged fast path),
  `validate_evidence(evidence)` (generalized gate), `run_oracle(name)` (canonical
  per-bug specs). All three are exposed to the agent in `SCHEMAS`.
- **Scorer** (`scripts/score.py`): a `GATE RE-VERIFICATION` section re-runs the
  oracle for each reported finding's site and credits it only if the gate
  passes. Findings whose oracle fails are listed as `GATE-REJECTED`.
- **Tests** (`agent/test_oracles.py`): every positive case is paired with a
  negative one — benign input, wrong crash site, already-insecure control,
  non-reproducing test, unknown type — so the suite proves the gate rejects
  non-proofs.

## Running it

```bash
make -s -C host_twin all
python3 agent/oracles.py --all                    # all named oracles
python3 agent/oracles.py bug003_credential_toctou # one, full verdict JSON
python3 agent/test_oracles.py                     # pass/fail gate tests
python3 scripts/score.py agent/findings-run2.json # gate-verified scoring
```

## Extending

Add a bug's spec to `oracles.ORACLES` keyed by name, and map its defect-site
function in `scripts/score.py:FN_TO_ORACLE`. A new evidence type is a function
returning the verdict shape, registered in `oracles._VALIDATORS`. Keep the
paper-honest framing: an oracle proves the *specific* insecure transition it
observes; it is not a claim of exhaustive concurrency coverage.
