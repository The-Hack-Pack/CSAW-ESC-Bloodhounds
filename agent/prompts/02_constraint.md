# Stage 2 — Constraint (symbolic execution)

You run directed symbolic execution over each chunk from `chunks.json` and
report, per sink, what the solver can prove. You do not classify vulnerabilities
— that is the analyzer's job. You produce constraint facts.

`symex_chunk` builds a `call_state` at the chunk entry, explores to the chunk's
sinks, and at each sink reads the destination and length **from the argument
registers at the call**, then derives the destination's capacity — preferring
the exact DWARF extent of the stack local, falling back to the containing
global's size, and only then to frame distance. `capacity_source` tells you
which; a `frame_distance_to_cfa` capacity is an upper bound on a buffer, not the
buffer, so an overflow verdict against it is weak and you must say so.

Three outcomes matter, and the third is the one fuzzing cannot give you:

- **overflow: true** with `solved` — a concrete input satisfying length >
  capacity. Record it; the analyzer and concolic stages will use it.
- **overflow: false** with `proved_unreachable` — UNSAT. The path's own guards
  bound the length. This is a *proof*, and it is a result worth reporting.
- **not reached** — the sink is in `sinks_not_reached`. Say why if you can
  (a guard the entry state cannot satisfy, a budget exhaustion, a state cap).

Check `stopped_early`. `budget_exhausted` or `state_cap_exceeded` means the
chunk did not finish and any negative is **not** a negative — it is no result.
Retry once with a larger `budget_s`, a smaller `loop_bound`, or `veritesting`,
and if it still does not finish, say so plainly.

When `interference_modeled` is true, the length became attacker-controlled
through a havoc'd global rather than through input bytes. `poc_kind` will be
`interference`: there is no byte string that proves it, and the proof stage
needs a scheduling argument instead. Never fabricate an input PoC for one.

## Output — write_artifact("constraints.json", ...)

```json
{"results":[
  {"chunk_id":"C-001","entry":"parse_config","ran":true,
   "sinks":[{"callee":"memcpy","call_site":"0x401ae6",
             "dest_capacity":32,"capacity_source":"dwarf_local:name:uint8_t[][32]",
             "length_symbolic":true,"length_max":61,
             "outcome":"overflow|proved_unreachable|not_reached|no_result",
             "solved_input_hex":"...","solved_length":61,
             "poc_kind":"input|interference",
             "note":"..."}],
   "stopped_early":null,"seconds":0.7}],
 "unfinished":[{"chunk_id":"...","why":"..."}]}
```
