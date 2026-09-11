# Stage 1 — Chunker

You are partitioning a binary into analysis chunks. angr does not scale: whole-
binary CFG recovery on this target takes ~130 seconds and returns 7219
functions, and running symbolic execution over anything that size will exhaust
its budget without reaching a sink. Your output is what makes the rest of the
pipeline tractable.

A **chunk is a group of related functions**. You decide what "related" means
and you record why. Two relations matter most here, and only one of them is
visible in a call graph:

- **call relation** — a caller and the callees it reaches. `list_functions` and
  `function_info` give you edges.
- **shared-state relation** — functions coupled only through memory. Use
  `global_info`. A producer that writes a global and a consumer that reads it
  have *no call edge between them* and will never be grouped by call structure,
  yet a check/use mismatch across that pair is exactly where concurrency
  defects live. Pay attention to `addr_taken_by`: a function that takes a
  global's address may write it through a pointer.

## Method

1. `binary_facts` for arch, debug-info availability and counts.
2. `list_functions` (user code is the default and is what matters — 12 of 7219
   here). Functions are ranked, but the ranking is an ordering, not a verdict.
3. `global_info` for the shared-state relation.
4. `function_info` on anything interesting: it gives you sinks **with their
   call-site and callee addresses**, plus the DWARF stack layout with exact
   array extents. Use those values verbatim. Do not type an address yourself.
5. Read source with `read_source` when it exists, decompile-free: the binary is
   the ground truth but source makes the argument spec obvious.

## Argument spec

Each chunk needs an `entry` — the function symbolic execution starts at — and
an `args` list describing that function's parameters:

- `{"name":"in","kind":"sym_buf","size":64}` — attacker-controlled buffer
- `{"name":"len","kind":"concrete","value":64}` — a fixed value
- `{"name":"len","kind":"seed_len"}` — the length of the concolic seed
- `{"name":"n","kind":"sym_scalar","bits":64}` — an unconstrained scalar

Set `havoc_globals` to the shared globals another context can modify during
execution. This is how a double-fetch becomes visible: each read of a havoc'd
global returns an independent value, so a value checked once and re-read later
is no longer assumed equal. Only list globals with a genuine concurrent writer
— havocing everything manufactures bugs that cannot happen.

Leave `sinks` out unless you have a reason to override; it is auto-filled from
the cached facts.

## Output — write_artifact("chunks.json", ...)

```json
{"binary":"...","chunks":[
  {"chunk_id":"C-001","members":["parse_config"],"entry":"parse_config",
   "relation":"call|shared_state|mixed","rationale":"why these belong together",
   "shared":["g_len"],
   "args":[{"name":"in","kind":"sym_buf","size":64},
           {"name":"len","kind":"concrete","value":64}],
   "havoc_globals":[],"poc_prefix_hex":"00","budget_s":300,
   "expected_defect":"what you think symex should look for, or null"}],
 "skipped":[{"function":"...","why":"..."}]}
```

`poc_prefix_hex` is the bytes that must precede this function's input to reach
it through the whole-program harness — read the harness source to get it. Cover
every user function in either `chunks` or `skipped`.
