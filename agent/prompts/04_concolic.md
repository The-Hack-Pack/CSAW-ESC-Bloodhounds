# Stage 4 — Concolic

You test the candidates dynamically with concolic execution. Where stage 2
asked a solver to fork at every branch, you start from a **concrete seed**,
follow the single path it actually takes, and negate its branch conditions to
generate new seeds. One state is live at a time, every input you produce is a
real byte string, and each is replayed through the ASan harness automatically.

`concolic_chunk` takes the chunk spec and a seed list and runs generations:
each generation's inputs become the next generation's seeds when they reach new
blocks. Use the chunk's `args` with `{"kind":"seed_len"}` for the length
parameter so the function sees the seed's real size.

What to do:

1. Seed deliberately. A garbage seed (`"41"*64`) is the honest starting point
   and shows what the loop can discover unaided — typically it recovers a magic
   byte in generation 0 and needs generation 1 to get past it. If
   `candidates.json` has a `concolic_seed_hint` from the solver, run that too
   and say which one got there.
2. Read `crashing_inputs`. Those are replayed and confirmed — each carries the
   full sanitizer report. That is the strongest evidence this pipeline
   produces.
3. Watch `sinks_hit` and `blocks_covered`. A generation that adds no blocks and
   hits no sinks means the seed is stuck behind a guard the solver could not
   flip; report that rather than burning more generations.
4. Confirm or contradict stage 2. If symex said an overflow was reachable and
   concolic cannot produce a crashing input, say so explicitly — that gap is a
   result, and usually means the entry state was under-constrained in a way the
   real harness does not permit.

A candidate whose `proof_kind` is `interference` cannot be proved here: there is
no input that causes it, only a schedule. Record it as `not_applicable` and
leave it for the proof stage. Do not manufacture a seed for it.

## Output — write_artifact("concolic.json", ...)

```json
{"runs":[
  {"candidate_id":"V-1","chunk_id":"C-001","seeds_used":["4141..."],
   "generations":4,"blocks_covered":20,"inputs_generated":15,
   "sinks_hit":["0x401050"],
   "crashing":[{"poc_hex":"00c00024...","flipped_at":"0x4155d0","generation":1,
                "evidence":"ASan stack-buffer-overflow ... parse_config target.c:70"}],
   "outcome":"confirmed|no_crash|not_applicable","note":"..."}]}
```
