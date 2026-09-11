#!/usr/bin/env python3
"""
The five stages, declared once.

Two drivers execute these: pipeline.py (Anthropic API, unattended, in the
container) and a Claude Code subagent driven by `pipeline.py --brief <stage>`
plus toolcli.py. Both read this table, so a stage's tool set and contract
cannot drift between them.

Each stage is a fresh conversation with a narrow tool set. That is deliberate:
the chunker has no proof tools, so it cannot wander into validating things, and
the prover has no symbolic tools, so it cannot re-derive a claim it is supposed
to be testing independently. Artifacts on disk are the only channel between
stages, which is what makes any stage re-runnable on its own.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PROMPTS = os.path.join(HERE, "prompts")

STAGES = [
    {
        "name": "chunk",
        "title": "Chunker",
        "artifact": "chunks.json",
        "reads": [],
        "prompt": "01_chunker.md",
        "budget": 30,
        "tools": ["binary_facts", "list_functions", "function_info",
                  "global_info", "stack_layout", "disassemble", "read_source",
                  "list_files", "write_artifact"],
    },
    {
        "name": "constrain",
        "title": "Constraint (symbolic execution)",
        "artifact": "constraints.json",
        "reads": ["chunks.json"],
        "prompt": "02_constraint.md",
        "budget": 40,
        "tools": ["read_artifact", "symex_chunk", "function_info",
                  "stack_layout", "read_source", "write_artifact"],
    },
    {
        "name": "analyze",
        "title": "Analyzer",
        "artifact": "candidates.json",
        "reads": ["chunks.json", "constraints.json"],
        "prompt": "03_analyzer.md",
        "budget": 30,
        "tools": ["read_artifact", "read_source", "function_info",
                  "disassemble", "stack_layout", "global_info",
                  "write_artifact"],
    },
    {
        "name": "concolic",
        "title": "Concolic",
        "artifact": "concolic.json",
        "reads": ["chunks.json", "candidates.json"],
        "prompt": "04_concolic.md",
        "budget": 40,
        "tools": ["read_artifact", "concolic_chunk", "validate_poc",
                  "function_info", "read_source", "write_artifact"],
    },
    {
        "name": "prove",
        "title": "Proof",
        "artifact": "findings.json",
        "reads": ["candidates.json", "concolic.json", "constraints.json"],
        "prompt": "05_prover.md",
        "budget": 30,
        "tools": ["read_artifact", "validate_poc", "prove_interference",
                  "prove_oracle", "run_tsan", "emulate_firmware", "build",
                  "read_source", "write_artifact"],
    },
]

BY_NAME = {s["name"]: s for s in STAGES}

SHARED_RULES = """
Ground rules for every stage of this pipeline:

1. Tools return evidence, never verdicts. You do the reasoning; do not treat a
   tool's output as a conclusion, and never report a suspicion as a finding.
2. Never invent an address, a symbol name or a buffer size. Every one of those
   is available from a tool -- function_info gives call-site and callee
   addresses, stack_layout gives exact DWARF extents. A hand-typed address is
   silently unreachable and costs you the whole chunk.
3. angr has no Xtensa lifter. Symbolic and concolic stages run on the x86-64
   twin only. Never claim a symbolic result about the ESP32 firmware.
4. A bounds check that is actually correct is not a vulnerability. Reporting a
   deliberate test hook or a correct clamp costs points.
5. Record what you rejected and why, not just what you found. A negative with a
   reason is a result.
6. End your turn by calling write_artifact exactly once with the artifact this
   stage owns. Emit JSON only -- no prose inside the artifact.
"""


def prompt_for(stage):
    """Full system prompt: shared rules plus the stage brief."""
    st = BY_NAME[stage] if isinstance(stage, str) else stage
    with open(os.path.join(PROMPTS, st["prompt"])) as f:
        body = f.read()
    return "%s\n\n%s" % (SHARED_RULES.strip(), body.strip())
