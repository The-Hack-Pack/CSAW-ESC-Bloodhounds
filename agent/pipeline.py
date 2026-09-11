#!/usr/bin/env python3
"""
Staged multi-agent pipeline: chunk -> constrain -> analyze -> concolic -> prove.

    python3 pipeline.py                     # all five stages
    python3 pipeline.py --stage chunk       # one stage
    python3 pipeline.py --from analyze      # resume from an artifact on disk
    python3 pipeline.py --brief concolic    # print the brief for a subagent
    python3 pipeline.py --target /path/elf  # any x86-64 ELF

Each stage is its own conversation with a narrow tool set, and artifacts on
disk are the only channel between them. That is what makes `--from` work: a
stage does not care whether the artifact it reads was written by the previous
stage, by a Claude Code subagent, or by hand.

`--brief` exists because this pipeline has two drivers. This file is the
unattended one; the other is a person (or a Claude Code subagent) executing the
same stage against the same tools through toolcli.py. Both read stages.py, so
the contract cannot drift.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import stages          # noqa: E402
import tools           # noqa: E402

ARTIFACTS = tools.ARTIFACTS

# Credential failures arrive as several unrelated exception types depending on
# which provider the SDK resolved: a bare TypeError when nothing resolves at
# all, AuthenticationError for a rejected key, and WorkloadIdentityError (from
# a private module, so matched by name) when an OAuth profile exists but its
# refresh token is dead. All three are the same problem to the operator and all
# three used to surface as a 40-line traceback.
_CRED_ERRORS = ("WorkloadIdentityError", "AuthenticationError",
                "PermissionDeniedError")
_CRED_MARKERS = ("invalid_grant", "refresh failed", "Could not resolve authentication",
                 "credential", "oauth")


def _credential_problem(e):
    if type(e).__name__ in _CRED_ERRORS:
        return True
    msg = str(e).lower()
    return any(m.lower() in msg for m in _CRED_MARKERS)


CRED_HELP = """FATAL: no Anthropic credentials resolved.

The SDK checks, in order: ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, an OAuth
profile from `ant auth login`, workload identity, then the default profile on
disk. None were found.

  API key:  create one at console.anthropic.com, then `export ANTHROPIC_API_KEY=...`
  OAuth:    install the `ant` CLI and run `ant auth login`, then `ant auth status`.

In the container, the agent service mounts ~/.config/anthropic read-only so an
OAuth profile carries through; an API key is passed via the environment. A
mounted profile whose refresh token has expired fails with invalid_grant -- the
file being present is not the same as it being valid. Re-run `ant auth login`
on the host; the mount picks the new profile up with no rebuild.

No key needed to inspect the pipeline: `--brief <stage>` prints a stage brief,
and toolcli.py runs any tool directly."""


def brief(stage_name, target):
    """The self-contained instruction block for driving one stage by hand or
    as a Claude Code subagent."""
    st = stages.BY_NAME[stage_name]
    lines = [
        "# %s  (stage: %s)" % (st["title"], st["name"]),
        "",
        "Target binary : %s" % target,
        "Reads         : %s" % (", ".join(st["reads"]) or "nothing"),
        "Writes        : agent/artifacts/%s" % st["artifact"],
        "Turn budget   : %d" % st["budget"],
        "",
        "Run tools with:",
        "    python3 agent/toolcli.py <tool> '<json args>'",
        "",
        "Tools available to this stage:",
    ]
    for t in st["tools"]:
        d = tools.SCHEMAS[t]["description"].split(". ")[0]
        lines.append("    %-20s %s" % (t, d))
    lines += ["", "-" * 72, "", stages.prompt_for(st)]
    return "\n".join(lines)


def _create(client, model, system, messages, toolset, max_tokens=16000):
    """One model turn. Adaptive thinking + high effort: partitioning a binary
    and reading a constraint set are exactly the hard-reasoning cases this is
    for. fallbacks="default" matters specifically here -- a vulnerability
    analysis prompt can trip the cyber safety classifier, and without a
    fallback a decline ends the run."""
    return client.beta.messages.create(
        model=model, max_tokens=max_tokens, system=system,
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        tools=tools.schemas_for(toolset),
        messages=messages,
    )


def run_stage(client, st, args):
    """Execute one stage to completion. Returns a result record."""
    system = stages.prompt_for(st)
    missing = [a for a in st["reads"]
               if not os.path.exists(os.path.join(ARTIFACTS, a))]
    if missing:
        return {"stage": st["name"], "ok": False,
                "error": "missing input artifact(s): %s -- run the earlier "
                         "stage, or drop the file in agent/artifacts/" % missing}

    opening = ("Target binary: %s\n"
               "Artifacts you may read: %s\n"
               "Write your output to %s when you are done.\n\n"
               "Begin." % (args.target, ", ".join(st["reads"]) or "none",
                           st["artifact"]))
    messages = [{"role": "user", "content": opening}]
    t0 = time.time()
    turns = in_tok = out_tok = 0
    resp = None

    while turns < st["budget"]:
        turns += 1
        try:
            resp = _create(client, args.model, system, messages, st["tools"])
        except TypeError as e:
            if "Could not resolve authentication" not in str(e):
                raise
            sys.exit(CRED_HELP)
        except Exception as e:
            if not _credential_problem(e):
                raise
            sys.exit("%s\n\nThe SDK reported: %s: %s"
                     % (CRED_HELP, type(e).__name__, str(e)[:400]))
        in_tok += resp.usage.input_tokens
        out_tok += resp.usage.output_tokens

        # A refusal is HTTP 200 with empty-ish content. Without this the loop
        # falls through and the stage writes nothing while reporting success.
        if resp.stop_reason == "refusal":
            cat = getattr(resp.stop_details, "category", None)
            return {"stage": st["name"], "ok": False, "turns": turns,
                    "error": "request declined (category=%s)" % cat}

        for b in resp.content:
            if b.type == "text" and b.text.strip():
                print("  [%s t%d] %s" % (st["name"], turns, b.text[:600]))

        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            break

        results = []
        for b in resp.content:
            if b.type != "tool_use":
                continue
            print("    -> %s(%s)" % (b.name, json.dumps(b.input)[:180]))
            out = tools.call(b.name, b.input)
            results.append({"type": "tool_result", "tool_use_id": b.id,
                            "content": json.dumps(out, default=str)[:14000]})
        messages.append({"role": "user", "content": results})

    path = os.path.join(ARTIFACTS, st["artifact"])
    wrote = os.path.exists(path)
    rec = {"stage": st["name"], "ok": wrote, "turns": turns,
           "in_tokens": in_tok, "out_tokens": out_tok,
           "seconds": round(time.time() - t0, 1),
           "artifact": st["artifact"] if wrote else None}
    if not wrote:
        # Budget exhaustion and a silent no-write look identical downstream.
        rec["error"] = ("stage ended without writing %s (turn budget %d "
                        "exhausted?)" % (st["artifact"], st["budget"]))
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=tools.DEFAULT_BINARY)
    ap.add_argument("--harness", default=tools.DEFAULT_HARNESS)
    ap.add_argument("--model", default="claude-opus-5")
    ap.add_argument("--stage", help="run exactly one stage")
    ap.add_argument("--from", dest="start", help="start at this stage")
    ap.add_argument("--to", dest="end", help="stop after this stage")
    ap.add_argument("--brief", help="print a stage brief and exit (no API)")
    ap.add_argument("--list", action="store_true", help="list stages and exit")
    args = ap.parse_args()

    tools.DEFAULT_BINARY = args.target
    tools.DEFAULT_HARNESS = args.harness
    os.makedirs(ARTIFACTS, exist_ok=True)

    if args.list:
        for s in stages.STAGES:
            print("%-10s %-32s reads: %s" % (s["name"], s["title"],
                                             ", ".join(s["reads"]) or "-"))
        return 0
    if args.brief:
        if args.brief not in stages.BY_NAME:
            sys.exit("unknown stage %r; one of %s"
                     % (args.brief, ", ".join(stages.BY_NAME)))
        print(brief(args.brief, args.target))
        return 0

    selected = stages.STAGES
    if args.stage:
        if args.stage not in stages.BY_NAME:
            sys.exit("unknown stage %r" % args.stage)
        selected = [stages.BY_NAME[args.stage]]
    else:
        names = [s["name"] for s in stages.STAGES]
        lo = names.index(args.start) if args.start else 0
        hi = names.index(args.end) + 1 if args.end else len(names)
        selected = stages.STAGES[lo:hi]

    try:
        from anthropic import Anthropic
    except ImportError:
        sys.exit("pip install anthropic")
    client = Anthropic()
    print("target     : %s" % args.target)
    print("credentials: %s" % ("ANTHROPIC_API_KEY from environment"
                               if os.environ.get("ANTHROPIC_API_KEY")
                               else "none in environment; deferring to SDK"))
    print("stages     : %s\n" % " -> ".join(s["name"] for s in selected))

    summary = []
    for st in selected:
        print("== %s (%s) ==" % (st["title"], st["name"]))
        rec = run_stage(client, st, args)
        summary.append(rec)
        print("   %s\n" % json.dumps({k: v for k, v in rec.items()
                                      if k != "stage"}))
        if not rec["ok"]:
            print("stopping: %s failed" % st["name"])
            break

    print("=== pipeline summary ===")
    for r in summary:
        print("  %-10s ok=%-5s turns=%-3s %5.1fs  in=%-7s out=%s"
              % (r["stage"], r["ok"], r.get("turns"), r.get("seconds", 0),
                 r.get("in_tokens"), r.get("out_tokens")))
    with open(os.path.join(ARTIFACTS, "pipeline_run.json"), "w") as f:
        json.dump({"target": args.target, "model": args.model,
                   "stages": summary, "when": time.strftime("%Y-%m-%dT%H:%M:%S")},
                  f, indent=1)
    return 0 if all(r["ok"] for r in summary) else 1


if __name__ == "__main__":
    sys.exit(main())
