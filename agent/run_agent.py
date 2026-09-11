#!/usr/bin/env python3
"""
Minimal autonomous loop: model + toolkit + PoC gate.

This is deliberately ~100 lines. Get this working end to end before you add
orchestration, parallelism or MCP -- the AIxCC result was that a reliable
simple pipeline beats an ambitious unreliable one.

    export ANTHROPIC_API_KEY=...
    pip install anthropic
    python3 run_agent.py --budget 25

Not executed in the environment where this scaffold was produced (no key).
"""
import argparse
import json
import os
import re
import sys

import tools


def extract_findings_blob(text: str) -> dict:
    """Pull a scorer-shaped object out of the model's final message.

    The scorer expects {"findings": [...], ...}. Models tend to wrap that in
    prose or a ```json fence, or emit a bare array. Recover all three so a live
    run always produces a scorable file (or a diagnostic one, never silent
    garbage). Returns a dict with at least a "findings" list.
    """
    candidates = []
    # 1. fenced ```json ... ``` blocks (last one wins -- usually the summary)
    candidates += re.findall(r"```(?:json)?\s*(.*?)```", text, re.S)
    # 2. the whole message, and the outermost {...} / [...] spans
    candidates.append(text)
    for m in re.finditer(r"(\{.*\}|\[.*\])", text, re.S):
        candidates.append(m.group(1))

    for blob in reversed(candidates):
        blob = blob.strip()
        if not blob:
            continue
        try:
            obj = json.loads(blob)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, list):
            return {"findings": obj}
        if isinstance(obj, dict) and "findings" in obj:
            return obj
    # Nothing parsed -- preserve the raw text so the run is diagnosable.
    return {"findings": [], "parse_error": "no JSON findings object recovered",
            "raw": text[:8000]}

CRED_HELP = """FATAL: no Anthropic credentials resolved.

The SDK checks, in order: ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, an OAuth
profile from `ant auth login`, workload identity, then the default profile on
disk. None were found.

  API key:  create one at console.anthropic.com, then `export ANTHROPIC_API_KEY=...`
            Note this is billed separately from a Claude.ai subscription.
  OAuth:    install the `ant` CLI and run `ant auth login`, then check with
            `ant auth status`. No env var needed -- the SDK reads the profile.

In the container, the agent service mounts ~/.config/anthropic read-only so an
OAuth profile carries through; an API key is passed via the environment."""


def _create(client, args, messages):
    """One model turn. Adaptive thinking + high effort: finding an atomicity
    violation is exactly the hard-reasoning case this is for. `budget_tokens`
    is rejected on current models -- effort replaces it. fallbacks="default"
    matters here specifically: a vulnerability-analysis prompt can trip the
    cyber safety classifier, and without a fallback a decline ends the run."""
    return client.beta.messages.create(
        model=args.model, max_tokens=16000, system=SYSTEM,
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        tools=tools.SCHEMAS, messages=messages,
    )

SYSTEM = """You are an autonomous firmware vulnerability analyst working on an \
ESP32/FreeRTOS smart-home gateway. The code under test is a host-buildable twin \
of the firmware: an RFID interrupt handler and a consumer task share state, a \
config parser reads attacker-controlled bytes, and an I2C EEPROM backs a \
credential store.

Your job is to find memory-safety and concurrency defects and prove each one.

Rules:
1. A finding is not a finding until validate_poc returns crashed=true, or a \
sanitizer report names the exact function and line. Never report a suspicion.
2. Prefer cheap tools first: read the source, then run the sanitizers, and only \
call symbolic_solve when you are blocked by a magic value or a structured input.
3. Concurrency bugs will not appear in a single-threaded run. If you suspect a \
race, use run_tsan and run_interleaving rather than reasoning about it.
4. Distinguish a bug from a deliberate test hook. Bounds checks that are \
actually correct are not vulnerabilities; reporting them costs you points.

When you are done, emit a final message containing a JSON array under the key \
"findings", each entry having: id, class, cwe, file, function, line, \
evidence (the sanitizer line that proves it), poc (hex string or command), \
and confidence."""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=25, help="max model turns")
    ap.add_argument("--model", default="claude-opus-5")
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args()

    # Imported here, not at module top, so the module (and extract_findings_blob)
    # is testable without the SDK installed.
    try:
        from anthropic import Anthropic, AuthenticationError
    except ImportError:
        sys.exit("pip install anthropic")

    # Do NOT hard-require ANTHROPIC_API_KEY. The SDK resolves credentials in
    # order: ANTHROPIC_API_KEY -> ANTHROPIC_AUTH_TOKEN -> the OAuth profile
    # from `ant auth login` -> workload identity -> the default profile on
    # disk. Demanding the env var breaks every path but the first, including
    # the no-key `ant auth login` flow. Let the SDK resolve, and report what
    # it found so a failure is diagnosable.
    # The constructor does NOT validate credentials -- it resolves them lazily
    # and raises a bare TypeError on the first request. Catch that below, where
    # it actually happens, rather than pretending to check it here.
    client = Anthropic()
    # Say what we are about to try, not that it worked -- nothing is validated
    # until the first request lands.
    print("credentials: %s" % ("ANTHROPIC_API_KEY from environment"
                               if os.environ.get("ANTHROPIC_API_KEY")
                               else "none in environment; deferring to SDK resolution"))
    messages = [{"role": "user", "content":
                 "Analyze the target. Start by listing the files."}]

    turns = 0
    tool_calls = 0
    in_tok = out_tok = 0
    while turns < args.budget:
        turns += 1
        try:
            resp = _create(client, args, messages)
        except TypeError as e:
            if "Could not resolve authentication" not in str(e):
                raise
            sys.exit(CRED_HELP)
        except AuthenticationError as e:
            sys.exit(f"FATAL: credentials were found but rejected ({e.status_code}).\n"
                     "       An expired OAuth profile: re-run `ant auth login`.\n"
                     "       A bad key: check it at console.anthropic.com.")
        in_tok += resp.usage.input_tokens
        out_tok += resp.usage.output_tokens

        # A refusal is HTTP 200 with empty-ish content. Without this the loop
        # would fall through and write a garbage findings.json.
        if resp.stop_reason == "refusal":
            cat = getattr(resp.stop_details, "category", None)
            sys.exit(f"FATAL: request declined (category={cat}) after "
                     f"{turns} turns; {args.out} left unchanged.")

        for block in resp.content:
            if block.type == "text" and block.text.strip():
                print(f"\n[turn {turns}] {block.text[:1200]}")

        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason != "tool_use":
            break

        results = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            print(f"  -> {block.name}({json.dumps(block.input)[:160]})")
            tool_calls += 1
            out = tools.call(block.name, block.input)
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(out)[:12000],
            })
        messages.append({"role": "user", "content": results})

    print(f"\n=== {turns} turns, {tool_calls} tool calls, "
          f"{in_tok} in / {out_tok} out tokens ===")

    # Persist a scorer-shaped findings file, not the raw model text. The scorer
    # reads {"findings": [...], "tool_calls_used": N}; recover that from the
    # final message and stamp the run metadata the scorer reports.
    final = "".join(b.text for b in resp.content if b.type == "text")
    out = extract_findings_blob(final)
    out.setdefault("run", f"run_agent.py {args.model}, {turns} turns")
    out["tool_calls_used"] = tool_calls
    out["tokens"] = {"in": in_tok, "out": out_tok}
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    n = len(out.get("findings", []))
    if out.get("parse_error"):
        print(f"WARNING: {out['parse_error']}; wrote {args.out} with raw text "
              "preserved for inspection.")
    print(f"wrote {args.out} ({n} finding(s), {tool_calls} tool calls)")


if __name__ == "__main__":
    main()
