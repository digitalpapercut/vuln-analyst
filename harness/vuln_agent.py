#!/usr/bin/env python3
"""vuln-agent: standalone CLI vulnerability analyst.

A thin, vendor-agnostic agent loop over the skills in skills/ and the data
scripts in scripts/. Python 3.8+, stdlib only.

Providers (checked in this order):
  1. Anthropic:          export ANTHROPIC_API_KEY=...        [optional ANTHROPIC_MODEL]
  2. OpenAI-compatible:  export LLM_API_BASE=https://.../v1  [LLM_API_KEY, LLM_MODEL]
     (works with OpenAI, Ollama, vLLM, LM Studio, most gateways)

Usage:
  python3 vuln_agent.py "Should I worry about CVE-2024-3400 on an internet-facing firewall?"
  python3 vuln_agent.py            # interactive session
  python3 vuln_agent.py --max-steps 12 "..."

The model drives research through a plain-text protocol (no vendor tool
schemas), one action per turn:
  RUN: <script.py> <args...>     -> executes a whitelisted script in scripts/
  READ_SKILL: <skill-name>       -> loads a SKILL.md into context
  FINAL:                         -> everything after this line is the answer

Safety: only scripts already present in scripts/ can run; arguments are
sanitized; no shell interpretation; network access is limited to whatever
those scripts do (all read-only public APIs).
"""
import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(ROOT)
SCRIPTS_DIR = os.path.join(REPO, "scripts")
SKILLS_DIR = os.path.join(REPO, "skills")
AGENT_MD = os.path.join(REPO, "AGENT.md")

SAFE_ARG = re.compile(r"^[A-Za-z0-9._:/\-]+$")
SCRIPT_TIMEOUT = 90


# ---------------------------------------------------------------- providers
def call_anthropic(messages, system, model):
    body = {
        "model": model,
        "max_tokens": 4000,
        "system": system,
        "messages": messages,
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return "".join(b.get("text", "") for b in data.get("content", [])
                   if b.get("type") == "text")


def call_openai_compatible(messages, system, model):
    base = os.environ["LLM_API_BASE"].rstrip("/")
    body = {
        "model": model,
        "messages": [{"role": "system", "content": system}] + messages,
        "max_tokens": 4000,
    }
    headers = {"content-type": "application/json"}
    key = os.environ.get("LLM_API_KEY")
    if key:
        headers["authorization"] = f"Bearer {key}"
    req = urllib.request.Request(f"{base}/chat/completions",
                                 data=json.dumps(body).encode("utf-8"),
                                 headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"] or ""


def pick_provider():
    if os.environ.get("ANTHROPIC_API_KEY"):
        model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
        return lambda m, s: call_anthropic(m, s, model), f"anthropic:{model}"
    if os.environ.get("LLM_API_BASE"):
        model = os.environ.get("LLM_MODEL", "")
        if not model:
            sys.exit("Set LLM_MODEL when using LLM_API_BASE.")
        return (lambda m, s: call_openai_compatible(m, s, model),
                f"openai-compatible:{model}")
    sys.exit("No provider configured. Set ANTHROPIC_API_KEY, or "
             "LLM_API_BASE (+ LLM_MODEL, optional LLM_API_KEY).")


# ------------------------------------------------------------------ actions
def list_scripts():
    return sorted(f for f in os.listdir(SCRIPTS_DIR)
                  if f.endswith(".py") and not f.startswith("_"))


def list_skills():
    out = []
    for name in sorted(os.listdir(SKILLS_DIR)):
        p = os.path.join(SKILLS_DIR, name, "SKILL.md")
        if os.path.isfile(p):
            out.append(name)
    return out


def run_script(line):
    parts = line.strip().split()
    if not parts:
        return "ERROR: empty RUN command."
    script, args = parts[0], parts[1:]
    if script not in list_scripts():
        return f"ERROR: unknown script '{script}'. Available: {', '.join(list_scripts())}"
    for a in args:
        if not SAFE_ARG.match(a) and not a.startswith("--"):
            return f"ERROR: argument rejected by sanitizer: {a!r}"
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS_DIR, script)] + args,
            capture_output=True, text=True, timeout=SCRIPT_TIMEOUT,
            cwd=REPO,
        )
    except subprocess.TimeoutExpired:
        return f"ERROR: {script} timed out after {SCRIPT_TIMEOUT}s."
    out = proc.stdout.strip()
    err = proc.stderr.strip()
    result = f"[exit={proc.returncode}]"
    if out:
        result += "\n" + out[:20000]
    if err:
        result += "\nSTDERR: " + err[:2000]
    return result


def read_skill(name):
    name = name.strip()
    p = os.path.join(SKILLS_DIR, name, "SKILL.md")
    if not os.path.isfile(p) or os.path.commonpath(
            [SKILLS_DIR, os.path.abspath(p)]) != SKILLS_DIR:
        return f"ERROR: unknown skill '{name}'. Available: {', '.join(list_skills())}"
    with open(p, encoding="utf-8") as f:
        return f.read()


# -------------------------------------------------------------------- agent
PROTOCOL = """
## How you operate in this CLI

You research by emitting exactly ONE action per reply, as the FIRST line:

RUN: <script.py> <args>      Execute a data script. Available scripts:
{scripts}

READ_SKILL: <name>           Load a skill's methodology. Available skills:
{skills}

FINAL:                       Done researching. Everything after this line
                             is your answer to the user.

Rules:
- One action per reply. Never combine RUN and FINAL in the same reply.
- Read the relevant skill BEFORE reasoning about methodology (e.g. read
  triage-ssvc before rendering a triage verdict).
- Ground every score/status/version claim in a RUN result from this session.
- If you need environmental context from the user, use FINAL: to ask the
  question — the conversation continues and you can resume research after
  they answer.
"""


def build_system_prompt():
    with open(AGENT_MD, encoding="utf-8") as f:
        agent = f.read()
    return agent + PROTOCOL.format(
        scripts="\n".join(f"  - {s}" for s in list_scripts()),
        skills="\n".join(f"  - {s}" for s in list_skills()),
    )


def parse_action(text):
    stripped = text.lstrip()
    for prefix in ("RUN:", "READ_SKILL:", "FINAL:"):
        if stripped.startswith(prefix):
            rest = stripped[len(prefix):]
            if prefix == "FINAL:":
                return "FINAL", rest.strip()
            first_line = rest.splitlines()[0] if rest.splitlines() else ""
            return prefix.rstrip(":"), first_line.strip()
    return "FINAL", text.strip()  # no protocol line -> treat as answer


def audit(log_path, record):
    if not log_path:
        return
    record["ts"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def agent_turn(call, system, messages, max_steps, verbose, log_path=None):
    for _ in range(max_steps):
        reply = call(messages, system)
        messages.append({"role": "assistant", "content": reply})
        action, payload = parse_action(reply)
        if action == "FINAL":
            audit(log_path, {"action": "FINAL", "answer": payload})
            return payload
        if verbose:
            print(f"  [{action}] {payload}", file=sys.stderr)
        if action == "RUN":
            result = run_script(payload)
        else:
            result = read_skill(payload)
        audit(log_path, {"action": action, "input": payload,
                         "result_preview": result[:1000]})
        messages.append({"role": "user",
                         "content": f"[{action} result]\n{result}"})
    return ("I hit the research step limit before finishing. Here's where "
            "I got to:\n\n" + messages[-2]["content"][:3000])


def main():
    ap = argparse.ArgumentParser(description="Standalone vulnerability analyst agent")
    ap.add_argument("question", nargs="*", help="One-shot question (omit for interactive)")
    ap.add_argument("--max-steps", type=int, default=15,
                    help="Max research actions per turn (default 15)")
    ap.add_argument("--quiet", action="store_true",
                    help="Hide research-step progress on stderr")
    ap.add_argument("--log", metavar="PATH",
                    help="Append a JSONL audit trail of every research "
                         "action and result to PATH")
    args = ap.parse_args()

    call, provider = pick_provider()
    system = build_system_prompt()
    verbose = not args.quiet
    print(f"vuln-agent · provider={provider} · read-only research agent",
          file=sys.stderr)

    messages = []

    def ask(q):
        messages.append({"role": "user", "content": q})
        audit(args.log, {"action": "USER", "input": q})
        answer = agent_turn(call, system, messages, args.max_steps, verbose,
                            log_path=args.log)
        print("\n" + answer + "\n")

    if args.question:
        ask(" ".join(args.question))
        return

    print("Interactive mode. Ctrl-D or 'exit' to quit.", file=sys.stderr)
    while True:
        try:
            q = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not q or q.lower() in {"exit", "quit"}:
            break
        ask(q)


if __name__ == "__main__":
    main()
