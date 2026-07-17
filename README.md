# Vulnerability Analyst Agent

An open-source, vendor-agnostic AI agent and skill set that turns any
capable LLM assistant into a vulnerability research and triage analyst.
Every answer is grounded in live, free data — EPSS, CISA KEV, NVD,
cvelistV5, OSV.dev, and public exploit indexes — with practitioner
methodology (CISA SSVC decision trees, cross-ecosystem identifier mapping,
audience-aware risk communication) layered on top.

**Zero dependencies. Zero required API keys. Python 3.8+ standard library only.**

Works standalone from the CLI, or drops into Claude Code, Claude.ai,
Cursor, GitHub Copilot, and any framework that can read markdown and run
Python.

---

## What it does

| Ask | Skill / script | Output |
|---|---|---|
| "Should we worry about CVE-X for our environment?" | `triage-ssvc` | CISA SSVC decision (Act / Attend / Track* / Track) with full evidence chain and conditions that change it |
| "Tell me everything about CVE-X" | `enrich-cve` | Multi-source research profile reconciling EPSS, KEV, NVD, cvelistV5, OSV, and weaponized tooling |
| "I have 200 CVEs from a scan — where do I start?" | `bulk_enrich.py` | Sorted, enriched table: KEV+ransomware → KEV → weaponized tooling → EPSS |
| "Is GHSA-X the same as CVE-Y? Is our RHEL package affected?" | `map-identifiers` | Identifier deconfliction + distro-backport reality check |
| "Why did this finding suddenly jump in priority?" | `explain-delta` | Dated timeline of what changed (EPSS movement, KEV addition, rescore) and the likely driver |
| "Write this up for the exec / draft the ticket / document the deferral" | `communicate-risk` | Exec summary, remediation ticket, or auditor-ready risk-acceptance memo |

---

## Design principles

1. **Evidence over recall.** The agent never states a score, status, or
   version from model memory. It runs the scripts, cites the source, and
   states the data date. Vulnerability data changes daily.

2. **Decisions, not just data.** Scores are universal; decisions are local.
   Before rendering a verdict the agent asks about your exposure, mission
   impact, and compensating controls — and shows how the decision changes
   under different answers.

3. **Vendor-agnostic by construction.** All data sources are free and open.
   The CISA SSVC methodology works regardless of which scanner produced the
   finding. The standalone harness works with any model API.

4. **Read-only.** The agent researches and advises. Humans decide and act.

---

## Install

### Option 1 — Standalone CLI agent

Runs independently. No agent framework needed.

```bash
git clone https://github.com/<you>/vuln-analyst-agent
cd vuln-analyst-agent

# Anthropic
export ANTHROPIC_API_KEY=sk-ant-...
python3 harness/vuln_agent.py "Should I worry about CVE-2024-3400 on an internet-facing firewall?"

# OpenAI-compatible (OpenAI, Ollama, vLLM, LM Studio, most gateways)
export LLM_API_BASE=http://localhost:11434/v1
export LLM_MODEL=llama3.3
python3 harness/vuln_agent.py              # interactive mode
python3 harness/vuln_agent.py --log audit.jsonl "..."   # with audit trail
```

The harness loop: model reads skills → executes data scripts → synthesizes
an analyst-grade answer. Only whitelisted scripts run; arguments are
sanitized; no shell. Read-only by construction.

### Option 2 — Claude.ai / Claude Desktop

Upload individual skill ZIPs in two clicks.

1. Download the per-skill ZIP from [Releases](../../releases)
   (e.g. `triage-ssvc-1.0.0.zip`).
2. Open Claude → **Customize → Skills → +** → Upload ZIP.
3. Toggle the skill on. Claude uses it automatically when relevant.

Requires a paid Claude plan with code execution enabled. Skills need
outbound HTTPS to the domains in the egress table below; on restricted
enterprise plans, allow those domains first.

To build skill ZIPs yourself from source:
```bash
python3 tools/make_release.py --version 1.0.0
# outputs to dist/
```

### Option 3 — Claude Code (filesystem)

```bash
# Personal (all your projects)
cp -r skills/triage-ssvc ~/.claude/skills/
cp -r skills/enrich-cve ~/.claude/skills/
# ...repeat for other skills

# Per-project
mkdir -p .claude/skills
cp -r skills/triage-ssvc .claude/skills/
```

Claude Code discovers and uses skills automatically. Reference `AGENT.md`
from your project's `CLAUDE.md` for the analyst persona.

### Option 4 — Cursor / Copilot / other assistants

Add `AGENT.md` to your rules or custom instructions, and keep `skills/`
and `scripts/` in your workspace. The skills are plain markdown; any
assistant that can read files and run Python can use them.

---

## Data sources & egress

All sources are free. Keys are optional (higher rate limits only).

| Source | Script | Egress domain | Auth |
|---|---|---|---|
| FIRST.org EPSS | `epss_lookup.py` | `api.first.org` | none |
| CISA KEV | `kev_check.py` | `cisa.gov` | none |
| NVD 2.0 | `nvd_fetch.py` | `services.nvd.nist.gov` | optional `NVD_API_KEY` |
| cvelistV5 | `cvelist_fetch.py` | `raw.githubusercontent.com` | none |
| OSV.dev | `osv_lookup.py` | `api.osv.dev` | none |
| Nuclei templates | `exploit_signals.py` | `raw.githubusercontent.com` | none |
| Metasploit modules | `exploit_signals.py` | `raw.githubusercontent.com` | none |

Exploit and KEV indexes are cached in the system temp directory (24h and 6h
TTL respectively) to minimise repeated downloads.

---

## Repo layout

```
AGENT.md                    # Agent definition / system prompt / install notes
SECURITY.md
CONTRIBUTING.md
LICENSE
skills/
  triage-ssvc/              # CISA SSVC decision tree → Act/Attend/Track*/Track
  enrich-cve/               # Multi-source synthesis
  map-identifiers/          # CVE ↔ GHSA ↔ OSV ↔ distro deconfliction
  explain-delta/            # Why did the risk picture change?
  communicate-risk/         # Exec summary / ticket / risk-acceptance memo
scripts/                    # Stdlib-only Python, JSON out, meaningful exit codes
  epss_lookup.py
  kev_check.py
  nvd_fetch.py
  cvelist_fetch.py
  osv_lookup.py
  exploit_signals.py        # Nuclei template + Metasploit module presence
  bulk_enrich.py            # Batch EPSS+KEV+tooling for scanner exports
harness/
  vuln_agent.py             # Standalone CLI loop (vendor-agnostic)
tools/
  make_release.py           # Builds per-skill ZIPs for claude.ai upload
examples/
  example-triage-session.md
exchange-listing/
  NOTES.md                  # CyberAgents Exchange submission draft
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Methodology PRs (against SKILL.md
files) are as welcome as code. New scripts must stay stdlib-only and
keyless-by-default.

## Security

See [SECURITY.md](SECURITY.md) for the threat model and how to report
issues privately.

## Disclaimer

Research and decision-support assistance only — not authoritative security
guidance. Verify affected-version and remediation details against vendor
advisories before acting. Data sources are third-party services with their
own terms and availability.

## License

MIT
