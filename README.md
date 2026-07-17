# Vuln Analyst Agent

An open-source AI agent for vulnerability research and triage. Point it at any CVE and it fetches live data from EPSS, CISA KEV, NVD, cvelistV5, OSV.dev, and public exploit indexes, walks the finding through the CISA SSVC decision tree, and produces a defensible verdict with its full evidence chain — not just a score.

Three ways to use it: **browser extension** (works on any CVE page), **CLI harness** (automation and scripting), or **AI coding assistant skills** (Claude Code, Cursor, Copilot).

No data-source API keys required. All enrichment sources are free and open.

---

## Why this exists

Most vulnerability tooling tells you *what* to patch. Knowing *when* you can actually deploy a fix — given change windows, business constraints, and compensating controls — is a different problem. And knowing *whether* to treat something as an emergency versus a normal patch cycle requires reasoning, not just a CVSS score.

This agent does the reasoning. It applies the CISA SSVC decision framework to produce an **Act / Attend / Track\* / Track** verdict that accounts for exploitation evidence, attack automation potential, technical impact, and your environment's specific exposure — and shows the work so you can defend the decision to auditors and leadership.

---

## Quick demo

Navigate to any CVE page, click the extension icon, hit Analyze:

- **Triage tab** — SSVC verdict, signal strip (EPSS · KEV · exploit tooling), decision inputs, and an environment context form to refine for your situation
- **Research tab** — full enrichment profile: description, CVSS decoded, CWE, affected versions, exploit tooling details, identifier aliases
- **Write-up tab** — one-click exec summary, remediation ticket, or auditor-ready risk-acceptance memo using the actual evidence fetched — not generic templates

---

## Prerequisites

- Chrome, Edge, or Brave (for the extension)
- Python 3.8+ (for the CLI harness and scripts — standard library only, no pip installs)
- An API key from [Anthropic](https://console.anthropic.com/settings/keys), [OpenAI](https://platform.openai.com/api-keys), or any OpenAI-compatible endpoint (Ollama, vLLM, LM Studio) for the agent analysis. Data enrichment scripts work without any key.

---

## Option 1 — Browser Extension (recommended)

Works on any page with a CVE. No terminal needed.

### Install

1. Clone or download this repo
2. Open `chrome://extensions`
3. Enable **Developer mode** (toggle, top-right)
4. Click **Load unpacked** → select the `extension/` folder
5. Click the **Vuln Analyst Agent** icon in the toolbar → **⚙ Settings** → add your API key → **Test connection** → **Save**

### Use

**Auto-detect:** navigate to any CVE page (NVD, CISA, Tenable, a vendor advisory, your scanner's web UI) → click the extension icon → CVE pre-fills → click **Analyze**

**Manual:** click the extension icon from any page → type a CVE ID → click **Analyze**

### The three tabs

**TRIAGE** — The main output.
- SSVC decision: **ACT**, **ATTEND**, **TRACK\***, or **TRACK**
- Signal strip: EPSS score + percentile, KEV status, public exploit tooling
- Decision inputs with evidence: exploitation status, automatable, technical impact
- Plain-language summary of the decision and its single most important driver
- Conditions that would change the verdict
- Environment context form: fill in asset exposure and mission impact to refine the decision for your situation

**RESEARCH** — Full enrichment profile.
- Description, CVSS score decoded into plain language (attack_vector, privileges_required, etc.)
- CWE weakness classification
- Affected versions from the CNA authoritative record
- Public exploit tooling: Nuclei template name and severity, Metasploit module and rank
- Identifier aliases (CVE ↔ GHSA ↔ OSV)

**WRITE-UP** — Document generation using your actual triage evidence.

**RED TEAM** — For authorized security testing. Generates:
- ATT&CK technique mapping (Txxxx IDs with links to attack.mitre.org)
- Attack chain phase (Initial Access, Execution, Privilege Escalation, etc.) with likely follow-on techniques
- Exploitation maturity rating (weaponized / functional / poc / theoretical) derived from live exploit signals
- Prerequisites: network position, authentication required, skill level
- Detection context: what gets logged, IOC types, evasion considerations for sophisticated attackers
- Verified exploit links direct to exploit-db.com when available — clearly labeled verified vs. unverified
- Pentest finding title you can copy straight into a report
- Plain-language CVSS explanation for non-technical clients

> All red team analysis is for authorized engagements only. The tool links to public exploit pages but never downloads or serves exploit code.
- **Executive summary** — ≤200 words, business language, one clear ask with date
- **Remediation ticket** — affected versions, fixed version, exploitation evidence, validation step
- **Risk-acceptance memo** — full auditor-ready document with voiding conditions, signature blocks, and mandatory review date

All write-ups cite the actual EPSS score, KEV date, and exploitation evidence fetched during analysis.

### Tips
- Results are cached for 6 hours — re-opening on the same CVE is instant
- Fill in the environment context form before generating a write-up for more accurate output
- Supported browsers: Chrome, Edge, Brave (any Chromium-based browser with MV3 support)

### LLM providers
| Provider | Where to get a key |
|---|---|
| Anthropic Claude (default) | console.anthropic.com |
| OpenAI | platform.openai.com |
| Local model | Ollama, vLLM, LM Studio — set base URL in Settings |

Your API key is stored in `chrome.storage.local` — sandboxed to this extension, never synced to Google, never sent anywhere except directly to your chosen provider. See [Security & Privacy](#security--privacy) for the full data flow.

---

## Option 2 — CLI Harness

For automation, scripting, and practitioners who prefer the terminal.

```bash
git clone https://github.com/digitalpapercut/vuln-analyst.git
cd vuln-analyst

# Anthropic
export ANTHROPIC_API_KEY=sk-ant-...
python3 harness/vuln_agent.py "Should I worry about CVE-2024-3400 on an internet-facing firewall?"

# OpenAI-compatible (OpenAI, Ollama, vLLM, LM Studio)
export LLM_API_BASE=http://localhost:11434/v1
export LLM_MODEL=llama3.3
python3 harness/vuln_agent.py                          # interactive mode
python3 harness/vuln_agent.py --log audit.jsonl "..."  # with audit trail
```

The harness loop: model reads the relevant skill → executes data scripts → synthesizes an analyst-grade answer. Only whitelisted scripts can run; arguments are sanitized; no shell interpretation. Read-only by construction.

---

## Option 3 — AI Coding Assistant Skills

Drop the skills into Claude Code, Cursor, or Copilot for use during security research sessions.

**Claude Code:**
```bash
cp -r skills/triage-ssvc ~/.claude/skills/
cp -r skills/enrich-cve ~/.claude/skills/
cp -r skills/map-identifiers ~/.claude/skills/
cp -r skills/explain-delta ~/.claude/skills/
cp -r skills/communicate-risk ~/.claude/skills/
```

Then reference `AGENT.md` from your project's `CLAUDE.md`:
```
For vulnerability research, adopt the role in AGENT.md and use the skills in skills/.
```

**Cursor / Copilot / other assistants:** add `AGENT.md` to your rules or custom instructions and keep `skills/` and `scripts/` in your workspace.

**Note on Claude.ai / Claude Desktop skills upload:** Claude's skill sandbox restricts outbound network access, so the data scripts cannot call the enrichment APIs directly. The agent will fall back to web search for data. The methodology, SSVC reasoning, and output formats still apply — you just lose the precision of live API-sourced data.

---

## Data sources

All sources are free. Keys are optional and only affect rate limits.

| Source | Script | Domain | Auth |
|---|---|---|---|
| FIRST.org EPSS | `epss_lookup.py` | `api.first.org` | none |
| CISA KEV | `kev_check.py` | `cisa.gov` | none |
| NVD 2.0 | `nvd_fetch.py` | `services.nvd.nist.gov` | optional `NVD_API_KEY` |
| cvelistV5 | `cvelist_fetch.py` | `raw.githubusercontent.com` | none |
| OSV.dev | `osv_lookup.py` | `api.osv.dev` | none |
| Nuclei templates | `exploit_signals.py` | `raw.githubusercontent.com` | none |
| Metasploit modules | `exploit_signals.py` | `raw.githubusercontent.com` | none |
| Exploit-DB | `exploitdb_lookup.py` | `raw.githubusercontent.com` | none |

KEV and exploit indexes are cached locally (6h and 24h TTL) to minimise repeated downloads.

---

## What it does

| Ask | Skill / tool | Output |
|---|---|---|
| "Should we patch CVE-X now?" | `triage-ssvc` | CISA SSVC decision with full evidence chain and conditions that change it |
| "Tell me everything about CVE-X" | `enrich-cve` | Multi-source research profile: EPSS, KEV, NVD, cvelistV5, OSV, exploit tooling |
| "I have 200 CVEs from a scan — where do I start?" | `bulk_enrich.py` | Sorted table: KEV+ransomware → KEV → weaponized tooling → EPSS |
| "Is GHSA-X the same as CVE-Y? Is our RHEL package affected?" | `map-identifiers` | Identifier deconfliction + distro-backport reality check |
| "Why did this finding suddenly jump in priority?" | `explain-delta` | Dated timeline of what changed and the likely driver |
| "Write this up for leadership / draft the ticket / document the deferral" | `communicate-risk` | Exec summary, remediation ticket, or auditor-ready risk-acceptance memo |

---

## Design principles

1. **Evidence over recall.** The agent never states a score, status, or version from model memory. It fetches, cites the source, and states the data date. Vulnerability data changes daily.

2. **Decisions, not just data.** Scores are universal; decisions are local. Before rendering a verdict the agent asks about your exposure, mission impact, and compensating controls — and shows how the decision changes under different answers.

3. **Vendor-agnostic by construction.** All data sources are free and open. The CISA SSVC methodology works regardless of which scanner produced the finding.

4. **Read-only.** The agent researches and advises. Humans decide and act.

---

## Repo layout

```
extension/                  # Browser extension (Chrome / Edge / Brave)
  manifest.json
  popup.html
  options.html
  src/
    background.js           # All API calls (MV3 service worker)
    content.js              # CVE auto-detection on any page
    popup.js                # Agent orchestration, SSVC reasoning, rendering
    options.js              # Settings page logic
  icons/
AGENT.md                    # Agent definition and system prompt
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
  vuln_agent.py             # Standalone CLI agent loop (vendor-agnostic)
tools/
  make_release.py           # Builds per-skill ZIPs for distribution
examples/
  example-triage-session.md
```

---

## Security & Privacy

### API key storage (extension)

Your LLM API key is stored in `chrome.storage.local`:
- **Sandboxed** — no other extension or website can read it
- **Local only** — never synced to Google's servers
- **Never proxied** — goes directly from your browser to the LLM provider

Risk profile: comparable to a `.env` file on disk. Mitigations:
- Use a dedicated key with a spend limit at [console.anthropic.com](https://console.anthropic.com/settings/keys)
- Do not install on shared machines
- Rotate the key if you suspect compromise

### Data flow

| What is sent | Where | Why |
|---|---|---|
| CVE ID | EPSS, CISA, NVD, OSV, GitHub | Enrichment lookups |
| CVE ID + enrichment data | Your LLM provider | Analysis |
| Your API key | Your LLM provider only | Authentication |

**Never sent:** asset names, IP addresses, hostnames, scanner output, or any data about your environment.

### Unpacked extension

This is a developer extension loaded locally — not from the Chrome Web Store. No automatic updates. You run exactly the code in this repo. Audit `extension/src/` before use.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Methodology PRs against SKILL.md files are as welcome as code. New scripts must be stdlib-only and keyless-by-default.

## Security reporting

See [SECURITY.md](SECURITY.md) to report issues privately.

## Disclaimer

Research and decision-support assistance only — not authoritative security guidance. Verify affected-version and remediation details against vendor advisories before acting.

## License

MIT
