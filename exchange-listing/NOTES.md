# CyberAgents Exchange listing prep

The exchange (exchange.tenable.com) hosts listings as metadata files that
point to your repo; submission is a PR to
`github.com/tenable/cyberagents-exchange` using the templates in their
`templates/` directory. Check their `CONTRIBUTING.md` for the current
schema before submitting — field names below are draft copy, not their
schema.

## Suggested listings

1. **Agent listing** — the full bundle (AGENT.md + skills + scripts).
2. **Skill listing: triage-ssvc** — also list the flagship skill on its own
   under Skills, where practitioners browse for drop-in capabilities.

## Draft copy

**Name:** Vulnerability Analyst Agent

**Short description (agent):**
Standalone, open-source vulnerability research and triage agent — runs from the CLI with any model API (Anthropic or OpenAI-compatible, including local models), or drops into Claude Code/Cursor/Copilot as an agent definition with skills.
Grounds every answer in live EPSS, CISA KEV, NVD, cvelistV5, and OSV data,
walks findings through the SSVC deployer decision tree with your
environmental context, deconflicts identifiers across ecosystems, explains
why risk pictures change, and drafts exec summaries, tickets, and
risk-acceptance memos. Zero dependencies, zero required API keys.

**Short description (triage-ssvc skill):**
/triage-ssvc — turn "should we worry about CVE-X?" into a defensible SSVC
decision (Act / Attend / Track* / Track) with a full evidence chain from
live EPSS, KEV, NVD, and cvelistV5 data plus your environment's exposure and
mission context. Includes the conditions that would change the verdict, so
re-triage is automatic when the world moves.

**Integrations / compatibility:** Claude Code, Claude.ai, Cursor, GitHub
Copilot, any framework with shell + file access. Python 3.8+ stdlib only.

**Category tags:** vulnerability management, triage, SSVC, EPSS, CISA KEV,
threat exposure, prioritization

**License:** MIT
