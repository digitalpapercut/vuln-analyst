---
name: enrich-cve
description: >
  Build a synthesized, source-cited research profile of a vulnerability by
  combining EPSS, CISA KEV, NVD, cvelistV5, and OSV data — what it is, what's
  affected, whether it's being exploited, and what the disagreements between
  sources mean. Use this skill whenever a user asks to "look up", "research",
  "tell me about", or "enrich" a CVE/GHSA/vulnerability, pastes a CVE ID and
  asks what it is, or asks about a named vulnerability ("what's the story
  with that new Palo Alto bug"). If the user wants a DECISION about what to
  do, hand off to triage-ssvc after gathering evidence.
---

# CVE Enrichment

Produce a research profile that synthesizes sources rather than listing
them. The value is in reconciliation: where sources agree, disagree, or are
silent, and what that pattern means.

## Step 1 — Resolve the identifier

If given a product name or informal description instead of a CVE ID
("the new Ivanti VPN bug"), use available web search to find the CVE ID
first; confirm with the user if multiple candidates exist. If given a GHSA
or OSV ID, run `scripts/osv_lookup.py id <ID>` and take the CVE from
`aliases`.

## Step 2 — Fetch all sources (parallel where possible)

```bash
python3 scripts/nvd_fetch.py <CVE>
python3 scripts/cvelist_fetch.py <CVE>
python3 scripts/epss_lookup.py <CVE>
python3 scripts/kev_check.py <CVE>
python3 scripts/osv_lookup.py id <CVE>   # if open-source software involved
python3 scripts/exploit_signals.py <CVE>  # Nuclei/Metasploit tooling presence
python3 scripts/exploitdb_lookup.py <CVE>   # Documented public exploits
```

If web search is available, additionally look for: vendor advisory, credible
exploitation reporting, and whether a Metasploit module or Nuclei template
exists. Cite what you find; skip silently if search is unavailable.


## Step 2.5 — Data quality check

Before synthesizing, verify:
- Which sources returned valid data vs. errors — list both
- Any material conflicts between sources (score, version, status)
- Whether any metric you plan to cite was actually returned this session
  (never fill a gap from memory — use "not available" instead)
- EPSS date: scores older than 7 days should be flagged as potentially stale

## Step 3 — Synthesize

Interpretation rules that make the profile analyst-grade:

- **Weaponized tooling check.** `exploit_signals.py` returning a Metasploit
  module or Nuclei template is high-signal evidence of: (a) exploitation
  status at least *poc*, possibly *active* when combined with KEV or
  reporting; and (b) automatable=yes for SSVC, since the exploitation
  step is already packaged. Name the specific module/template; it tells
  defenders what to expect.
- **Exploitation picture.** KEV presence = confirmed. EPSS is probabilistic:
  report both the score AND the percentile (0.15 means little to most
  readers; "higher than 96% of all CVEs" lands). Exploit-tagged references
  without KEV = weaponizable but not confirmed in the wild.
- **Severity vs. exploitability tension.** Explicitly flag CVSS-high +
  EPSS-low ("severe if exploited, but exploitation unlikely so far") and
  CVSS-moderate + KEV-listed ("attackers disagree with the score —
  treat as urgent").
- **Vector-to-exposure translation.** Decode the CVSS vector into plain
  meaning: AV:N/PR:N/UI:N = "remotely exploitable, no credentials, no user
  action — dangerous on anything reachable." AV:L/PR:H = "requires a
  privileged local account — post-compromise escalation, not initial access."
- **Affected-version reconciliation.** Prefer cvelistV5 (CNA authoritative)
  and the vendor advisory for version ranges; use NVD CPEs as corroboration;
  use OSV for open-source package semantics. If they conflict, say which you
  trust and why.
- **Freshness.** State each source's data date. If NVD status is
  "Awaiting Analysis" or EPSS has no score yet (very new CVE), flag the gap
  rather than papering over it.

## Step 4 — Report

ALWAYS use this structure:

```
## <CVE> — <title>

**One-paragraph summary** — what it is, what's affected, exploitation
status, and the headline takeaway.

**Exploitation evidence**
- KEV: <in/not in; date added, ransomware use, due date if present>
- EPSS: <score> (<percentile ordinal> percentile) as of <date>
- Public exploit code: <what exists, with references>

**Technical profile**
- CVSS: <score/severity> — <vector decoded into plain-language exposure meaning>
- Weakness: <CWE(s), in words>
- Attack prerequisites: <auth? user interaction? config? adjacency?>

**Affected & fixed**
- <products/packages and version ranges, with which source asserts each>
- Fix/workaround: <patch versions, mitigations from vendor advisory>

**Source notes**
- <agreements, conflicts, gaps, data dates>

**Suggested next step**
- <e.g. "Want me to run SSVC triage against your environment?">
```

Never invent affected versions, scores, or dates. Anything not returned by
a script or found in a cited page does not appear in the profile.
