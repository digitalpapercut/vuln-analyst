---
name: triage-ssvc
description: >
  Produce a defensible triage decision (Act / Attend / Track* / Track) for a
  vulnerability using the CISA SSVC (Stakeholder-Specific Vulnerability
  Categorization) decision tree, combining live exploitation
  evidence with the user's environmental context. Use this skill whenever a
  user asks "should I worry about CVE-X", "how urgent is this finding", "do
  we need to patch now", "help me prioritize these CVEs", or any question
  that requires a verdict about what to DO about a vulnerability — even if
  they don't mention SSVC by name. For pure information gathering with no
  decision needed, use enrich-cve instead.
---

# SSVC Triage

Walk a vulnerability through the **CISA SSVC decision tree** and
return a decision with its full evidence chain. SSVC (from CMU/SEI and
CISA) answers the question CVSS cannot: *what should this organization do,
and how fast?* This skill implements the CISA SSVC tree (five decision
values: exploitation, automatable, technical impact, mission prevalence,
public well-being — the last two combined as Mission & Well-being) per the
CISA SSVC Guide; validate edge cases against the official calculator at
https://www.cisa.gov/ssvc-calculator.

## Step 1 — Gather exploitation evidence (run scripts, never recall)

Run these before any reasoning:

```bash
python3 scripts/epss_lookup.py <CVE>
python3 scripts/kev_check.py <CVE>
python3 scripts/nvd_fetch.py <CVE>
python3 scripts/cvelist_fetch.py <CVE>
python3 scripts/exploit_signals.py <CVE>   # Nuclei template / Metasploit module presence
```

Note: `cvelist_fetch.py` may return a ready-made CISA ADP SSVC assessment
(`cisa_adp_ssvc`). Use it as corroborating input, not as the answer — it
scores the vulnerability in the abstract, while your job is to score it for
*this user's environment*.

## Step 2 — Determine the three tree inputs

### Decision point 1: Exploitation status
- **active** — in CISA KEV, or credible reporting of exploitation in the
  wild (KEV `known_ransomware_use: Known` is the strongest signal).
- **poc** — public proof-of-concept exists: `exploit_signals.py` reports a
  Metasploit module or Nuclei template, or NVD/cvelistV5 references are
  tagged `exploit`, or a public PoC repo exists. A Metasploit module or
  Nuclei template is also strong evidence for **Automatable: yes** — the
  exploitation step is already packaged for automation.
  A high EPSS score (roughly ≥ 0.10, or percentile ≥ 90) with no confirmed
  reports also justifies treating exploitation as at least *poc*-likely;
  say you're doing so.
- **none** — no evidence of either. Low EPSS supports this but does not
  prove it; EPSS is a prediction, not an observation.

### Decision point 2: Automatable?
Could an attacker chain reconnaissance → exploitation → post-exploitation
without human interaction per target? Reason from the decoded CVSS vector
and the vulnerability class:
- Leans **yes**: attack_vector=network, privileges_required=none,
  user_interaction=none, attack_complexity=low; wormable classes
  (unauth RCE in a listening service, SSRF, auth bypass on an API).
- Leans **no**: user_interaction=required, physical/local vector, complex
  preconditions (non-default config, race conditions, credentials needed).

### Decision point 3: Technical impact
- **total** — attacker gains full control of the component (RCE, auth
  bypass to admin, full memory disclosure of secrets).
- **partial** — limited disclosure, DoS, constrained write, low-privilege
  foothold requiring further chaining.

## Step 3 — Ask the user for environmental context

The deployer tree requires **Mission & Well-being impact** (and exposure
helps calibrate it). If not already known from the conversation, ask:

1. Where does the affected asset sit? (internet-facing / internal / isolated)
2. What happens to the business if this asset is compromised or offline?
   (mission-essential / supporting / minimal)
3. Any mitigating controls? (WAF rules, segmentation, feature disabled,
   compensating detection)

Map answers to Mission & Well-being: **low / medium / high**. If the user
can't answer, run the tree under the most plausible assumption AND show how
the decision changes under the alternatives — a sensitivity analysis is more
useful than a stalled triage.

## Step 4 — Walk the tree

CISA SSVC tree outcomes (per the CISA SSVC Guide decision table), condensed:

| Exploitation | Automatable | Tech impact | Mission low | medium | high |
|---|---|---|---|---|---|
| none | no | partial | Track | Track | Track |
| none | no | total | Track | Track | Track* |
| none | yes | partial | Track | Track | Attend |
| none | yes | total | Track | Track | Attend |
| poc | no | partial | Track | Track | Track* |
| poc | no | total | Track | Track* | Attend |
| poc | yes | partial | Track | Track | Attend |
| poc | yes | total | Track | Track* | Attend |
| active | no | partial | Track | Track | Attend |
| active | no | total | Track | Attend | Act |
| active | yes | partial | Attend | Attend | Act |
| active | yes | total | Attend | Act | Act |

Decision meanings:
- **Act** — remediate as an emergency; leadership involvement; out-of-band
  patching or take the asset offline. If KEV lists a `due_date`, cite it.
- **Attend** — remediate ahead of normal cadence; notify affected teams.
- **Track\*** — no immediate action, but monitor closely for changes
  (recheck EPSS/KEV weekly; a delta here should re-trigger triage).
- **Track** — remediate within standard patch cycle.

## Step 5 — Report

ALWAYS use this exact output structure:

```
## Triage: <CVE> — <short name>

**Decision: <ACT | ATTEND | TRACK* | TRACK>**

**Decision inputs**
- Exploitation: <value> — <evidence: KEV date added / EPSS score+percentile+date / exploit refs>
- Automatable: <yes/no> — <reasoning from decoded CVSS vector + vuln class>
- Technical impact: <total/partial> — <reasoning>
- Mission & well-being: <low/med/high> — <user-provided context or stated assumption>

**What this means**
<2-4 sentences: the action, the timeline, and the single most important
driver of the decision. If severity and exploitation evidence disagree,
explain the disagreement here.>

**Would change this decision**
<1-3 bullets: e.g. "KEV addition or EPSS crossing ~0.10 → escalates to Attend";
"confirmation that the WAF rule blocks the exploit path → de-escalates">

**Sources**
<each source with its data date>
```

If CISA's ADP SSVC assessment exists and differs from yours, note the
difference and explain it (almost always: they lack your environmental
context — that's the point of stakeholder-specific scoring).

## Batch mode

For a list of CVEs, run scripts in batch (EPSS and KEV accept multiple IDs),
apply the tree per CVE, and return a table sorted Act → Attend → Track* →
Track, followed by one-line rationale per CVE. Offer the full per-CVE
breakdown for any the user wants to drill into.
