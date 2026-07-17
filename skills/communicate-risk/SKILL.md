---
name: communicate-risk
description: >
  Turn vulnerability analysis into audience-ready writeups — executive
  summaries, remediation tickets for patching/dev teams, and risk-acceptance
  or deferral memos. Use this skill whenever a user asks to "write this up",
  "summarize for leadership", "draft a ticket", "explain to the app team",
  "document why we're not patching", or needs the same finding communicated
  to a non-security audience.
---

# Risk Communication

Same evidence, different audiences. Never send an engineer an executive
summary or an executive a CVSS vector.

If analysis hasn't been done yet in this conversation, run `enrich-cve`
(and `triage-ssvc` if a decision is needed) first — writeups are downstream
of evidence, and every factual claim in a writeup must trace to a fetched
source.

## Executive summary (leadership / CISO briefing)

- ≤ 200 words. No CVE jargon in the first sentence — lead with business
  exposure: what could happen, to which business capability, how likely.
- Translate metrics: "actively exploited by ransomware groups per CISA"
  beats "KEV-listed, knownRansomwareCampaignUse: Known".
- One clear ask: the decision or resource needed, with a date.
- Structure: **Situation → Exposure → Action underway → Ask.**

## Remediation ticket (patching / dev team)

- Title: `[<Decision>] <CVE> in <component> — <action> by <date>`
- Body: affected asset(s) and exact versions; fixed version or workaround
  (from vendor advisory); why now (exploitation evidence, one line);
  validation step (how to confirm remediation); rollback consideration if
  the fix is disruptive.
- Everything an engineer needs to act without opening five browser tabs,
  and nothing they don't.

## Risk-acceptance / deferral memo

The writeup most tools can't produce and auditors most want to see:

- **Finding** — CVE, asset, severity, exploitation status (dated).
- **Decision** — accept / defer to <date>, and who owns the decision.
- **Rationale** — compensating controls, exposure limits, business
  constraint. Be specific: "asset is on an isolated VLAN with no inbound
  routes" not "low risk".
- **Conditions that void this acceptance** — e.g. KEV addition, EPSS
  crossing a threshold, control removal, architecture change. Pull these
  directly from the triage's "would change this decision" section.
- **Review date.**

## Rules

- State the data date on every metric ("EPSS 0.91 as of 2026-07-14").
- Keep uncertainty visible in all formats — executives get "we have not
  confirmed exploitability in our configuration", not silence.
- Offer all applicable formats when the audience is unspecified, but ask
  once rather than generating three documents nobody requested.
