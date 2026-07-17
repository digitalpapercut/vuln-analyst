# Example session: SSVC triage

Illustrative transcript (data values are representative — the agent always
fetches live values at run time).

---

**User:** Our scanner flagged CVE-2024-3400 on two PAN-OS firewalls. How
worried should we be?

**Agent:** *(runs `epss_lookup.py`, `kev_check.py`, `nvd_fetch.py`,
`cvelist_fetch.py`)*

Before I give you a verdict, two quick questions since the decision depends
on your environment:

1. Are these firewalls internet-facing with GlobalProtect enabled?
2. If one were compromised, what's behind it — is this the perimeter for
   production?

**User:** Yes, both internet-facing with GlobalProtect. One fronts
production, the other is a lab.

**Agent:**

## Triage: CVE-2024-3400 — PAN-OS GlobalProtect command injection

**Decision: ACT** (production firewall) / **ATTEND** (lab firewall)

**Decision inputs**
- Exploitation: **active** — in CISA KEV (added 2024-04-12); exploitation
  in the wild reported prior to patch availability
- Automatable: **yes** — CVSS vector AV:N/AC:L/PR:N/UI:N decodes to
  network-reachable, no credentials, no user interaction; unauthenticated
  command injection in a listening service is scan-and-exploit territory
- Technical impact: **total** — unauthenticated root-level command
  execution on the firewall itself
- Mission & well-being: **high** (production perimeter) / **medium** (lab)

**What this means**
Active exploitation + automatable + total control of a perimeter device is
the worst cell of the SSVC tree. Treat the production firewall as an
emergency: apply the vendor hotfix out-of-band today, and because
exploitation predated the patch, follow Palo Alto's compromise-assessment
guidance rather than assuming patching closes the incident. The lab unit
should be patched ahead of normal cadence.

**Would change this decision**
- Disabling GlobalProtect / removing internet exposure → production drops to Attend
- Evidence of compromise found → shifts from vulnerability management to incident response

**Sources**
- CISA KEV (catalog as of run date), FIRST EPSS (score/percentile as of run
  date), NVD, cvelistV5, Palo Alto advisory PAN-SA-2024-0004

Want the exec summary and the remediation ticket? I can also draft the
compromise-assessment checklist as a ticket for the SOC.
