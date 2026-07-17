---
name: explain-delta
description: >
  Explain WHY a vulnerability's risk picture changed — an EPSS score jump or
  drop, a new CISA KEV addition, a CVSS rescore, or a scanner suddenly
  reprioritizing a finding. Use this skill whenever a user asks "why did
  this CVE's score change", "why is this suddenly critical", "what changed
  since last week", "did anything new happen with CVE-X", or wants to review
  recent KEV additions relevant to them.
---

# Delta Explanation

Priority changes are signals; unexplained ones are noise. Reconstruct what
changed, when, and what most plausibly drove it.

## Gather the timeline

```bash
python3 scripts/epss_lookup.py <CVE> --history      # ~30-day daily series
python3 scripts/epss_lookup.py <CVE> --date <YYYY-MM-DD>  # older point-in-time
python3 scripts/kev_check.py <CVE>                  # date_added if listed
python3 scripts/kev_check.py --recent 14            # recent KEV additions
python3 scripts/nvd_fetch.py <CVE>                  # last_modified, rescores
python3 scripts/cvelist_fetch.py <CVE>              # date_updated, new refs
```

Locate the inflection date in the EPSS series, then look for co-timed
events: KEV addition, new exploit-tagged references, NVD modification,
vendor advisory update. If web search is available, check for exploitation
reporting, Metasploit/Nuclei additions, or Patch Tuesday coverage around
that date.

## Interpretation guide

- **EPSS spike (e.g. 0.04 → 0.60+)** — usually a discrete event: public PoC
  release, Metasploit module merge, Nuclei template, KEV addition, or mass
  exploitation reporting. Name the likely trigger if evidence supports it;
  otherwise say the driver is not publicly attributable (EPSS inputs are
  partially non-public — do not fabricate a cause).
- **EPSS gradual drift** — model retraining and ambient signal changes;
  usually not actionable by itself.
- **EPSS drop** — exploitation interest fading or model recalibration.
  Warn: a drop is NOT evidence an unpatched system became safe.
- **KEV addition** — the strongest single escalation signal; carries a
  federal remediation due date and sometimes a ransomware flag.
- **CVSS rescore / NVD modification** — new analysis or CNA update; compare
  old/new vectors if discoverable and translate the difference.

## Output format

```
## What changed: <CVE>

**The change** — <metric, from → to, dates>
**Most likely driver** — <event + evidence, or "not publicly attributable">
**Timeline**
- <date>: <event>
**So what** — <does this change the triage decision? If it crossed an SSVC
threshold (e.g. exploitation none → active), recommend re-running
triage-ssvc and say what the new outcome likely is.>
**Sources** — <with data dates>
```

For "anything new for me this week?" requests: run `kev_check.py --recent`,
filter against whatever product/stack context the user has provided, and
summarize only the relevant additions.
