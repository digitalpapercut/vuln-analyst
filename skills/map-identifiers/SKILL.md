---
name: map-identifiers
description: >
  Deconflict and cross-map vulnerability identifiers across ecosystems —
  CVE ↔ GHSA ↔ OSV ↔ distro advisories (Debian DSA, RHSA, USN) — and
  determine whether two findings from different tools refer to the same
  underlying vulnerability. Use this skill whenever a user has identifiers
  from multiple systems ("my scanner says CVE-X but Dependabot says
  GHSA-Y — same thing?"), asks what CVE corresponds to a GHSA/OSV/vendor
  advisory ID or vice versa, asks whether a distro's backported package is
  actually affected, or needs to reconcile duplicate-looking findings across
  tools.
---

# Identifier Mapping & Deconfliction

Different tools speak different identifier dialects. This skill establishes
whether IDs are aliases of one underlying vulnerability and reconciles
affected-version claims across ecosystems.

## Core lookups

```bash
# Any ID (CVE, GHSA, OSV, PYSEC, DSA, RUSTSEC...) → canonical record + aliases
python3 scripts/osv_lookup.py id <ID>

# All known vulns for a package (optionally a specific version)
python3 scripts/osv_lookup.py package <name> --ecosystem <npm|PyPI|Go|Maven|crates.io|Debian|...> [--version <v>]

# Authoritative CVE-side record for cross-checking
python3 scripts/cvelist_fetch.py <CVE>
```

The OSV `aliases` array is the primary equivalence signal; `related` means
connected-but-distinct (e.g., same root cause, different CVE per product) —
never treat `related` as "same vulnerability."

## Deconfliction procedure ("are these the same finding?")

1. Fetch each identifier's record.
2. **Same** if either appears in the other's `aliases` (directly or through
   a shared alias).
3. If not aliased, compare: CWE/problem type, affected package and version
   ranges, publication window, and description substance. Report a judgment
   with confidence ("distinct CVEs for the same underlying flaw in different
   forks" is a common pattern — say so when you see it).
4. Beware **split/merge history**: some advisories cover multiple CVEs; some
   CVEs are rejected/merged. Check `state` in cvelistV5 (REJECTED records
   still haunt scanner databases).

## Distro backport reality check

A scanner flagging `openssl 1.1.1k` on RHEL as vulnerable to a CVE "fixed in
1.1.1l" is often wrong: distros backport fixes without bumping upstream
versions.

1. Query OSV with the distro ecosystem (e.g. `--ecosystem Debian` — OSV
   carries distro advisory data for several ecosystems).
2. If web search is available, check the distro security tracker
   (Debian security-tracker, Red Hat CVE pages, Ubuntu CVE tracker) for the
   distro's own fixed-version and status (`not-affected`, `DNE`, etc.).
3. Report the answer in terms of the *distro package version*, not the
   upstream version, and name the source. If you cannot confirm, say the
   finding may be a backport false positive and give the user the exact
   tracker URL to verify — do not guess.

## Output format

For a mapping request:

```
## Identifier map: <primary ID>

**Canonical set** (aliases — same vulnerability)
- <ID> (<database>) — <role: CNA record / GitHub advisory / distro advisory>

**Related but distinct**
- <ID> — <relationship, e.g. "same root cause, affects forked package">

**Affected versions by source**
- <source>: <package> <range>
- <conflicts, and which source to trust for which ecosystem>

**Verdict** — <one or two sentences answering the user's actual question>
```

For version-affected questions, lead with a yes/no/unconfirmed verdict for
the user's exact package+version, then the evidence.
