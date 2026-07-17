# Contributing

Methodology improvements are as welcome as code — if you triage
vulnerabilities professionally and something here doesn't match how strong
analysts actually work, that's a bug. PRs against SKILL.md files need no
code at all.

## Ground rules

**Skills (`skills/*/SKILL.md`)**
- Keep the YAML frontmatter description specific about *when* the skill
  applies — it's the triggering mechanism.
- Methodology must be sourced: cite the framework document (e.g. the CISA
  SSVC Guide) for any decision logic.
- Output formats are contracts; change them deliberately and update
  `examples/`.

**Data scripts (`scripts/*.py`)**
- Python 3.8+ standard library only. No pip dependencies.
- Keyless by default; optional keys via environment variables only.
- JSON to stdout; errors to stderr; exit codes: 0 ok, 1 error, 2 not found.
- Include the API's documentation URL in the docstring.
- Cache heavyweight feeds to the temp directory with a TTL; never cache
  credentials or personal data.

**Harness (`harness/`)**
- Preserve the read-only property: no new action types that write, modify,
  or execute outside the scripts whitelist.

## New data sources

Open an issue first describing: what decision the source improves, its
access terms (must be free tier at minimum, keyless preferred), and rate
limits. Sources that only restate CVSS/EPSS/KEV data add noise, not signal.

## Testing

Run the offline checks (`python3 -m py_compile scripts/*.py harness/*.py`)
plus one live invocation per touched script against a known CVE (e.g.
CVE-2021-44228), and paste the output in the PR.
