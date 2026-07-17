# Security Policy

## Reporting a vulnerability

If you find a security issue in this project (script injection, unsafe
handling of fetched data, harness sandbox escape, etc.), please report it
privately via GitHub Security Advisories on this repository rather than a
public issue. Expect an acknowledgment within 7 days.

## Security model

This project is **read-only research tooling** by design:

- Data scripts only perform GET/POST reads against public vulnerability
  data APIs. They take no remediation actions and touch no systems of yours.
- The standalone harness restricts the model to three actions: running
  whitelisted scripts in `scripts/` (arguments sanitized, executed without
  shell interpretation, with timeouts), reading skill files, and answering.
- No credentials are required for data sources. The optional `NVD_API_KEY`
  and model-provider keys are read from environment variables and never
  written to disk or logs by this project.

## Things users should know

- **Fetched data is untrusted input.** Vulnerability descriptions and
  advisory text originate from third parties. The agent definition instructs
  the model to treat retrieved content as data, not instructions; if you
  build on this project, preserve that property.
- **Network egress**: the scripts contact only the domains listed in the
  README's egress table. Pin your allowlist to those.
- **Caches**: KEV and exploit-index caches are written to the system temp
  directory and contain only public data.
