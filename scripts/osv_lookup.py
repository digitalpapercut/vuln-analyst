#!/usr/bin/env python3
"""Query OSV.dev to map identifiers (CVE / GHSA / OSV / distro) and pull
affected-version ranges for open-source packages. No API key required.

Usage:
  python3 osv_lookup.py id CVE-2021-44228          # fetch by any known ID
  python3 osv_lookup.py id GHSA-jfh8-c2jp-5v3q
  python3 osv_lookup.py package lodash --ecosystem npm
  python3 osv_lookup.py package requests --ecosystem PyPI --version 2.19.0

Subcommands:
  id       Fetch a vulnerability record by identifier; returns aliases,
           related IDs, severity, and affected ranges.
  package  Query vulnerabilities affecting a package (optionally a version).

Output: JSON to stdout. Exit 0 success, 1 error, 2 not found.
Docs: https://google.github.io/osv.dev/api/
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

API_VULN = "https://api.osv.dev/v1/vulns/"
API_QUERY = "https://api.osv.dev/v1/query"
UA = "vuln-analyst-agent/1.0 (open-source)"


def http_get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_post(url: str, body: dict) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def summarize(v: dict, full: bool = False) -> dict:
    out = {
        "id": v.get("id"),
        "aliases": v.get("aliases", []),
        "related": v.get("related", []),
        "summary": v.get("summary", ""),
        "published": v.get("published"),
        "modified": v.get("modified"),
        "severity": v.get("severity", []),
        "references": [r.get("url") for r in v.get("references", [])][:15],
    }
    affected = []
    for a in v.get("affected", []):
        pkg = a.get("package", {})
        affected.append({
            "ecosystem": pkg.get("ecosystem"),
            "package": pkg.get("name"),
            "ranges": a.get("ranges", []),
            "versions_sample": a.get("versions", [])[:20],
            "ecosystem_specific": a.get("ecosystem_specific", {}),
            "database_specific": a.get("database_specific", {}) if full else {},
        })
    out["affected"] = affected
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="OSV.dev lookup")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_id = sub.add_parser("id", help="Fetch record by CVE/GHSA/OSV ID")
    p_id.add_argument("identifier")
    p_id.add_argument("--full", action="store_true",
                      help="Include database_specific blobs")

    p_pkg = sub.add_parser("package", help="Query vulns for a package")
    p_pkg.add_argument("name")
    p_pkg.add_argument("--ecosystem", required=True,
                       help="e.g. npm, PyPI, Go, Maven, crates.io, Debian")
    p_pkg.add_argument("--version", help="Specific version to check")

    args = ap.parse_args()

    try:
        if args.cmd == "id":
            ident = args.identifier.strip()
            try:
                v = http_get(API_VULN + urllib.parse.quote(ident))
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    print(json.dumps({"id": ident, "found": False,
                                      "source": "osv.dev"}))
                    return 2
                raise
            print(json.dumps({"source": "osv.dev", "found": True,
                              **summarize(v, full=args.full)}, indent=2))
            return 0

        # package query
        body = {"package": {"name": args.name, "ecosystem": args.ecosystem}}
        if args.version:
            body["version"] = args.version
        data = http_post(API_QUERY, body)
        vulns = data.get("vulns", [])
        print(json.dumps({
            "source": "osv.dev",
            "query": body,
            "count": len(vulns),
            "vulns": [summarize(v) for v in vulns],
        }, indent=2))
        return 0 if vulns else 2

    except Exception as e:
        print(json.dumps({"error": str(e), "source": "osv.dev"}),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
