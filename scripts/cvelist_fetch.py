#!/usr/bin/env python3
"""Fetch the authoritative CVE record from the CVEProject cvelistV5 GitHub
repository (raw JSON, no API key, no GitHub token needed).

Useful when NVD is lagging or rate-limited: cvelistV5 is the CNA-published
source of truth and often carries affected-version data and ADP-enriched
content (including CISA-ADP SSVC assessments) before NVD analysis lands.

Usage:
  python3 cvelist_fetch.py CVE-2024-3400

Output: JSON to stdout. Exit 0 success, 1 error, 2 not found.
Repo: https://github.com/CVEProject/cvelistV5
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request

RAW = ("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
       "{year}/{bucket}/{cve}.json")
UA = "vuln-analyst-agent/1.0 (open-source)"


def bucket_for(cve: str) -> str:
    """cvelistV5 shards by thousands: CVE-2024-3400 -> 3xxx."""
    num = cve.split("-")[2]
    if len(num) <= 3:
        return "0xxx"
    return num[:-3] + "xxx"


def main() -> int:
    ap = argparse.ArgumentParser(description="cvelistV5 record fetch")
    ap.add_argument("cve", help="CVE ID, e.g. CVE-2024-3400")
    args = ap.parse_args()
    cve = args.cve.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        print(json.dumps({"error": f"invalid CVE id: {cve}"}), file=sys.stderr)
        return 1

    year = cve.split("-")[1]
    url = RAW.format(year=year, bucket=bucket_for(cve), cve=cve)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as resp:
            record = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(json.dumps({"cve": cve, "found": False,
                              "source": "cvelistV5"}))
            return 2
        print(json.dumps({"error": str(e), "source": "cvelistV5"}),
              file=sys.stderr)
        return 1
    except Exception as e:
        print(json.dumps({"error": str(e), "source": "cvelistV5"}),
              file=sys.stderr)
        return 1

    cna = record.get("containers", {}).get("cna", {})
    adps = record.get("containers", {}).get("adp", [])

    desc = next((d.get("value") for d in cna.get("descriptions", [])
                 if d.get("lang", "").startswith("en")), "")

    affected = [{
        "vendor": a.get("vendor"),
        "product": a.get("product"),
        "platforms": a.get("platforms", []),
        "versions": a.get("versions", []),
        "default_status": a.get("defaultStatus"),
    } for a in cna.get("affected", [])]

    # Surface ADP enrichment — notably CISA's SSVC assessment when present.
    ssvc = None
    kev_flag = None
    for adp in adps:
        for m in adp.get("metrics", []):
            other = m.get("other", {})
            if other.get("type") == "ssvc":
                ssvc = other.get("content")
            if other.get("type") == "kev":
                kev_flag = other.get("content")

    refs = [{"url": r.get("url"), "tags": r.get("tags", [])}
            for r in cna.get("references", [])]
    exploit_refs = [r for r in refs if "exploit" in (r.get("tags") or [])]

    print(json.dumps({
        "source": "cvelistV5 (CVEProject)",
        "cve": cve,
        "found": True,
        "state": record.get("cveMetadata", {}).get("state"),
        "assigner": record.get("cveMetadata", {}).get("assignerShortName"),
        "date_published": record.get("cveMetadata", {}).get("datePublished"),
        "date_updated": record.get("cveMetadata", {}).get("dateUpdated"),
        "title": cna.get("title", ""),
        "description": desc,
        "affected": affected,
        "problem_types": [
            d.get("description")
            for pt in cna.get("problemTypes", [])
            for d in pt.get("descriptions", [])
        ],
        "cisa_adp_ssvc": ssvc,
        "cisa_adp_kev": kev_flag,
        "exploit_tagged_references": exploit_refs,
        "references": refs[:25],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
