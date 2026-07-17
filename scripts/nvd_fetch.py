#!/usr/bin/env python3
"""Fetch CVE details from the NVD 2.0 API: description, CVSS vectors,
CWEs, CPE applicability, and references.

No key required (5 req / 30s). Set NVD_API_KEY env var for higher limits.

Usage:
  python3 nvd_fetch.py CVE-2024-3400
  NVD_API_KEY=xxxx python3 nvd_fetch.py CVE-2024-3400

Output: JSON to stdout, including a decoded CVSS vector so downstream
reasoning doesn't have to memorize metric abbreviations.
Exit 0 success, 1 error, 2 not found.
Docs: https://nvd.nist.gov/developers/vulnerabilities
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "vuln-analyst-agent/1.0 (open-source)"

# CVSS v3.x metric decodings, so the agent reasons over words, not codes.
V3_METRICS = {
    "AV": ("attack_vector", {"N": "network", "A": "adjacent", "L": "local",
                             "P": "physical"}),
    "AC": ("attack_complexity", {"L": "low", "H": "high"}),
    "PR": ("privileges_required", {"N": "none", "L": "low", "H": "high"}),
    "UI": ("user_interaction", {"N": "none", "R": "required"}),
    "S": ("scope", {"U": "unchanged", "C": "changed"}),
    "C": ("confidentiality_impact", {"N": "none", "L": "low", "H": "high"}),
    "I": ("integrity_impact", {"N": "none", "L": "low", "H": "high"}),
    "A": ("availability_impact", {"N": "none", "L": "low", "H": "high"}),
}


def decode_vector(vector: str) -> dict:
    decoded = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        if k in V3_METRICS:
            name, values = V3_METRICS[k]
            decoded[name] = values.get(v, v)
    return decoded


def main() -> int:
    ap = argparse.ArgumentParser(description="NVD CVE detail fetch")
    ap.add_argument("cve", help="CVE ID, e.g. CVE-2024-3400")
    args = ap.parse_args()
    cve = args.cve.strip().upper()

    url = f"{API}?{urllib.parse.urlencode({'cveId': cve})}"
    headers = {"User-Agent": UA}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(json.dumps({"error": str(e), "source": "nvd",
                          "hint": "Unkeyed NVD access is rate-limited to "
                                  "5 requests per 30s; retry after a pause "
                                  "or set NVD_API_KEY."}), file=sys.stderr)
        return 1

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print(json.dumps({"cve": cve, "found": False, "source": "nvd"}))
        return 2

    c = vulns[0].get("cve", {})
    desc = next((d.get("value") for d in c.get("descriptions", [])
                 if d.get("lang") == "en"), "")

    cvss = []
    metrics = c.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                "cvssMetricV2"):
        for m in metrics.get(key, []):
            cd = m.get("cvssData", {})
            entry = {
                "version": cd.get("version"),
                "source": m.get("source"),
                "type": m.get("type"),
                "base_score": cd.get("baseScore"),
                "base_severity": cd.get("baseSeverity"),
                "vector": cd.get("vectorString"),
            }
            if cd.get("version", "").startswith("3"):
                entry["decoded"] = decode_vector(cd.get("vectorString", ""))
            cvss.append(entry)

    cwes = [d.get("value") for w in c.get("weaknesses", [])
            for d in w.get("description", []) if d.get("lang") == "en"]

    cpes = []
    for cfg in c.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpes.append({
                        "criteria": match.get("criteria"),
                        "version_start_including":
                            match.get("versionStartIncluding"),
                        "version_end_excluding":
                            match.get("versionEndExcluding"),
                        "version_end_including":
                            match.get("versionEndIncluding"),
                    })

    refs = [{"url": r.get("url"), "tags": r.get("tags", [])}
            for r in c.get("references", [])]

    print(json.dumps({
        "source": "NVD",
        "cve": cve,
        "found": True,
        "status": c.get("vulnStatus"),
        "published": c.get("published"),
        "last_modified": c.get("lastModified"),
        "description": desc,
        "cvss": cvss,
        "cwes": sorted(set(cwes)),
        "vulnerable_cpes": cpes[:40],
        "references": refs,
        "cisa_kev_hint": {
            "date_added": c.get("cisaExploitAdd"),
            "action_due": c.get("cisaActionDue"),
        } if c.get("cisaExploitAdd") else None,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
