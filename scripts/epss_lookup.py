#!/usr/bin/env python3
"""Fetch EPSS score(s) from the FIRST.org EPSS API. No API key required.

Usage:
  python3 epss_lookup.py CVE-2024-3400
  python3 epss_lookup.py CVE-2024-3400 CVE-2023-44487
  python3 epss_lookup.py CVE-2024-3400 --history        # 30-day time series
  python3 epss_lookup.py CVE-2024-3400 --date 2026-06-01  # score on a past date

Output: JSON to stdout. Exit 0 on success, 1 on error, 2 if CVE not found.
Docs: https://api.first.org/epss/
"""
import argparse
import json
import sys
import urllib.parse
import urllib.request

API = "https://api.first.org/data/v1/epss"
UA = "vuln-analyst-agent/1.0 (open-source; +https://github.com/)"


def fetch(params: dict) -> dict:
    url = f"{API}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description="EPSS score lookup (FIRST.org)")
    ap.add_argument("cves", nargs="+", help="One or more CVE IDs")
    ap.add_argument("--history", action="store_true",
                    help="Include ~30-day score time series per CVE")
    ap.add_argument("--date", help="Score as of a specific date (YYYY-MM-DD)")
    args = ap.parse_args()

    cves = [c.strip().upper() for c in args.cves]
    params = {"cve": ",".join(cves)}
    if args.history:
        params["scope"] = "time-series"
    if args.date:
        params["date"] = args.date

    try:
        data = fetch(params)
    except Exception as e:  # network, HTTP, JSON errors
        print(json.dumps({"error": str(e), "source": "epss"}), file=sys.stderr)
        return 1

    rows = data.get("data", [])
    found = {r.get("cve"): r for r in rows}
    out = {
        "source": "FIRST.org EPSS",
        "model_date": data.get("access", ""),
        "results": [],
    }
    missing = []
    for cve in cves:
        r = found.get(cve)
        if not r:
            missing.append(cve)
            continue
        entry = {
            "cve": cve,
            "epss": float(r.get("epss", 0)),
            "percentile": float(r.get("percentile", 0)),
            "date": r.get("date"),
        }
        if args.history and "time-series" in r:
            entry["time_series"] = [
                {"date": t.get("date"), "epss": float(t.get("epss", 0)),
                 "percentile": float(t.get("percentile", 0))}
                for t in r["time-series"]
            ]
        out["results"].append(entry)
    if missing:
        out["not_found"] = missing

    print(json.dumps(out, indent=2))
    return 2 if missing and not out["results"] else 0


if __name__ == "__main__":
    sys.exit(main())
