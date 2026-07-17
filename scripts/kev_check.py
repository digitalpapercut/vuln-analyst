#!/usr/bin/env python3
"""Check CVE(s) against the CISA Known Exploited Vulnerabilities catalog.

Downloads the KEV JSON feed (no API key) and caches it locally for 6 hours.

Usage:
  python3 kev_check.py CVE-2024-3400
  python3 kev_check.py CVE-2024-3400 CVE-2021-44228
  python3 kev_check.py --recent 14          # entries added in last N days
  python3 kev_check.py --refresh CVE-...    # force cache refresh

Output: JSON to stdout. Exit 0 on success, 1 on error.
Feed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
import argparse
import datetime as dt
import json
import os
import sys
import tempfile
import time
import urllib.request

FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json")
CACHE = os.path.join(tempfile.gettempdir(), "cisa_kev_cache.json")
CACHE_TTL_SECONDS = 6 * 3600
UA = "vuln-analyst-agent/1.0 (open-source)"


def load_catalog(force_refresh: bool = False) -> dict:
    if (not force_refresh and os.path.exists(CACHE)
            and time.time() - os.path.getmtime(CACHE) < CACHE_TTL_SECONDS):
        with open(CACHE, "r", encoding="utf-8") as f:
            return json.load(f)
    req = urllib.request.Request(FEED, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
    data = json.loads(raw.decode("utf-8"))
    try:
        with open(CACHE, "wb") as f:
            f.write(raw)
    except OSError:
        pass  # caching is best-effort
    return data


def entry_summary(v: dict) -> dict:
    return {
        "cve": v.get("cveID"),
        "in_kev": True,
        "vendor": v.get("vendorProject"),
        "product": v.get("product"),
        "name": v.get("vulnerabilityName"),
        "date_added": v.get("dateAdded"),
        "due_date": v.get("dueDate"),
        "known_ransomware_use": v.get("knownRansomwareCampaignUse"),
        "required_action": v.get("requiredAction"),
        "notes": v.get("notes", ""),
        "cwes": v.get("cwes", []),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="CISA KEV catalog check")
    ap.add_argument("cves", nargs="*", help="CVE IDs to check")
    ap.add_argument("--recent", type=int, metavar="DAYS",
                    help="List entries added in the last N days")
    ap.add_argument("--refresh", action="store_true",
                    help="Force re-download of the KEV feed")
    args = ap.parse_args()

    if not args.cves and args.recent is None:
        ap.error("provide CVE IDs and/or --recent DAYS")

    try:
        catalog = load_catalog(force_refresh=args.refresh)
    except Exception as e:
        print(json.dumps({"error": str(e), "source": "kev"}), file=sys.stderr)
        return 1

    vulns = catalog.get("vulnerabilities", [])
    by_cve = {v.get("cveID", "").upper(): v for v in vulns}
    out = {
        "source": "CISA KEV",
        "catalog_version": catalog.get("catalogVersion"),
        "date_released": catalog.get("dateReleased"),
        "total_entries": catalog.get("count", len(vulns)),
    }

    if args.cves:
        results = []
        for cve in (c.strip().upper() for c in args.cves):
            v = by_cve.get(cve)
            results.append(entry_summary(v) if v
                           else {"cve": cve, "in_kev": False})
        out["results"] = results

    if args.recent is not None:
        cutoff = dt.date.today() - dt.timedelta(days=args.recent)
        recent = [entry_summary(v) for v in vulns
                  if v.get("dateAdded", "") >= cutoff.isoformat()]
        recent.sort(key=lambda r: r["date_added"], reverse=True)
        out["recent_additions"] = recent
        out["recent_window_days"] = args.recent

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
