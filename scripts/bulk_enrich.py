#!/usr/bin/env python3
"""Bulk-enrich a list of CVEs (a scanner export, a backlog, a spreadsheet
column) with EPSS + KEV + exploit-tooling signals, and emit a
prioritization-ready table. Keyless; batches API calls.

Usage:
  python3 bulk_enrich.py --file cves.txt              # one CVE per line (extra text ok)
  cat scanner_export.csv | python3 bulk_enrich.py -   # reads stdin, extracts CVE IDs
  python3 bulk_enrich.py --file cves.txt --csv out.csv

CVE IDs are extracted by pattern from whatever text is given, so raw scanner
CSV exports work without cleanup. Output rows are sorted by triage signal:
KEV+ransomware first, then KEV, then weaponized tooling, then EPSS desc.

Output: JSON to stdout (and optional CSV). Exit 0 success, 1 error,
2 if no CVE IDs found in input.
"""
import argparse
import csv
import json
import re
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
EPSS_BATCH = 100


def run_json(script, args):
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, script)] + args,
        capture_output=True, text=True, timeout=300)
    if not proc.stdout.strip():
        raise RuntimeError(f"{script}: {proc.stderr.strip()[:300]}")
    return json.loads(proc.stdout)


def main() -> int:
    ap = argparse.ArgumentParser(description="Bulk CVE enrichment")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="File containing CVE IDs (any format)")
    src.add_argument("stdin_flag", nargs="?", choices=["-"],
                     help="Read from stdin")
    ap.add_argument("--csv", help="Also write results to this CSV path")
    ap.add_argument("--no-exploit-signals", action="store_true",
                    help="Skip Nuclei/Metasploit index download (faster)")
    args = ap.parse_args()

    text = (open(args.file, encoding="utf-8", errors="replace").read()
            if args.file else sys.stdin.read())
    cves = sorted({m.upper() for m in CVE_RE.findall(text)})
    if not cves:
        print(json.dumps({"error": "no CVE IDs found in input"}),
              file=sys.stderr)
        return 2

    errors = []

    # EPSS in batches
    epss = {}
    for i in range(0, len(cves), EPSS_BATCH):
        chunk = cves[i:i + EPSS_BATCH]
        try:
            data = run_json("epss_lookup.py", chunk)
            for r in data.get("results", []):
                epss[r["cve"]] = r
        except Exception as e:
            errors.append(f"epss batch {i // EPSS_BATCH}: {e}")

    # KEV in one shot (local catalog filter)
    kev = {}
    try:
        data = run_json("kev_check.py", cves)
        for r in data.get("results", []):
            kev[r["cve"]] = r
    except Exception as e:
        errors.append(f"kev: {e}")

    # Exploit tooling signals
    tooling = {}
    if not args.no_exploit_signals:
        try:
            data = run_json("exploit_signals.py", cves)
            for r in data.get("results", []):
                tooling[r["cve"]] = r
        except Exception as e:
            errors.append(f"exploit_signals: {e}")

    rows = []
    for c in cves:
        e, k, t = epss.get(c, {}), kev.get(c, {}), tooling.get(c, {})
        rows.append({
            "cve": c,
            "in_kev": bool(k.get("in_kev")),
            "kev_ransomware": (k.get("known_ransomware_use") == "Known"),
            "kev_due_date": k.get("due_date"),
            "epss": e.get("epss"),
            "epss_percentile": e.get("percentile"),
            "nuclei_template": bool(t.get("nuclei_template")),
            "metasploit_module": bool(t.get("metasploit_module")),
        })

    rows.sort(key=lambda r: (
        not r["kev_ransomware"],
        not r["in_kev"],
        not (r["nuclei_template"] or r["metasploit_module"]),
        -(r["epss"] or 0.0),
        r["cve"],
    ))

    out = {"count": len(rows), "results": rows}
    if errors:
        out["errors"] = errors

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        out["csv_written"] = args.csv

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
