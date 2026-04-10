#!/usr/bin/env python3
"""ZPA Status Mini-SIEM — management CLI.

Commands:
    health    Check for missing reports vs available log files
    regen     Regenerate the report for a specific date

Usage:
    zpa-siem-ctl health [--days N]
    zpa-siem-ctl regen YYYY-MM-DD
"""

import argparse
import glob
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta

from config import Config


def find_log_dates(log_dir: str) -> set[str]:
    """Scan log_dir and return the set of YYYY-MM-DD data dates covered by rotated logs.

    Each rotated file zpa.log-YYYYMMDD primarily contains data from the
    day BEFORE the rotation date (~03:00 → 23:59).  We only claim that
    primary date — the early morning hours (00:00 → ~03:00) are a small
    supplement covered by the previous file.  This avoids false positives
    where a date appears "covered" but only has a few hours of data
    from a single file.
    """
    date_re = re.compile(r"zpa\.log-(\d{8})(\.gz)?$")
    dates = set()
    for path in glob.glob(os.path.join(log_dir, "zpa.log-*")):
        m = date_re.search(os.path.basename(path))
        if not m:
            continue
        rotation_date = datetime.strptime(m.group(1), "%Y%m%d")
        # Primary data date: the day before rotation
        dates.add((rotation_date - timedelta(days=1)).strftime("%Y-%m-%d"))
    return dates


def find_reports(output_dir: str) -> set[str]:
    """Return set of YYYY-MM-DD dates that have a generated report."""
    date_re = re.compile(r"(\d{4}-\d{2}-\d{2})")
    dates = set()
    if not os.path.isdir(output_dir):
        return dates
    for fname in os.listdir(output_dir):
        if not fname.endswith(".xlsx"):
            continue
        m = date_re.search(fname)
        if m:
            dates.add(m.group(1))
    return dates


def cmd_health(args, config: Config) -> int:
    """Check for gaps: days with logs but no report."""
    log_dir = args.log_dir or config.log_dir
    output_dir = args.output_dir or config.output_dir
    days = args.days

    log_dates = find_log_dates(log_dir)
    reports = find_reports(output_dir)

    if not log_dates:
        print("No rotated log files found in", log_dir)
        return 0

    # Don't check today (report not due yet)
    today = datetime.now().strftime("%Y-%m-%d")
    log_dates.discard(today)

    all_dates = sorted(log_dates)

    # Limit to last N days if requested
    if days:
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        all_dates = [d for d in all_dates if d >= cutoff]

    if not all_dates:
        print("No log files in the requested range.")
        return 0

    print(f"Checking {len(all_dates)} days ({all_dates[0]} to {all_dates[-1]})")
    print(f"  Log directory:    {log_dir}")
    print(f"  Report directory: {output_dir}")
    print()

    missing = []
    ok_count = 0
    for date in all_dates:
        if date in reports:
            ok_count += 1
        else:
            missing.append(date)

    if not missing:
        print(f"All {ok_count} days have reports. No gaps found.")
        return 0

    print(f"OK: {ok_count} days with reports")
    print(f"MISSING: {len(missing)} days with logs but no report:\n")
    for date in missing:
        print(f"  {date}")

    print(f"\nTo regenerate, run:")
    if len(missing) == 1:
        print(f"  zpa-siem-ctl regen {missing[0]}")
    else:
        print(f"  zpa-siem-ctl regen {missing[0]}   # one at a time")
        print(f"  zpa-siem-ctl regen --all             # all missing days")

    return 1


def cmd_regen(args, config: Config) -> int:
    """Regenerate report(s) for specific date(s)."""
    log_dir = args.log_dir or config.log_dir
    output_dir = args.output_dir or config.output_dir

    # Determine which dates to regenerate
    if args.all_missing:
        log_dates = find_log_dates(log_dir)
        today = datetime.now().strftime("%Y-%m-%d")
        log_dates.discard(today)
        reports = find_reports(output_dir)
        dates = sorted(d for d in log_dates if d not in reports)
        if not dates:
            print("No missing reports to regenerate.")
            return 0
        print(f"Regenerating {len(dates)} missing reports...")
    elif args.date:
        dates = [args.date]
    else:
        print("ERROR: specify a date (YYYY-MM-DD) or --all", file=sys.stderr)
        return 1

    # Find the report_generator.py script (same directory as this script)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    generator = os.path.join(script_dir, "report_generator.py")
    if not os.path.exists(generator):
        print(f"ERROR: report_generator.py not found at {generator}", file=sys.stderr)
        return 1

    python = sys.executable
    failures = 0

    for date in dates:
        print(f"\n  {date}: regenerating...")

        # Use --date to let report_generator find all relevant log files
        cmd = [
            python, generator,
            "--date", date,
            "--log-dir", log_dir,
            "--output-dir", output_dir,
        ]
        if args.config:
            cmd += ["--config", args.config]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                print(f"    {line}")
            print(f"  {date}: OK")
        else:
            print(f"  {date}: FAILED (exit {result.returncode})")
            for line in (result.stderr or result.stdout).strip().splitlines():
                print(f"    {line}")
            failures += 1

    print()
    total = len(dates)
    ok = total - failures
    if failures:
        print(f"Done: {ok}/{total} reports generated ({failures} failed)")
        return 1
    print(f"Done: {ok}/{total} reports generated successfully.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="zpa-siem-ctl",
        description="ZPA Status Mini-SIEM management tool",
    )
    parser.add_argument("--config", default=None, help="Path to config.ini")
    parser.add_argument("--log-dir", default=None, help="Override log directory")
    parser.add_argument("--output-dir", default=None, help="Override report output directory")

    sub = parser.add_subparsers(dest="command")

    # health
    health_p = sub.add_parser("health", help="Check for missing reports")
    health_p.add_argument("--days", type=int, default=None,
                          help="Only check the last N days (default: all)")

    # regen
    regen_p = sub.add_parser("regen", help="Regenerate report for a date")
    regen_p.add_argument("date", nargs="?", help="Date to regenerate (YYYY-MM-DD)")
    regen_p.add_argument("--all", dest="all_missing", action="store_true",
                         help="Regenerate all missing reports")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    config = Config(args.config)

    if args.command == "health":
        return cmd_health(args, config)
    elif args.command == "regen":
        return cmd_regen(args, config)


if __name__ == "__main__":
    sys.exit(main())
