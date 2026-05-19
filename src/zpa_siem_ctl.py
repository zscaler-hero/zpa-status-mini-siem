#!/usr/bin/env python3
"""ZPA Status Mini-SIEM — management CLI.

Commands:
    health        Check for missing reports vs available log files
    regen         Regenerate the report for a specific date (no auto-upload)
    test-share    Upload a file to the configured share to validate connectivity
    selftest      End-to-end production smoke test (no side effects)

Usage:
    zpa-siem-ctl health [--days N]
    zpa-siem-ctl regen YYYY-MM-DD
    zpa-siem-ctl regen --all [--force]
    zpa-siem-ctl test-share [--file PATH]
    zpa-siem-ctl selftest [--date YYYY-MM-DD] [--skip-share]
"""

import argparse
import glob
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta

from config import Config
from app_logger import setup_logging, get_logger

log = get_logger(__name__)


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
        if args.force:
            dates = sorted(log_dates)
            if not dates:
                print("No log dates available to regenerate.")
                return 0
            print(f"Regenerating {len(dates)} reports (--force: including existing)...")
        else:
            reports = find_reports(output_dir)
            dates = sorted(d for d in log_dates if d not in reports)
            if not dates:
                print("No missing reports to regenerate. Use --force to rebuild existing reports.")
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

        # Use --date to let report_generator find all relevant log files.
        # Always pass --no-upload: regen should never auto-push to the share —
        # use `zpa-siem-ctl test-share` (or a manual upload) to send a file.
        cmd = [
            python, generator,
            "--date", date,
            "--log-dir", log_dir,
            "--output-dir", output_dir,
            "--no-upload",
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
    if config.share_enabled:
        print("Note: share upload was skipped. Run `zpa-siem-ctl test-share` to verify upload.")
    return 0


def cmd_test_share(args, config: Config) -> int:
    """Upload a file to the configured share to verify connectivity.

    File selection priority:
      1. --file PATH (any file)
      2. Newest report in output_dir matching share_format (xlsx/csv)
      3. Auto-generated temp file with a timestamp marker
    """
    if not config.share_enabled:
        print("Share upload is disabled in config.ini.", file=sys.stderr)
        print("Enable it with: install.sh --configure", file=sys.stderr)
        return 1

    # Print resolved configuration so the user sees what's being tested
    print(f"Method: {config.share_method}")
    if config.share_method == "smb":
        print(f"  Share:    {config.smb_share}")
        print(f"  Username: {config.smb_username or '(none)'}")
        print(f"  Domain:   {config.smb_domain or '(none)'}")
    elif config.share_method == "scp":
        port = config.scp_port or "22"
        user_prefix = f"{config.scp_username}@" if config.scp_username else ""
        print(f"  Host:     {user_prefix}{config.scp_host}:{port}")
        print(f"  Path:     {config.scp_path}")
        if config.scp_password:
            print(f"  Auth:     password (sshpass)")
        else:
            print(f"  Auth:     SSH key")
    print(f"  Format:   {config.share_format}")
    print()

    # Pick a file to upload
    cleanup = None
    if args.file:
        if not os.path.exists(args.file):
            print(f"ERROR: file not found: {args.file}", file=sys.stderr)
            return 1
        upload_path = args.file
        source = "user-provided"
    else:
        output_dir = args.output_dir or config.output_dir
        ext = ".csv" if config.share_format == "csv" else ".xlsx"
        candidates = sorted(
            glob.glob(os.path.join(output_dir, f"*{ext}")),
            key=os.path.getmtime,
            reverse=True,
        )
        if candidates:
            upload_path = candidates[0]
            source = f"newest {ext} in {output_dir}"
        else:
            # No real reports — generate a small marker file
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=f"-zpa-siem-test-{ts}.txt", delete=False
            )
            tmp.write(f"ZPA Status Mini-SIEM share connectivity test\nTimestamp: {ts}\n")
            tmp.close()
            upload_path = tmp.name
            cleanup = tmp.name
            source = "auto-generated test file"

    print(f"Uploading: {os.path.basename(upload_path)} ({source})")

    # Import lazily so help/-h works without the dependency tree
    from share_upload import upload_report, delete_remote
    success, msg = upload_report(upload_path, config)

    if cleanup:
        try:
            os.unlink(cleanup)
        except OSError:
            pass
        # Also try to remove the auto-generated marker from the remote share
        if success:
            removed, rmsg = delete_remote(os.path.basename(upload_path), config)
            if removed:
                print(f"Remote cleanup: {rmsg}")
            else:
                print(f"Remote cleanup skipped: {rmsg}", file=sys.stderr)

    if success:
        print(f"OK: {msg}")
        return 0
    print(f"FAILED: {msg}", file=sys.stderr)
    return 1


def cmd_selftest(args, config: Config) -> int:
    """Production smoke test — verifies the whole pipeline without leaving artifacts.

    Steps:
      1. Config readable and required sections present
      2. App log directory writable (write + read back a marker line)
      3. Syslog source directory readable + at least one zpa.log* present
      4. Dry-run report generation on yesterday (or --date): parse + build sessions
         without writing any output file or attempting an upload
      5. Share connectivity (if enabled): upload a tiny marker file and remove it
         from the remote share (best-effort cleanup)

    Exit code 0 = all checks passed. Non-zero = at least one check failed.
    """
    failures: list[str] = []

    def step(name: str, ok: bool, detail: str = ""):
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] {name}{(' — ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    print("ZPA Status Mini-SIEM — selftest")
    print(f"  Config: {config.path}")
    print()

    # 1. Config sanity
    print("Config:")
    try:
        _ = config.log_dir
        _ = config.output_dir
        _ = config.timezone_name
        step("config readable", True, f"timezone={config.timezone_name}")
    except Exception as exc:
        step("config readable", False, str(exc))

    # 2. App log writability
    print("\nApp log:")
    log_path = os.path.join(config.app_log_dir, config.app_log_file)
    marker = f"selftest marker {datetime.now().strftime('%Y%m%dT%H%M%S')}"
    try:
        os.makedirs(config.app_log_dir, exist_ok=True)
        log.info("selftest: %s", marker)
        for h in log.parent.handlers:
            try:
                h.flush()
            except Exception:
                pass
        with open(log_path, "r", encoding="utf-8") as f:
            tail = f.read()[-4096:]
        step(
            f"writable {log_path}",
            marker in tail,
            "marker round-trip OK" if marker in tail else "marker not found in tail",
        )
    except OSError as exc:
        step(f"writable {log_path}", False, str(exc))

    # 3. Syslog source
    print("\nLog source:")
    log_dir = config.log_dir
    if not os.path.isdir(log_dir):
        step(f"directory {log_dir}", False, "missing")
    else:
        files = sorted(glob.glob(os.path.join(log_dir, "zpa.log*")))
        readable = [p for p in files if os.access(p, os.R_OK)]
        step(
            f"directory {log_dir}",
            bool(readable),
            f"{len(readable)}/{len(files)} files readable"
            if files else "no zpa.log* files present (no ZPA traffic yet?)",
        )

    # 4. Dry-run report generation (no files written, no upload)
    print("\nReport pipeline (dry-run):")
    target_date = args.date or (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    generator = os.path.join(script_dir, "report_generator.py")
    if not os.path.exists(generator):
        step("dry-run report", False, f"generator not found: {generator}")
    else:
        cmd = [
            sys.executable, generator,
            "--date", target_date,
            "--dry-run",
            "--log-dir", log_dir,
            "--output-dir", config.output_dir,
        ]
        if args.config:
            cmd += ["--config", args.config]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        ok = result.returncode == 0
        # Show a few key lines from stdout
        for line in (result.stdout or "").strip().splitlines()[-6:]:
            print(f"      {line}")
        if not ok:
            for line in (result.stderr or "").strip().splitlines()[-6:]:
                print(f"      {line}", file=sys.stderr)
        step(f"dry-run report for {target_date}", ok,
             f"exit={result.returncode}")

    # 5. Share upload + remote cleanup
    print("\nShare upload:")
    if not config.share_enabled:
        print("  [SKIP] share upload disabled in config")
    elif args.skip_share:
        print("  [SKIP] --skip-share flag set")
    else:
        from share_upload import upload_report, delete_remote
        ts = datetime.now().strftime("%Y%m%dT%H%M%S")
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=f"-zpa-siem-selftest-{ts}.txt", delete=False,
        )
        tmp.write(f"ZPA SIEM selftest {ts}\n")
        tmp.close()
        try:
            uploaded, umsg = upload_report(tmp.name, config)
            step("upload marker", uploaded, umsg)
            if uploaded:
                removed, rmsg = delete_remote(os.path.basename(tmp.name), config)
                # Remote cleanup failure does NOT fail the selftest — it's
                # best-effort. We surface the message so the operator can act.
                if removed:
                    print(f"  [OK  ] remote cleanup — {rmsg}")
                else:
                    print(f"  [WARN] remote cleanup left marker behind — {rmsg}")
                    print(f"         (please remove '{os.path.basename(tmp.name)}' manually)")
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    print()
    if failures:
        print(f"SELFTEST FAILED: {len(failures)} check(s) failed:")
        for name in failures:
            print(f"  - {name}")
        log.error("event=selftest_failed checks_failed=%d", len(failures))
        return 1
    print("SELFTEST OK — all checks passed.")
    log.info("event=selftest_ok")
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
    regen_p = sub.add_parser("regen", help="Regenerate report for a date (does not upload)")
    regen_p.add_argument("date", nargs="?", help="Date to regenerate (YYYY-MM-DD)")
    regen_p.add_argument("--all", dest="all_missing", action="store_true",
                         help="Regenerate all missing reports")
    regen_p.add_argument("--force", action="store_true",
                         help="With --all: rebuild every day with logs, including those that already have a report")

    # test-share
    test_p = sub.add_parser("test-share", help="Upload a file to the configured share to verify connectivity")
    test_p.add_argument("--file", default=None,
                        help="Specific file to upload (default: newest report in output_dir, or auto-generated test file)")

    # selftest
    selftest_p = sub.add_parser(
        "selftest",
        help="Production smoke test: config, log writability, log source, dry-run report, share connectivity",
    )
    selftest_p.add_argument("--date", default=None,
                            help="Date to dry-run (default: yesterday)")
    selftest_p.add_argument("--skip-share", action="store_true",
                            help="Skip the share connectivity check even if enabled")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    config = Config(args.config)
    setup_logging(config.app_log_dir, config.app_log_file)

    if args.command == "health":
        return cmd_health(args, config)
    elif args.command == "regen":
        return cmd_regen(args, config)
    elif args.command == "test-share":
        return cmd_test_share(args, config)
    elif args.command == "selftest":
        return cmd_selftest(args, config)


if __name__ == "__main__":
    sys.exit(main())
