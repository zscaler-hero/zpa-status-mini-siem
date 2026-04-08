#!/usr/bin/env python3
"""ZPA Status Mini-SIEM — Daily Report Generator.

Reads ZPA syslog files, extracts user sessions, and generates Excel + JSON reports.

Usage:
    python3 report_generator.py                        # process yesterday's log
    python3 report_generator.py --log-file path.log    # process a specific file
    python3 report_generator.py --output-dir ./reports  # custom output directory
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from session_parser import REPORT_COLUMNS, build_sessions, parse_log_file
from config import Config


# --- Excel generation ---


def generate_excel(sessions: list[dict], output_path: str) -> None:
    """Generate the Excel report from consolidated sessions."""
    wb = Workbook()
    ws = wb.active
    ws.title = "ZPA Sessions"

    header_font = Font(bold=True, color="FFFFFF", size=11)
    header_fill = PatternFill(start_color="2F5496", end_color="2F5496", fill_type="solid")
    header_alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    thin_border = Border(
        left=Side(style="thin"),
        right=Side(style="thin"),
        top=Side(style="thin"),
        bottom=Side(style="thin"),
    )
    active_fill = PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid")

    for col_idx, col_name in enumerate(REPORT_COLUMNS, 1):
        cell = ws.cell(row=1, column=col_idx, value=col_name)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
        cell.border = thin_border

    for row_idx, session in enumerate(sessions, 2):
        is_active = session["Session End"] == "In corso"
        for col_idx, col_name in enumerate(REPORT_COLUMNS, 1):
            value = session[col_name]
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = thin_border
            cell.alignment = Alignment(horizontal="center" if col_name != "Username" else "left")
            if is_active:
                cell.fill = active_fill

    for col_idx in range(1, len(REPORT_COLUMNS) + 1):
        col_letter = get_column_letter(col_idx)
        max_len = len(REPORT_COLUMNS[col_idx - 1])
        for row in ws.iter_rows(min_row=2, max_row=ws.max_row, min_col=col_idx, max_col=col_idx):
            for cell in row:
                if cell.value:
                    max_len = max(max_len, len(str(cell.value)))
        ws.column_dimensions[col_letter].width = min(max_len + 3, 40)

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(REPORT_COLUMNS))}{ws.max_row}"

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    wb.save(output_path)


# --- JSON generation ---


def generate_json(sessions: list[dict], output_path: str, timezone_name: str) -> None:
    """Generate the JSON report from consolidated sessions."""
    report = {
        "report_date": sessions[0]["Date"] if sessions else "",
        "timezone": timezone_name,
        "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "sessions": [
            {
                "username": s["Username"],
                "date": s["Date"],
                "session_start": s["Session Start"],
                "session_end": s["Session End"],
                "duration": s["Duration"],
                "public_ip": s["Public IP"],
                "private_ip": s["Private IP"],
                "city": s["City"],
                "country": s["Country"],
                "device": s["Device"],
                "platform": s["Platform"],
                "client_version": s["Client Version"],
                "trusted_network": s["Trusted Network"],
                "bytes_rx": s["Bytes Rx"],
                "bytes_tx": s["Bytes Tx"],
            }
            for s in sessions
        ],
    }
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


# --- Retention cleanup ---


def cleanup_old_reports(output_dir: str, retention_days: int) -> None:
    """Delete report files older than retention_days."""
    if retention_days <= 0:
        return
    cutoff = datetime.now() - timedelta(days=retention_days)
    date_pattern = re.compile(r"(\d{4}-\d{2}-\d{2})")

    for filename in os.listdir(output_dir):
        if not (filename.endswith(".xlsx") or filename.endswith(".json")):
            continue
        match = date_pattern.search(filename)
        if not match:
            continue
        try:
            file_date = datetime.strptime(match.group(1), "%Y-%m-%d")
        except ValueError:
            continue
        if file_date < cutoff:
            filepath = os.path.join(output_dir, filename)
            os.remove(filepath)
            print(f"  Cleaned up old report: {filename}")


# --- Main ---


def get_rotated_log_path(log_dir: str) -> tuple[str, str]:
    """Get the path to the most recent rotated log file and its report date.

    logrotate with dateext names the rotated file with TODAY's date
    (the date of rotation), not yesterday's. The file contains
    yesterday's log data.

    Returns (log_path, report_date) where report_date is yesterday's
    date in YYYY-MM-DD format (the date the logs cover).
    """
    yesterday = datetime.now() - timedelta(days=1)
    report_date = yesterday.strftime("%Y-%m-%d")

    # logrotate uses the rotation date (today) in the filename
    today = datetime.now().strftime("%Y%m%d")
    today_path = os.path.join(log_dir, f"zpa.log-{today}")
    if os.path.exists(today_path):
        return today_path, report_date

    # Fallback: try yesterday's date in filename
    yesterday_fmt = yesterday.strftime("%Y%m%d")
    return os.path.join(log_dir, f"zpa.log-{yesterday_fmt}"), report_date


def main():
    config = Config()

    parser = argparse.ArgumentParser(description="ZPA Status Mini-SIEM Report Generator")
    parser.add_argument("--log-file", help="Path to log file to process (default: yesterday's rotated log)")
    parser.add_argument("--log-dir", default=config.log_dir, help="Directory containing log files")
    parser.add_argument("--output-dir", default=config.output_dir, help="Directory for output reports")
    parser.add_argument("--output-file", help="Specific output file path (overrides --output-dir)")
    parser.add_argument("--timezone", default=config.timezone_name, help="Timezone for report timestamps")
    parser.add_argument("--config", default=None, help="Path to config.ini file")
    args = parser.parse_args()

    # Reload config if custom path specified
    if args.config:
        config = Config(args.config)

    from zoneinfo import ZoneInfo
    tz = ZoneInfo(args.timezone)
    print(f"Timezone: {args.timezone}")

    # Determine input file and report date
    if args.log_file:
        log_path = args.log_file
        # For manual runs, derive report date from the log filename or use today
        date_match = re.search(r"(\d{4})(\d{2})(\d{2})", os.path.basename(log_path))
        if date_match:
            y, m, d = date_match.groups()
            report_date = f"{y}-{m}-{d}"
        else:
            report_date = datetime.now().strftime("%Y-%m-%d")
    else:
        log_path, report_date = get_rotated_log_path(args.log_dir)

    if not os.path.exists(log_path):
        print(f"ERROR: Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading log file: {log_path}")
    print(f"Report date: {report_date}")
    records = parse_log_file(log_path)
    print(f"  Total records: {len(records)}")

    max_ver = config.max_client_version
    if max_ver > 0:
        print(f"  Version filter: major <= {max_ver}")
    sessions = build_sessions(records, tz, max_client_version=max_ver)
    print(f"  User sessions (after filtering): {len(sessions)}")

    if not sessions:
        print("  No sessions to report. Exiting.")
        sys.exit(0)

    # Determine output file — use report_date (from log), not session dates
    filename = config.filename_pattern.replace("{date}", report_date)

    if args.output_file:
        excel_path = args.output_file
    else:
        excel_path = os.path.join(args.output_dir, f"{filename}.xlsx")

    generate_excel(sessions, excel_path)
    print(f"  Excel report: {excel_path}")

    # Generate JSON report alongside Excel
    json_path = os.path.splitext(excel_path)[0] + ".json"
    generate_json(sessions, json_path, args.timezone)
    print(f"  JSON report:  {json_path}")

    # Upload to file share if enabled
    if config.share_enabled:
        from share_upload import upload_report
        success, msg = upload_report(excel_path, config)
        if success:
            print(f"  Share upload:  {msg}")
        else:
            print(f"  Share upload FAILED: {msg}", file=sys.stderr)

    # Clean up old reports
    cleanup_old_reports(args.output_dir, config.retention_days)


if __name__ == "__main__":
    main()
