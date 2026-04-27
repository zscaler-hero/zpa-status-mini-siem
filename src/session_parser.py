"""ZPA log parsing and session consolidation.

Parses ZPA syslog files, extracts user sessions, filters auth probes,
and merges consecutive sessions caused by ZPA SessionID rotation.
"""

import gzip
import json
from collections import defaultdict
from datetime import datetime
from typing import Optional
from zoneinfo import ZoneInfo

MIN_SESSION_DURATION_SECONDS = 5
SESSION_MERGE_GAP_SECONDS = 60
USER_CLIENT_TYPE = "zpn_client_type_zapp"

REPORT_COLUMNS = [
    "Username",
    "Date",
    "Session Start",
    "Session End",
    "Duration",
    "Public IP",
    "Private IP",
    "City",
    "Country",
    "Device",
    "Platform",
    "Client Version",
    "Trusted Network",
    "Bytes Rx",
    "Bytes Tx",
]


def parse_log_line(line: str) -> Optional[dict]:
    """Extract JSON payload from a syslog line."""
    idx = line.find("{")
    if idx == -1:
        return None
    try:
        return json.loads(line[idx:])
    except (json.JSONDecodeError, ValueError):
        return None


def parse_log_file(path: str) -> list[dict]:
    """Read a log file (plain or gzipped) and return all valid JSON records."""
    records = []
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, mode="rt", errors="replace") as f:
        for line in f:
            rec = parse_log_line(line)
            if rec:
                records.append(rec)
    return records


def parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse ISO timestamp from ZPA log."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _version_major(version: str) -> Optional[int]:
    """Extract the major version number from a version string like '4.7.168.xxx'."""
    if not version:
        return None
    try:
        return int(version.split(".")[0])
    except (ValueError, IndexError):
        return None


def build_sessions(records: list[dict], tz: ZoneInfo,
                   max_client_version: int = 0) -> list[dict]:
    """Group records by SessionID and build consolidated session rows.

    Filters:
    - Only zpn_client_type_zapp (real user sessions)
    - Discards client versions with major > max_client_version (if set)
    - Discards sessions < 5 seconds (auth probes)

    Timestamps are converted from UTC to the given timezone for display.
    """
    grouped = defaultdict(list)

    for rec in records:
        if rec.get("ClientType") != USER_CLIENT_TYPE:
            continue
        if max_client_version > 0:
            major = _version_major(rec.get("Version", ""))
            if major is not None and major > max_client_version:
                continue
        sid = rec.get("SessionID")
        if not sid:
            continue
        grouped[sid].append(rec)

    sessions = []
    for sid, events in grouped.items():
        last = events[-1]
        first = events[0]

        username = first.get("Username", "")
        auth_ts = parse_timestamp(first.get("TimestampAuthentication", ""))

        if not auth_ts:
            continue

        unauth_ts = None
        for e in events:
            if e.get("SessionStatus") == "ZPN_STATUS_DISCONNECTED":
                unauth_ts = parse_timestamp(e.get("TimestampUnAuthentication", ""))
                last = e
                break

        auth_local = auth_ts.astimezone(tz)

        if unauth_ts:
            duration_sec = (unauth_ts - auth_ts).total_seconds()
            if duration_sec < MIN_SESSION_DURATION_SECONDS:
                continue
            duration_str = format_duration(duration_sec)
            unauth_local = unauth_ts.astimezone(tz)
            end_str = unauth_local.strftime("%H:%M:%S")
        else:
            duration_str = "In corso"
            end_str = "In corso"

        trusted = last.get("TrustedNetworksNames", [])
        trusted_str = ", ".join(trusted) if trusted else ""

        version = last.get("Version", "")
        parts = version.split(".")
        if len(parts) > 4:
            version = ".".join(parts[:4])

        unauth_local = unauth_ts.astimezone(tz) if unauth_ts else None

        sessions.append({
            "Username": username,
            "Date": auth_local.strftime("%Y-%m-%d"),
            "Session Start": auth_local.strftime("%H:%M:%S"),
            "Session End": end_str,
            "Duration": duration_str,
            "Public IP": last.get("PublicIP", ""),
            "Private IP": last.get("PrivateIP", ""),
            "City": last.get("City", ""),
            "Country": last.get("CountryCode", ""),
            "Device": last.get("Hostname", ""),
            "Platform": last.get("Platform", ""),
            "Client Version": version,
            "Trusted Network": trusted_str,
            "Bytes Rx": last.get("TotalBytesRx", 0),
            "Bytes Tx": last.get("TotalBytesTx", 0),
            "_start_dt": auth_local,
            "_end_dt": unauth_local,
        })

    sessions.sort(key=lambda s: (s["Username"], s["Date"], s["Session Start"]))
    sessions = merge_sessions(sessions)
    for s in sessions:
        s.pop("_start_dt", None)
        s.pop("_end_dt", None)
    return sessions


def merge_sessions(sessions: list[dict]) -> list[dict]:
    """Merge consecutive sessions for the same user when the gap is small.

    ZPA rotates SessionIDs periodically even if the user stays connected.
    This produces back-to-back (or overlapping) sessions that should be
    reported as a single continuous session.
    """
    if not sessions:
        return sessions

    merged = []
    current = None

    for s in sessions:
        if current is None:
            current = s.copy()
            continue

        if s["Username"] != current["Username"] or s["Date"] != current["Date"]:
            merged.append(current)
            current = s.copy()
            continue

        if current["Session End"] == "In corso":
            merged.append(current)
            current = s.copy()
            continue

        cur_end_dt = current.get("_end_dt")
        next_start_dt = s.get("_start_dt")
        if cur_end_dt is None or next_start_dt is None:
            merged.append(current)
            current = s.copy()
            continue
        gap_sec = (next_start_dt - cur_end_dt).total_seconds()

        # Only merge if context hasn't changed (same network location)
        same_context = (
            s["Public IP"] == current["Public IP"]
            and s["Trusted Network"] == current["Trusted Network"]
        )

        if gap_sec <= SESSION_MERGE_GAP_SECONDS and same_context:
            current["Session End"] = s["Session End"]
            current["_end_dt"] = s.get("_end_dt")
            for field in ("Public IP", "Private IP", "City", "Country",
                          "Device", "Platform", "Client Version",
                          "Trusted Network", "Bytes Rx", "Bytes Tx"):
                current[field] = s[field]
            if current["Session End"] != "In corso" and current["_end_dt"] is not None:
                duration_sec = (current["_end_dt"] - current["_start_dt"]).total_seconds()
                current["Duration"] = format_duration(duration_sec)
            else:
                current["Duration"] = "In corso"
        else:
            merged.append(current)
            current = s.copy()

    if current:
        merged.append(current)

    return merged


def format_duration(seconds: float) -> str:
    """Format seconds into HH:MM:SS."""
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"
