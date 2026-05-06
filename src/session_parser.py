"""ZPA log parsing and session consolidation.

Parses ZPA syslog files, extracts user sessions, filters auth probes,
and merges consecutive sessions caused by ZPA SessionID rotation.
"""

import gzip
import ipaddress
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
    "Main Public IP",
    "Other Public IPs",
    "Main Private IP",
    "Other Private IPs",
    "City",
    "Country",
    "Device",
    "Platform",
    "Client Version",
    "Trusted Network",
    "Bytes Rx",
    "Bytes Tx",
]


def _is_public_ip(ip_str: str) -> bool:
    """True if ip_str is a public-routable address (excludes RFC1918, loopback,
    link-local, CGNAT, multicast, and other reserved ranges)."""
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


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

        public_ip = last.get("PublicIP", "")
        private_ip = last.get("PrivateIP", "")
        city = last.get("City", "")
        country = last.get("CountryCode", "")
        sessions.append({
            "Username": username,
            "Date": auth_local.strftime("%Y-%m-%d"),
            "Session Start": auth_local.strftime("%H:%M:%S"),
            "Session End": end_str,
            "Duration": duration_str,
            "Public IP": public_ip,
            "Private IP": private_ip,
            "City": city,
            "Country": country,
            "Device": last.get("Hostname", ""),
            "Platform": last.get("Platform", ""),
            "Client Version": version,
            "Trusted Network": trusted_str,
            "Bytes Rx": last.get("TotalBytesRx", 0),
            "Bytes Tx": last.get("TotalBytesTx", 0),
            "_start_dt": auth_local,
            "_end_dt": unauth_local,
            "_session_ids": [sid],
            "_ip_history": [(auth_local, unauth_local, public_ip, private_ip, city, country)],
        })

    sessions.sort(key=lambda s: (s["Username"], s["Date"], s["Session Start"]))
    sessions = merge_sessions(sessions)
    for s in sessions:
        _finalize_row(s)
        s.pop("_start_dt", None)
        s.pop("_end_dt", None)
        s.pop("_ip_history", None)
        s.pop("Public IP", None)
        s.pop("Private IP", None)
    return sessions


_DESCRIPTIVE_FIELDS = ("Device", "Platform", "Client Version", "Trusted Network")


def _start_chain(s: dict) -> dict:
    """Start a new merge chain from a session, isolating mutable state."""
    new = s.copy()
    new["_session_ids"] = list(s.get("_session_ids", []))
    new["_ip_history"] = list(s.get("_ip_history", []))
    return new


def _can_merge(current: dict, s: dict, gap_sec: float) -> bool:
    """Decide whether s should be merged into the current chain.

    Two sessions merge when, within the same Trusted Network and gap <= 60s,
    at least one of these holds:
      1. same Public IP as some segment already in the chain (same uplink),
      2. same Private IP as some segment in the chain (Public/Private Edge
         transition: client interface unchanged, egress path differs),
      3. temporal overlap with the chain's running max end (ZPA tunnel
         switchover: the new tunnel comes up before the old DISCONNECT lands).
    """
    if gap_sec > SESSION_MERGE_GAP_SECONDS:
        return False
    if current.get("Trusted Network", "") != s.get("Trusted Network", ""):
        return False

    s_pub = s.get("Public IP", "")
    s_priv = s.get("Private IP", "")
    history = current.get("_ip_history", [])
    chain_pubs = {seg[2] for seg in history if seg[2]}
    chain_privs = {seg[3] for seg in history if seg[3]}

    if s_pub and s_pub in chain_pubs:
        return True
    if s_priv and s_priv in chain_privs:
        return True
    if gap_sec < 0:
        return True
    return False


def merge_sessions(sessions: list[dict]) -> list[dict]:
    """Merge consecutive sessions for the same user/date.

    ZPA emits multiple overlapping SessionIDs per physical user session
    (uplink rotation, dual-tunnel App Connectors, Public/Private Service
    Edge transitions, post-network-change tunnel teardown). Sessions are
    consolidated so the row reflects the full activity span (max end across
    merged segments), the total bytes, and the union of IP addresses seen.
    """
    if not sessions:
        return sessions

    merged = []
    current = None

    for s in sessions:
        if current is None:
            current = _start_chain(s)
            continue

        if s["Username"] != current["Username"] or s["Date"] != current["Date"]:
            merged.append(current)
            current = _start_chain(s)
            continue

        if current["Session End"] == "In corso":
            merged.append(current)
            current = _start_chain(s)
            continue

        cur_end_dt = current.get("_end_dt")
        next_start_dt = s.get("_start_dt")
        if cur_end_dt is None or next_start_dt is None:
            merged.append(current)
            current = _start_chain(s)
            continue
        gap_sec = (next_start_dt - cur_end_dt).total_seconds()

        if not _can_merge(current, s, gap_sec):
            merged.append(current)
            current = _start_chain(s)
            continue

        current["_session_ids"].extend(s.get("_session_ids", []))
        current["_ip_history"].extend(s.get("_ip_history", []))
        current["Bytes Rx"] = current["Bytes Rx"] + s["Bytes Rx"]
        current["Bytes Tx"] = current["Bytes Tx"] + s["Bytes Tx"]

        s_end_dt = s.get("_end_dt")
        if s["Session End"] == "In corso":
            current["Session End"] = "In corso"
            current["Duration"] = "In corso"
            current["_end_dt"] = None
            for field in _DESCRIPTIVE_FIELDS:
                current[field] = s[field]
        elif s_end_dt is not None and s_end_dt > cur_end_dt:
            current["Session End"] = s["Session End"]
            current["_end_dt"] = s_end_dt
            duration_sec = (s_end_dt - current["_start_dt"]).total_seconds()
            current["Duration"] = format_duration(duration_sec)
            for field in _DESCRIPTIVE_FIELDS:
                current[field] = s[field]
        # else: segment ended earlier than running max, only bytes/history accumulated.

    if current:
        merged.append(current)

    return merged


def _finalize_row(row: dict) -> None:
    """Compute Main/Other Public/Private IPs and resolve City/Country.

    Effective duration per segment is computed by truncating each segment's
    end at the next segment's start (Rule A: ZPA keeps the old tunnel alive
    for a while after a network change, but in practice the user is already
    on the new one).

    Main = IP with the largest cumulative effective duration. Other = the
    remaining IPs, listed by descending duration. RFC1918 addresses that ZPA
    reports in the PublicIP field are excluded from the Public columns
    (those represent Private Service Edge paths with no NAT, not real public
    egresses); they remain represented in the Private columns.
    """
    history = row.get("_ip_history", [])
    sorted_hist = sorted(history, key=lambda h: h[0])
    n = len(sorted_hist)

    public_durations: dict[str, float] = defaultdict(float)
    private_durations: dict[str, float] = defaultdict(float)
    public_to_geo: dict[str, tuple[str, str]] = {}
    seg_durations: list[float] = []

    for i, (start, end, pub, priv, city, country) in enumerate(sorted_hist):
        if i + 1 < n:
            next_start = sorted_hist[i + 1][0]
            eff_end = next_start if end is None else min(end, next_start)
        else:
            eff_end = end
        duration = 0.0 if eff_end is None else max((eff_end - start).total_seconds(), 0.0)
        seg_durations.append(duration)
        if pub:
            public_durations[pub] += duration
            if pub not in public_to_geo:
                public_to_geo[pub] = (city, country)
        if priv:
            private_durations[priv] += duration

    public_class = {ip: dur for ip, dur in public_durations.items() if _is_public_ip(ip)}
    if public_class:
        ranked_pub = sorted(public_class.items(), key=lambda x: -x[1])
        main_pub = ranked_pub[0][0]
        other_pub = [ip for ip, _ in ranked_pub[1:]]
        main_city, main_country = public_to_geo.get(main_pub, ("", ""))
    else:
        main_pub = ""
        other_pub = []
        if seg_durations and any(d > 0 for d in seg_durations):
            longest_idx = max(range(n), key=lambda i: seg_durations[i])
            main_city = sorted_hist[longest_idx][4]
            main_country = sorted_hist[longest_idx][5]
        elif sorted_hist:
            main_city = sorted_hist[0][4]
            main_country = sorted_hist[0][5]
        else:
            main_city, main_country = "", ""

    if private_durations:
        ranked_priv = sorted(private_durations.items(), key=lambda x: -x[1])
        main_priv = ranked_priv[0][0]
        other_priv = [ip for ip, _ in ranked_priv[1:]]
    else:
        main_priv = ""
        other_priv = []

    row["Main Public IP"] = main_pub
    row["Other Public IPs"] = ", ".join(other_pub)
    row["Main Private IP"] = main_priv
    row["Other Private IPs"] = ", ".join(other_priv)
    row["City"] = main_city
    row["Country"] = main_country


def format_duration(seconds: float) -> str:
    """Format seconds into HH:MM:SS."""
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"
