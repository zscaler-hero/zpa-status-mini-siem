# ZPA Status Mini-SIEM

A lightweight syslog collector and reporting tool for **Zscaler Private Access (ZPA)**.

---

**Copyright (c) 2025 ZHERO srl, Italy**
**Website:** [https://zhero.ai](https://zhero.ai)

This project is released under the MIT License. See the [LICENSE](LICENSE) file for full details.

---

## 🎯 Purpose

Organizations using Zscaler Private Access need visibility into user session activity — who connected, when, from where, and for how long. ZPA's built-in logging streams raw JSON events via syslog, but turning that into actionable daily reports requires parsing, session consolidation, and presentation.

**ZPA Status Mini-SIEM** bridges that gap: it receives ZPA syslog, consolidates raw events into meaningful user sessions, generates daily Excel and JSON reports, and serves a web dashboard for historical browsing and search. Designed for RHEL 9/10, it installs in minutes on air-gapped servers.

## 🏗️ Architecture

```
[ZPA App Connector] --syslog(TCP/514)--> [rsyslog] --> /var/log/zpa/zpa.log
                                                              |
                                         (daily timer) --> [report_generator.py]
                                                              |
                                              ┌───────────────┼───────────────┐
                                              v               v               v
                                        Excel report    JSON report     Share upload
                                        (download)      (dashboard)     (SMB/SCP)

[Web Dashboard] <--HTTPS--> [Flask app] --> reads JSON reports
```

### Components

| Component | Description |
|-----------|-------------|
| **rsyslog** | Receives ZPA syslog on TCP/514, writes to `/var/log/zpa/` |
| **logrotate** | Daily rotation, 30-day retention, gzip compression |
| **report_generator.py** | Streams logs (line-by-line, pre-filter before `json.loads`), consolidates sessions via per-SID accumulators, writes Excel/JSON/CSV + a small `.summary.json` sidecar for the dashboard |
| **web_dashboard.py** | Flask HTTPS dashboard with auth, browse, search, download, on-demand partial-report generation. Reads sidecars to render the index without parsing multi-MB JSON files |
| **share_upload.py** | Uploads reports to SMB/CIFS or SCP shares |
| **zpa_siem_ctl.py** | Management CLI: health checks, report regeneration, share upload test |
| **install.sh** | Interactive installer for RHEL 9/10 |

## 🚀 Quick Start

### Install on RHEL 9/10

```bash
# Transfer the zip to the server and extract
unzip zpa-siem-*.zip && cd zpa-siem-*/

# Run the interactive installer (as root)
sudo bash install.sh
```

The installer will prompt for:
- Timezone and max client version filter
- Syslog port and protocol
- Report retention and filename pattern
- Dashboard credentials
- File share settings (optional)

### Manage

```bash
sudo bash install.sh --status      # Show service status and config
sudo bash install.sh --configure   # Change settings without reinstalling
sudo bash install.sh --uninstall   # Remove the installation
```

### Health check and report management

After installation, the `zpa-siem-ctl` command is available system-wide:

```bash
# Check for missing reports (days with logs but no report)
sudo zpa-siem-ctl health

# Check only the last 7 days
sudo zpa-siem-ctl health --days 7

# Regenerate a specific day's report (does NOT upload to share — see test-share)
sudo zpa-siem-ctl regen 2026-04-09

# Regenerate all missing reports at once
sudo zpa-siem-ctl regen --all

# Force-rebuild every day, including those that already have a report
sudo zpa-siem-ctl regen --all --force

# Build dashboard sidecars for reports created before the sidecar feature
# (idempotent — existing sidecars are kept unless --force is passed)
sudo zpa-siem-ctl reindex
sudo zpa-siem-ctl reindex --force
```

> **Note:** `regen` never auto-uploads to the configured file share. Only the
> daily systemd timer pushes reports. Use `test-share` (below) to validate
> connectivity, or upload manually if you need to push a regenerated report.

> **Note:** Every freshly generated report writes a small `{date}.summary.json`
> sidecar (a few KB containing the username list and session count). The
> dashboard reads sidecars to render the index and to pre-filter searches
> without loading the full multi-MB report payload. Run `reindex` once after
> upgrading to populate sidecars for older reports already on disk.

### Production smoke test (selftest)

The `selftest` subcommand runs an end-to-end check of the whole pipeline
**without creating permanent artifacts**. Recommended right after install and
whenever something changes (config edit, share migration, OS upgrade):

```bash
# Full check: config + app log writability + log source + dry-run report + share upload
sudo zpa-siem-ctl selftest

# Skip the share upload step (useful when the share isn't reachable yet)
sudo zpa-siem-ctl selftest --skip-share

# Dry-run on a specific date instead of yesterday
sudo zpa-siem-ctl selftest --date 2026-04-09
```

What it checks:
1. `config.ini` is readable and has all required sections
2. `/var/log/zpa-siem/app.log` is writable (writes a marker, reads it back)
3. `/var/log/zpa/` exists and contains at least one readable `zpa.log*` file
4. **Dry-run report generation** — parses logs and builds sessions in memory,
   but writes **no** Excel/CSV/JSON files and does **not** attempt upload
5. **Share connectivity** — uploads a tiny marker file and then **deletes it
   from the remote share** (best-effort cleanup via `smbclient del` / `ssh rm`).
   If the remote cleanup fails, the marker filename is printed so an operator
   can remove it manually.

Exit code `0` = all checks passed, `1` = at least one check failed.

### Validate file share upload

```bash
# Upload the newest report to the configured share, or generate a tiny test
# file if no reports exist yet. Shows method, target, and auth mode.
sudo zpa-siem-ctl test-share

# Upload a specific file
sudo zpa-siem-ctl test-share --file /opt/zpa-siem/reports/zpa-report-2026-04-09.xlsx
```

The command prints the resolved share configuration (method, target/share path,
auth mode, format) and reports the outcome of the upload. It does not modify
any reports — it only invokes the same `share_upload.py` code path used by the
daily timer.

### Generate a report manually

```bash
# Process yesterday's rotated log (default)
sudo /opt/zpa-siem/venv/bin/python3 /opt/zpa-siem/report_generator.py

# Process a specific date (finds all relevant log files automatically)
sudo /opt/zpa-siem/venv/bin/python3 /opt/zpa-siem/report_generator.py --date 2026-04-09

# Process today's active log (for testing)
sudo /opt/zpa-siem/venv/bin/python3 /opt/zpa-siem/report_generator.py --log-file /var/log/zpa/zpa.log

# Skip the share upload even if enabled (default for zpa-siem-ctl regen)
sudo /opt/zpa-siem/venv/bin/python3 /opt/zpa-siem/report_generator.py --date 2026-04-09 --no-upload

# Dry-run: parse + build sessions in memory only (no files written, no upload)
sudo /opt/zpa-siem/venv/bin/python3 /opt/zpa-siem/report_generator.py --date 2026-04-09 --dry-run
```

Generated Excel and JSON reports are written to `/opt/zpa-siem/reports/` by default
(configurable via `output_dir` in the `[reports]` section of `config.ini`). Files
follow the pattern `zpa-report-YYYY-MM-DD.{xlsx,json,csv}` and are auto-pruned
after `retention_days`.

### On-demand partial report (web dashboard)

The dashboard home page exposes a **Generate today's report now** button
(*Refresh today's report* if one already exists). Clicking it runs the same
generator code path against the current day's live log, without uploading to the
share. The midnight cron will replace the partial file with the final daily
report.

Behavior and safeguards:

- Synchronous: the request blocks until the report is built (or fails after a
  5-minute timeout). The button shows "Generating..." while the worker is busy.
- One generation at a time: a per-process `threading.Lock` plus an advisory
  `fcntl.flock` on `<output_dir>/.ondemand-generation.lock` prevent overlap
  with another click or with the scheduled job.
- **Cutoff**: blocked after `[dashboard] on_demand_cutoff` (default `23:45`,
  local timezone) to keep the dashboard out of the way of the midnight cron.
  The button shows a "Paused" pill with the reason during the blocked window.
- No share upload: the partial is for dashboard browsing/search only.
- App log events: `event=ondemand_started`, `event=ondemand_complete`,
  `event=ondemand_blocked`, `event=ondemand_skipped`, `event=ondemand_failed`.

Disable the button entirely via `[dashboard] enable_on_demand = false` in
`config.ini`. The equivalent CLI call is:

```bash
sudo /opt/zpa-siem/venv/bin/python3 /opt/zpa-siem/report_generator.py \
     --date "$(date +%F)" --no-upload
```

### Application log

All report runs and share uploads write to a persistent log file in addition to
stdout/journald, with a structured summary line on each run:

```
/var/log/zpa-siem/app.log    # Rotated daily, 30-day retention, gzip
```

Inspect activity:

```bash
# Live tail
sudo tail -f /var/log/zpa-siem/app.log

# Summary lines only (one per report run)
sudo grep "event=report_complete\|event=report_failed\|event=upload_" /var/log/zpa-siem/app.log

# Same content also available via journald (no rotation/retention there)
sudo journalctl -u zpa-report.service --since today
```

Summary line format:
```
event=report_complete date=2026-04-09 sessions=4390 excel=zpa-report-2026-04-09.xlsx
  csv=... json=... upload=ok|failed|skipped|disabled duration_ms=14921
```

## 🛠️ Development Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run report generator against sample data
PYTHONPATH=src python3 src/report_generator.py \
  --log-file logs/zpa-sample.log \
  --output-dir reports/ \
  --timezone Europe/Rome

# Run web dashboard (dev mode)
PYTHONPATH=src python3 src/web_dashboard.py

# Run tests
python3 -m pytest tests/ -v
```

## ⚙️ Configuration

All settings are stored in `/opt/zpa-siem/config.ini` (generated by the installer).
See `config/config.ini.example` for all options with documentation.

| Section | Key Settings |
|---------|-------------|
| `general` | timezone, max_client_version |
| `syslog` | port, protocol |
| `logging` | log_dir, log_file (application log, default `/var/log/zpa-siem/app.log`) |
| `reports` | output_dir (default `/opt/zpa-siem/reports`), schedule, retention_days, filename_pattern |
| `dashboard` | enabled, port, username, password_hash, session_timeout, enable_on_demand, on_demand_cutoff |
| `share` | enabled, method (smb/scp), credentials |

### Version Filter

The `max_client_version` setting filters out noise from virtual machines or test environments that report unusually high version numbers (e.g., `25.4.3`). Set it to the maximum expected major version of real Zscaler Client Connector installations (default: `10`). Set to `0` to disable filtering.

### File Share Upload

When share upload is enabled, the daily timer pushes the generated report to a
remote location. Two methods are supported:

**SMB / CIFS** (Windows file shares)
- Requires `samba-client` (uses the `smbclient` CLI)
- Configured via `smb_share`, `smb_username`, `smb_password`, `smb_domain`

**SCP** (any SSH-reachable host) — connection is built from discrete fields:
- `scp_host` — hostname or IP (required)
- `scp_port` — SSH port (optional, default 22)
- `scp_path` — remote directory (required)
- `scp_username` — optional
- `scp_password` — optional

Two authentication modes:
- **SSH key** (recommended): leave `scp_password` empty. The runtime user
  (root, by default) must have an SSH key authorized on the remote host.
  Test once manually so the host key is in `known_hosts`.
- **Username + password**: set `scp_username` and `scp_password`. The installer
  will install `sshpass` (from EPEL on RHEL) and use it to inject the password
  securely via the `SSHPASS` environment variable. The first connection
  auto-trusts the remote host key (`StrictHostKeyChecking=accept-new`).

Use `zpa-siem-ctl test-share` after configuring to validate the upload before
relying on the daily timer. The `regen` subcommand never uploads — keep using
`test-share` for ad-hoc verification.

## 🌐 ZPA Log Stream Configuration

In the ZPA Admin Portal, configure the NSS feed **Log Stream Content** with this template
(the trailing `\n` is required):

```
{"Username": %j{Username},"SessionID": %j{SessionID},"SessionStatus": %j{SessionStatus},"Version": %j{Version},"PrivateIP": %j{PrivateIP},"PublicIP": %j{PublicIP},"CountryCode": %j{CountryCode},"TimestampAuthentication": %j{TimestampAuthentication:iso8601},"TimestampUnAuthentication": %j{TimestampUnAuthentication:iso8601},"TotalBytesRx": %d{TotalBytesRx},"TotalBytesTx": %d{TotalBytesTx},"Hostname": %j{Hostname},"Platform": %j{Platform},"ClientType": %j{ClientType},"TrustedNetworksNames": [%j(,){TrustedNetworksNames}],"City": %j{City}}\n
```

> **Path**: ZPA Admin Portal > Configuration > Log Receivers > edit feed > Log Stream Content

## 🧠 Memory model

The report generator was designed for VMs with limited RAM facing large-scale
ZPA deployments (10k+ users, tens of millions of log records per day):

- Log files are read **line-by-line**; lines that do not contain the
  `zpn_client_type_zapp` marker are dropped before `json.loads`, avoiding
  the dict allocation entirely.
- Records are streamed through generators — no intermediate `list[dict]` of
  all records is ever materialised.
- Session consolidation keeps one slim accumulator (`__slots__` class) per
  `SessionID`, not the raw event list. Peak RAM scales with the number of
  distinct sessions (tens of thousands), not raw events (millions).
- Excel output uses openpyxl's write-only mode; JSON output is written
  row-by-row; CSV streams via `csv.DictWriter`.
- The dashboard reads `{date}.summary.json` sidecars to render the index and
  to pre-filter username searches, avoiding multi-MB JSON loads on every
  request.

Measured peak RSS on a real two-file day of logs (~1.4M records, 4.4k user
sessions): **~62 MB**.

## 📊 Session Processing Logic

ZPA emits one event per `SessionID` change, and a single physical user session
typically generates many `SessionID` events: rotation every few minutes, dual
App Connector tunnels, network reconfigurations during the day, Public Service
Edge / Private Service Edge transitions, post-network-change tunnel teardown.
A naive "one row per SessionID" view produces 30 to 100 rows for a single
workday for a single user. The pipeline below consolidates raw events into a
small set of meaningful user sessions. A real example: 1039 raw events for one
user on one day collapse into 2 rows in the final report.

### Stage 1: Filtering

A raw event is kept only if all three hold:

1. `ClientType == zpn_client_type_zapp` (real Zscaler Client Connector sessions,
   excludes machine tunnels and connector-internal events).
2. `Version` major number `<= max_client_version` (drops VM/test noise like
   version `25.x.x`; configurable, default `10`).
3. `TimestampAuthentication` falls inside the target day in the configured
   timezone (so a session that authenticated at 23:50 UTC is correctly assigned
   to the corresponding local day).

Events are grouped by `SessionID`. Each group becomes a **candidate session**.
Candidates with duration `< 5 seconds` are discarded as authentication probes
(short reconnect attempts that never carry user traffic).

### Stage 2: Merge rules

Candidate sessions are sorted by `(Username, Date, Session Start)` and walked
left-to-right. Two consecutive candidates `current` and `next` merge into a
single consolidated row when **all** of these hold:

- same `Username` and same `Date`
- same `TrustedNetworksNames` (the strongest signal of "physical location",
  no merge across Trusted/Untrusted boundaries)
- effective gap `<= 60s`, where the effective gap is `next.start - max(end_dt
  across the chain)` and a negative value means temporal overlap

AND **at least one** of these reasons holds:

| Reason | Description |
|---|---|
| **Same uplink** | `next.PublicIP` matches a `PublicIP` already in the chain. The original case: ZPA rotated the SessionID without changing the network path. |
| **Same client interface** | `next.PrivateIP` matches a `PrivateIP` already in the chain. Typical of a Public Service Edge ↔ Private Service Edge transition: the client's local interface is unchanged, but the egress path was rebound to a different connector. |
| **Temporal overlap** | `next.start < max(chain.end)`. ZPA keeps the previous tunnel "alive" for some seconds after a network change, so old and new tunnels coexist briefly; the user is already on the new one. |

If the gap exceeds 60 seconds, no merge regardless of IP commonality. If
`TrustedNetworksNames` changes, no merge regardless of timing.

### Stage 3: Field rendering

A consolidated row can span multiple network paths. Four IP columns separate
the picture:

| Column | Definition |
|---|---|
| `Main Public IP` | the **public-class** IP (RFC1918 / link-local / loopback / CGNAT excluded) with the **largest cumulative effective duration** across the merged segments. Empty if no segment in the chain has a public-class IP. |
| `Other Public IPs` | comma-separated, the remaining public-class IPs ranked by descending duration. |
| `Main Private IP` | the `PrivateIP` with the largest cumulative effective duration. |
| `Other Private IPs` | comma-separated, the remaining `PrivateIP`s ranked by descending duration. |

**Effective duration per segment**: each segment's end is truncated at the
start of the next segment in the chain. A 15-minute overlap between an old
tunnel and a new one is attributed entirely to the new tunnel, because in
practice the user already moved over.

**Bytes Rx/Tx**: summed across all merged segments. ZPA reports byte counters
per `SessionID` (resetting on rotation), so summing gives the true total
traffic for the consolidated session.

**City / Country**: geolocation that ZPA attached to `Main Public IP`. When
the chain has no public-class IP (typical of "user worked entirely through
Private Service Edge"), the fallback uses the City/Country of the longest
segment, which is often empty for purely internal traffic.

**Session End / Duration**: the consolidated row's end is the maximum
`TimestampUnAuthentication` across merged segments (open `In corso` segments
make the consolidated row `In corso`). Duration is `end - start`.

**SessionID list (JSON only)**: the JSON report includes a `session_ids` array
per row containing every raw `SessionID` that contributed to that row, for
SIEM/audit traceability. Excel and CSV stay compact.

### Anonymized examples

Examples use:

- usernames `alice@example.com`, `bob@example.com`
- hostname `WORKSTATION-01`
- public IPs from `203.0.113.0/24` (TEST-NET-3, RFC 5737)
- private IPs from `10.0.0.0/8` (RFC 1918)

#### Example A: SessionID rotation (Same uplink)

Two raw candidate sessions for the same user, same Trusted Network:

```
SID-A1: 09:00:00 -> 09:30:15   pub 203.0.113.10   priv 10.20.30.40   Trusted
SID-A2: 09:30:18 -> 11:45:00   pub 203.0.113.10   priv 10.20.30.40   Trusted
```

Gap = 3s, same `PublicIP`, same Trusted. **Merge** under "Same uplink".

Consolidated row:

```
09:00:00 -> 11:45:00   Main Public IP=203.0.113.10   Main Private IP=10.20.30.40
                       Other Public IPs=(empty)       Other Private IPs=(empty)
                       Bytes summed across both segments
                       session_ids=[SID-A1, SID-A2]
```

#### Example B: Public ↔ Private Service Edge transition (Same client interface)

```
SID-B1: 14:00:00 -> 14:30:00   pub 203.0.113.10   priv 10.20.30.40   Trusted
SID-B2: 14:30:15 -> 16:00:00   pub 10.20.30.40    priv 10.20.30.40   Trusted
```

Gap = 15s. `PublicIP` changes; in SID-B2 it equals `PrivateIP`, indicating
a Private Service Edge path with no NAT. `PrivateIP` is identical (same
client NIC). **Merge** under "Same client interface".

Consolidated row:

```
14:00:00 -> 16:00:00   Main Public IP=203.0.113.10   (only public-class one)
                       Other Public IPs=(empty)       (RFC1918 from SID-B2 is excluded)
                       Main Private IP=10.20.30.40   Other Private IPs=(empty)
                       session_ids=[SID-B1, SID-B2]
```

The RFC1918 value `10.20.30.40` that ZPA emitted in `PublicIP` is not shown
in any Public column; that information is already represented by the
Private columns.

#### Example C: ZPA tunnel switchover (Temporal overlap)

```
SID-C1: 13:00:00 -> 14:11:23   pub 203.0.113.10   priv 10.20.30.40   Trusted
SID-C2: 13:55:06 -> 14:10:06   pub 203.0.113.20   priv 10.20.30.50   Trusted
```

SID-C2 starts at 13:55:06, before SID-C1 ends at 14:11:23 (overlap of 16
minutes). Both `PublicIP` and `PrivateIP` differ between the two segments,
but Trusted is the same. **Merge** under "Temporal overlap": ZPA logged the
old DISCONNECT 16 minutes after the user already switched networks.

Consolidated row:

```
13:00:00 -> 14:11:23   Main Public IP=203.0.113.10    (longer effective duration)
                       Other Public IPs=203.0.113.20
                       Main Private IP=10.20.30.40    Other Private IPs=10.20.30.50
                       session_ids=[SID-C1, SID-C2]
```

The effective duration of SID-C1 is computed as `13:55:06 - 13:00:00`
(truncated at SID-C2's start), so SID-C1's `203.0.113.10` accumulates ~55
minutes while SID-C2's `203.0.113.20` accumulates ~15 minutes; the former
wins as Main.

#### Example D: No merge (Trusted Network changes)

```
SID-D1: 17:00:00 -> 17:45:00   pub 203.0.113.10    priv 10.20.30.40   Trusted
SID-D2: 19:00:00 -> 22:00:00   pub 198.51.100.50   priv 192.168.1.5   (empty)
```

Gap is 1h15m (>> 60s) and `TrustedNetworksNames` differs (the user moved
from corporate network to a home network). Two separate rows in the report,
regardless of any IP commonality.

#### Example E: Pure Private Service Edge work (no public-class IP)

```
SID-E1: 09:00:00 -> 13:00:00   pub 10.20.30.40   priv 10.20.30.40   Trusted
SID-E2: 13:00:30 -> 18:00:00   pub 10.20.30.40   priv 10.20.30.40   Trusted
```

Gap = 30s, same `PublicIP` (RFC1918, but the value matches), same `PrivateIP`,
same Trusted. **Merge** under "Same uplink".

Consolidated row:

```
09:00:00 -> 18:00:00   Main Public IP=(empty)        Other Public IPs=(empty)
                       Main Private IP=10.20.30.40   Other Private IPs=(empty)
                       City=(empty)  Country=(empty)
                       session_ids=[SID-E1, SID-E2]
```

The user worked entirely through a Private Service Edge with no NAT, so
no public-class IP exists. The Public IP columns stay empty, the activity
is documented through the Private IP. `City`/`Country` are typically empty
because ZPA's geolocation only resolves public IPs.

#### Example F: Mixed-egress workday (multiple uplinks consolidated)

A user moves between buildings during the day. Pre-merge candidate sessions:

```
SID-F1: 08:30 -> 13:55   pub 203.0.113.10   priv 10.20.30.40   Trusted
SID-F2: 13:55 -> 14:10   pub 203.0.113.11   priv 10.20.50.98   Trusted   (15 min)
SID-F3: 14:10 -> 15:21   pub 10.20.50.98    priv 10.20.50.98   Trusted   (no NAT)
SID-F4: 15:21 -> 17:24   pub 10.20.30.40    priv 10.20.30.40   Trusted   (no NAT)
SID-F5: 17:27 -> 17:45   pub 203.0.113.12   priv 10.20.70.233  Trusted   (small overlap)
```

All are within Trusted. Each consecutive pair satisfies one of the three
merge reasons (same Public, same Private, or overlap). Result: **all five
collapse into one consolidated row**.

```
08:30:00 -> 17:45:00
Main Public IP    : 203.0.113.10                  (~5h21m effective)
Other Public IPs  : 203.0.113.12, 203.0.113.11    (~18m + ~15m)
Main Private IP   : 10.20.30.40                   (~7h25m, sums of F1+F4)
Other Private IPs : 10.20.50.98, 10.20.70.233
City              : (city of 203.0.113.10)
session_ids       : [SID-F1, SID-F2, SID-F3, SID-F4, SID-F5]
```

The two RFC1918 values that appeared in `PublicIP` (`10.20.50.98` and
`10.20.30.40` from SID-F3/F4) are excluded from the Public columns and
merged with the Private side.

### Report fields

The Excel and CSV reports have 17 columns:

`Username`, `Date`, `Session Start`, `Session End`, `Duration`,
`Main Public IP`, `Other Public IPs`, `Main Private IP`, `Other Private IPs`,
`City`, `Country`, `Device`, `Platform`, `Client Version`, `Trusted Network`,
`Bytes Rx`, `Bytes Tx`.

The JSON report has the same fields (lowercase / underscore naming) plus
`session_ids` (array of raw SessionIDs that contributed to the row).

## 📦 Distribution

Build a distributable zip with vendored dependencies:

```bash
bash build-dist.sh
```

This creates a self-contained zip that can be installed on air-gapped servers with no internet access. The build script downloads all Python wheels for RHEL x86_64 (Python 3.9+).

## 🔧 Troubleshooting

| Issue | Check | Solution |
|-------|-------|---------|
| Anything looks off | `sudo zpa-siem-ctl selftest` | Single command that exercises the whole pipeline — start here |
| Dashboard won't start | `journalctl -u zpa-dashboard -n 30` | Check Python errors in log |
| No logs arriving | `ss -tlnp \| grep 514` | Verify rsyslog is listening |
| Empty reports | `cat /var/log/zpa/zpa.log` | Confirm log data is flowing |
| Report not generated | `tail -100 /var/log/zpa-siem/app.log` or `journalctl -u zpa-report.service --since yesterday` | Check for errors, then `zpa-siem-ctl regen YYYY-MM-DD` |
| Missing days | `sudo zpa-siem-ctl health` | Shows gaps, then `zpa-siem-ctl regen --all` |
| Wrong timezone in reports | `cat /opt/zpa-siem/config.ini` | Update timezone, regenerate |
| VM noise in reports | Config: `max_client_version` | Set to expected max major (e.g., `10`) |
| Share upload fails | `sudo zpa-siem-ctl test-share` | Read the printed `scp`/`smbclient` error message (also logged to `/var/log/zpa-siem/app.log` with `event=upload_failed`) |
| `sshpass: command not found` | SCP password mode without sshpass | `sudo dnf install epel-release && sudo dnf install sshpass`, or re-run `install.sh --configure` |
| On-demand button disabled / "Paused" | Time past `[dashboard] on_demand_cutoff` (default `23:45`) or `enable_on_demand = false` | Wait for the midnight report, or change the cutoff/flag in `config.ini` |
| On-demand "already in progress" | Another generation holds the lock | Wait for the in-flight run (or the scheduled job) to finish, then reload |

### Debug a report manually

```bash
# Check what's in the active log
wc -l /var/log/zpa/zpa.log

# Check for missing reports
sudo zpa-siem-ctl health

# Generate with verbose output
sudo /opt/zpa-siem/venv/bin/python3 /opt/zpa-siem/report_generator.py --log-file /var/log/zpa/zpa.log
```

## 🤝 Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with a clear description

## 📄 License

MIT — see [LICENSE](LICENSE) for details.
