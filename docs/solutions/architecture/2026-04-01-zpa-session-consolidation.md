---
date: "2026-04-01"
problem_type: data-processing
component: session_parser.py
symptoms:
  - "ZPA creates multiple SessionIDs for a single continuous user connection"
  - "Auth probe sessions (< 1 second) pollute session data"
  - "Back-to-back sessions with negative gaps (overlapping) appear as separate connections"
root_cause: protocol-mismatch
resolution_type: fix
severity: high
tags:
  - zpa
  - session-parsing
  - data-consolidation
  - zscaler
custom_fields: {}
---

# ZPA Session Consolidation Logic

## Problem

ZPA (Zscaler Private Access) session logs do not follow a simple start/stop model.
Three behaviors produce noisy data that must be handled:

1. **Auth probes**: ZPA Client Connector periodically checks authentication against
   the IdP (SAML/Entra). These produce AUTHENTICATED → DISCONNECTED events within
   fractions of a second. They are NOT real user sessions.

2. **SessionID rotation**: ZPA rotates SessionIDs during a continuous connection.
   A user connected for 2 hours may have 8+ different SessionIDs. Consecutive
   sessions have gaps of -7s to +5s (overlaps and micro-disconnects).

3. **Periodic heartbeats**: While connected, ZPA emits AUTHENTICATED events every
   few minutes. A single session produces many log entries.

## Root Cause

ZPA's NSS (Nanolog Streaming Service) is designed for real-time monitoring, not
for session accounting. The log format reflects ZPA's internal session management
rather than the user's logical connection state.

## Solution

Three-stage pipeline:

1. **Filter by ClientType**: Only `zpn_client_type_zapp` (real users). Exclude
   `zpn_client_type_ip_anchoring` (infrastructure) and `zpn_client_type_slogger`
   (log service itself).

2. **Discard auth probes**: Sessions with duration < 5 seconds are authentication
   checks, not real connections. Observed probes are always < 1 second with exactly
   2 events.

3. **Merge consecutive sessions**: For the same user on the same day, if the gap
   between one session's end and the next session's start is <= 60 seconds, merge
   them into a single logical session. Use the earliest start time and latest end
   time. Take accumulated values (bytes, IP) from the last event.

## Prevention

- When integrating with ZPA logs, always apply this three-stage pipeline
- The thresholds (5s for probes, 60s for merge) were validated against real lab data
- Document these thresholds in the config as constants, not magic numbers
- The merge logic must handle negative gaps (overlapping sessions) — ZPA starts
  the new session before the old one is formally closed
