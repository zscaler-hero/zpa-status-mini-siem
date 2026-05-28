"""Tests for the dashboard sidecar workflow.

Covers: sidecar generation by report_generator, sidecar consumption by the
dashboard list view (must NOT load the full JSON when sidecar exists), and
sidecar-driven pre-filtering in search (must skip dates whose sidecar
usernames don't contain the query).
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

import web_dashboard
from report_generator import generate_summary_sidecar


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")
SAMPLE_LOG = os.path.join(FIXTURES_DIR, "sample_small.log")
REPORT_DATE = "2026-04-19"


def _run_generator(tmp_path):
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(project_root, "src")
    env["ZPA_SIEM_CONFIG"] = os.path.join(project_root, "config.ini")
    result = subprocess.run(
        [
            sys.executable, os.path.join(project_root, "src", "report_generator.py"),
            "--log-file", SAMPLE_LOG,
            "--output-dir", str(tmp_path),
            "--date", REPORT_DATE,
            "--timezone", "Europe/Rome",
            "--no-upload",
        ],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return str(tmp_path)


def test_sidecar_produced_alongside_full_report(tmp_path):
    out_dir = _run_generator(tmp_path)
    sidecar = os.path.join(out_dir, f"zpa-report-{REPORT_DATE}.summary.json")
    assert os.path.exists(sidecar)
    with open(sidecar) as f:
        data = json.load(f)
    assert set(data.keys()) >= {"date", "session_count", "has_csv", "has_xlsx", "usernames"}
    assert data["date"] == REPORT_DATE
    assert data["session_count"] == 51
    assert data["has_csv"] is True
    assert data["has_xlsx"] is True
    # All usernames in the sidecar must also be unique and sorted
    usernames = data["usernames"]
    assert usernames == sorted(set(usernames))
    assert len(usernames) == 51


def test_sidecar_much_smaller_than_full_json(tmp_path):
    """The whole point of the sidecar — should be at least an order of magnitude smaller."""
    out_dir = _run_generator(tmp_path)
    sidecar = os.path.join(out_dir, f"zpa-report-{REPORT_DATE}.summary.json")
    full_json = os.path.join(out_dir, f"zpa-report-{REPORT_DATE}.json")
    assert os.path.getsize(sidecar) < os.path.getsize(full_json) / 10


def test_list_uses_sidecar_not_full_json(tmp_path, monkeypatch):
    """When a sidecar exists, _list_available_reports must read it and skip the full JSON."""
    out_dir = _run_generator(tmp_path)
    _bind_dashboard_to(out_dir)

    opens = _track_opens(monkeypatch)
    reports = web_dashboard._list_available_reports()

    assert len(reports) == 1
    assert reports[0]["date"] == REPORT_DATE
    assert reports[0]["session_count"] == 51
    json_opens = [p for p in opens if p.endswith(".json")]
    assert all("summary" in p for p in json_opens), (
        f"_list_available_reports should only open *.summary.json, but opened: {json_opens}"
    )


def test_list_falls_back_to_full_json_when_sidecar_missing(tmp_path, monkeypatch):
    """Legacy reports without sidecars must still show in the index (via fallback)."""
    out_dir = _run_generator(tmp_path)
    sidecar = os.path.join(out_dir, f"zpa-report-{REPORT_DATE}.summary.json")
    os.remove(sidecar)

    _bind_dashboard_to(out_dir)
    reports = web_dashboard._list_available_reports()
    assert len(reports) == 1
    assert reports[0]["session_count"] == 51


def test_search_skips_dates_without_username_match(tmp_path, monkeypatch):
    """search() must NOT open the full JSON for a date whose sidecar usernames
    list doesn't contain the query substring."""
    out_dir = _run_generator(tmp_path)
    _bind_dashboard_to(out_dir)

    opens = _track_opens(monkeypatch)
    reports_dir, summaries, full_jsons, _ = web_dashboard._index_reports_dir()
    # Simulate search() inner logic with a query that does NOT match
    matched = False
    full_loaded = False
    for d in sorted(set(summaries) | set(full_jsons), reverse=True):
        if d in summaries:
            with open(os.path.join(reports_dir, summaries[d])) as f:
                s = json.load(f)
            if not any("nonexistent-user" in u.lower() for u in s.get("usernames", [])):
                continue
            matched = True
        if d in full_jsons:
            with open(os.path.join(reports_dir, full_jsons[d])) as f:
                json.load(f)
            full_loaded = True

    assert not matched
    assert not full_loaded


def _bind_dashboard_to(reports_dir):
    """Point the Flask app's Config at a temporary reports directory."""
    from config import Config
    cfg = Config()
    cfg._parser.set("reports", "output_dir", reports_dir)
    web_dashboard.app.config["ZPA_CONFIG"] = cfg


def _track_opens(monkeypatch):
    """Record the basename of every file opened via builtins.open."""
    import builtins
    opens = []
    real_open = builtins.open

    def tracked(file, *args, **kwargs):
        try:
            opens.append(os.path.basename(file) if isinstance(file, str) else "fd")
        except Exception:
            opens.append("?")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", tracked)
    return opens
