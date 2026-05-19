#!/usr/bin/env python3
"""ZPA Status Mini-SIEM — Web Dashboard.

Flask application providing a web interface for browsing ZPA session reports,
searching by username, and downloading Excel files. Protected by basic auth
over HTTPS with a self-signed certificate.
"""

import errno
import fcntl
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime, time as dtime, timedelta
from functools import wraps
from zoneinfo import ZoneInfo

import bcrypt
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from app_logger import get_logger
from config import Config

log = get_logger(__name__)

app = Flask(__name__)

# In-process lock prevents two concurrent generations under the same Flask
# worker. The on-disk sentinel below (fcntl.flock) covers cross-process
# collisions with the systemd timer.
_GEN_LOCK = threading.Lock()
_GEN_SENTINEL = ".ondemand-generation.lock"
_GEN_TIMEOUT_SECONDS = 300


def create_app(config_path=None):
    """Configure and return the Flask app."""
    config = Config(config_path)

    app.secret_key = secrets.token_hex(32)
    app.config["ZPA_CONFIG"] = config
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
        minutes=config.dashboard_session_timeout or 30
    )

    return app


# --- Auth ---


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        # Check session timeout
        last_active = session.get("last_active")
        if last_active:
            config = app.config["ZPA_CONFIG"]
            timeout = config.dashboard_session_timeout
            if timeout > 0:
                last_dt = datetime.fromisoformat(last_active)
                if datetime.now() - last_dt > timedelta(minutes=timeout):
                    session.clear()
                    flash("Session expired. Please log in again.")
                    return redirect(url_for("login"))
        session["last_active"] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        config = app.config["ZPA_CONFIG"]
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if (
            username == config.dashboard_username
            and config.dashboard_password_hash
            and bcrypt.checkpw(
                password.encode(), config.dashboard_password_hash.encode()
            )
        ):
            session["authenticated"] = True
            session["last_active"] = datetime.now().isoformat()
            session.permanent = True
            return redirect(url_for("index"))

        return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Report helpers ---


def _get_reports_dir():
    return os.path.abspath(app.config["ZPA_CONFIG"].output_dir)


def _local_now(config) -> datetime:
    """Current time in the configured timezone."""
    return datetime.now(ZoneInfo(config.timezone_name))


def _parse_cutoff(value: str) -> dtime:
    """Parse an 'HH:MM' string into a time. Falls back to 23:45 on bad input."""
    try:
        hh, mm = value.split(":")
        return dtime(int(hh), int(mm))
    except (ValueError, AttributeError):
        return dtime(23, 45)


def _on_demand_block_reason(config) -> str | None:
    """Return a human message if the on-demand button must be blocked, else None."""
    if not config.dashboard_enable_on_demand:
        return "On-demand generation is disabled in config.ini."
    cutoff = _parse_cutoff(config.dashboard_on_demand_cutoff)
    now_local = _local_now(config).time()
    if now_local >= cutoff:
        return (
            f"On-demand generation is paused after {cutoff.strftime('%H:%M')} "
            f"to avoid colliding with the nightly run. Please wait for the "
            f"midnight report."
        )
    return None


def _load_json_report(date_str):
    """Load a JSON report file. Returns dict or None."""
    reports_dir = _get_reports_dir()
    # Find the JSON file matching this date
    for filename in os.listdir(reports_dir):
        if filename.endswith(".json") and date_str in filename:
            path = os.path.join(reports_dir, filename)
            with open(path) as f:
                return json.load(f)
    return None


def _list_available_reports():
    """List all available report dates with session counts."""
    reports_dir = _get_reports_dir()
    if not os.path.isdir(reports_dir):
        return []

    reports = []
    date_pattern = re.compile(r"(\d{4}-\d{2}-\d{2})")
    seen_dates = set()

    for filename in sorted(os.listdir(reports_dir), reverse=True):
        if not filename.endswith(".json"):
            continue
        match = date_pattern.search(filename)
        if not match:
            continue
        date_str = match.group(1)
        if date_str in seen_dates:
            continue
        seen_dates.add(date_str)

        path = os.path.join(reports_dir, filename)
        try:
            with open(path) as f:
                data = json.load(f)
            session_count = len(data.get("sessions", []))
        except (json.JSONDecodeError, OSError):
            session_count = 0

        has_csv = any(
            f.endswith(".csv") and date_str in f
            for f in os.listdir(reports_dir)
        )
        reports.append({"date": date_str, "session_count": session_count, "has_csv": has_csv})

    reports.sort(key=lambda r: r["date"], reverse=True)
    return reports


# --- Routes ---


@app.route("/")
@login_required
def index():
    config = app.config["ZPA_CONFIG"]
    reports = _list_available_reports()
    today = _local_now(config).strftime("%Y-%m-%d")

    today_sessions = None
    today_date = None
    for r in reports:
        if r["date"] == today:
            data = _load_json_report(today)
            if data:
                today_sessions = data.get("sessions", [])
                today_date = today
            break

    return render_template(
        "report_list.html",
        reports=reports,
        today_sessions=today_sessions,
        today_date=today_date,
        today_str=today,
        on_demand_enabled=config.dashboard_enable_on_demand,
        on_demand_blocked_reason=_on_demand_block_reason(config),
    )


@app.route("/report/generate-today", methods=["POST"])
@login_required
def generate_today():
    config = app.config["ZPA_CONFIG"]

    blocked = _on_demand_block_reason(config)
    if blocked:
        flash(blocked)
        log.info("event=ondemand_blocked reason=%s", blocked)
        return redirect(url_for("index"))

    today = _local_now(config).strftime("%Y-%m-%d")

    # In-process lock: never block the request thread waiting for it.
    if not _GEN_LOCK.acquire(blocking=False):
        flash("A report generation is already in progress. Please wait and reload.")
        log.info("event=ondemand_skipped reason=in_process_lock_busy date=%s", today)
        return redirect(url_for("index"))

    sentinel_path = os.path.join(_get_reports_dir(), _GEN_SENTINEL)
    sentinel_fd = None
    try:
        try:
            os.makedirs(_get_reports_dir(), exist_ok=True)
            sentinel_fd = os.open(
                sentinel_path, os.O_RDWR | os.O_CREAT, 0o644
            )
            fcntl.flock(sentinel_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                flash(
                    "Another report generation is already running on this server "
                    "(possibly the scheduled job). Please retry shortly."
                )
                log.info(
                    "event=ondemand_skipped reason=file_lock_busy date=%s", today
                )
            else:
                flash(f"Could not acquire generation lock: {exc}")
                log.error(
                    "event=ondemand_failed reason=lock_error date=%s error=%s",
                    today, exc,
                )
            if sentinel_fd is not None:
                os.close(sentinel_fd)
                sentinel_fd = None
            return redirect(url_for("index"))

        script_dir = os.path.dirname(os.path.abspath(__file__))
        generator = os.path.join(script_dir, "report_generator.py")
        if not os.path.exists(generator):
            flash(f"report_generator.py not found at {generator}.")
            log.error("event=ondemand_failed reason=generator_missing path=%s", generator)
            return redirect(url_for("index"))

        cmd = [
            sys.executable, generator,
            "--date", today,
            "--log-dir", config.log_dir,
            "--output-dir", config.output_dir,
            "--no-upload",
        ]
        if config.path:
            cmd += ["--config", config.path]

        log.info("event=ondemand_started date=%s", today)
        started = time.monotonic()
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=_GEN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.monotonic() - started) * 1000)
            flash(
                f"Generation timed out after {_GEN_TIMEOUT_SECONDS // 60} minutes. "
                f"Check /var/log/zpa-siem/app.log for details."
            )
            log.error(
                "event=ondemand_failed reason=timeout date=%s duration_ms=%d",
                today, duration_ms,
            )
            return redirect(url_for("index"))

        duration_ms = int((time.monotonic() - started) * 1000)

        if result.returncode == 0:
            data = _load_json_report(today)
            session_count = len(data.get("sessions", [])) if data else 0
            if session_count:
                flash(f"Today's report regenerated ({session_count} sessions).")
            else:
                flash(
                    "No user sessions recorded for today yet. The report is empty; "
                    "please retry later."
                )
            log.info(
                "event=ondemand_complete date=%s sessions=%d duration_ms=%d",
                today, session_count, duration_ms,
            )
        else:
            tail = (result.stderr or result.stdout or "").strip().splitlines()[-3:]
            detail = " | ".join(tail) if tail else f"exit code {result.returncode}"
            flash(f"Generation failed: {detail}")
            log.error(
                "event=ondemand_failed reason=nonzero_exit date=%s exit=%d "
                "duration_ms=%d detail=%s",
                today, result.returncode, duration_ms, detail,
            )

        return redirect(url_for("index"))
    finally:
        if sentinel_fd is not None:
            try:
                fcntl.flock(sentinel_fd, fcntl.LOCK_UN)
            finally:
                os.close(sentinel_fd)
        _GEN_LOCK.release()


@app.route("/report/<date>")
@login_required
def report(date):
    data = _load_json_report(date)
    if data is None:
        flash(f"Report not found for {date}.")
        return redirect(url_for("index"))

    reports_dir = _get_reports_dir()
    has_csv = any(
        f.endswith(".csv") and date in f
        for f in os.listdir(reports_dir)
    )

    return render_template(
        "report.html",
        date=date,
        sessions=data.get("sessions", []),
        timezone=data.get("timezone", ""),
        generated_at=data.get("generated_at", ""),
        has_csv=has_csv,
    )


@app.route("/report/<date>/download")
@login_required
def download(date):
    return _download_report(date, ".xlsx")


@app.route("/report/<date>/download/csv")
@login_required
def download_csv(date):
    return _download_report(date, ".csv")


def _download_report(date, ext):
    reports_dir = _get_reports_dir()
    for filename in os.listdir(reports_dir):
        if filename.endswith(ext) and date in filename:
            return send_file(
                os.path.join(reports_dir, filename),
                as_attachment=True,
                download_name=filename,
            )
    label = "CSV" if ext == ".csv" else "Excel"
    flash(f"{label} file not found for {date}.")
    return redirect(url_for("index"))


@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "").strip()
    if not query:
        return render_template("search.html", query=None, results=None)

    reports_dir = _get_reports_dir()
    results = []

    if os.path.isdir(reports_dir):
        for filename in sorted(os.listdir(reports_dir), reverse=True):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(reports_dir, filename)
            try:
                with open(path) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            for s in data.get("sessions", []):
                if query.lower() in s.get("username", "").lower():
                    results.append(s)

    # Sort by date desc, then session start
    results.sort(key=lambda s: (s.get("date", ""), s.get("session_start", "")), reverse=True)

    return render_template("search.html", query=query, results=results)


# --- Main ---


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ZPA Mini-SIEM Web Dashboard")
    parser.add_argument("--config", default=None, help="Path to config.ini")
    args = parser.parse_args()

    create_app(args.config)
    config = app.config["ZPA_CONFIG"]

    ssl_ctx = None
    cert_dir = os.path.join(os.path.dirname(config.path), "certs")
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")
    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_ctx = (cert_file, key_file)

    app.run(
        host="0.0.0.0",
        port=config.dashboard_port,
        ssl_context=ssl_ctx,
    )
