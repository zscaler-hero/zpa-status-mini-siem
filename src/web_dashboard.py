#!/usr/bin/env python3
"""ZPA Status Mini-SIEM — Web Dashboard.

Flask application providing a web interface for browsing ZPA session reports,
searching by username, and downloading Excel files. Protected by basic auth
over HTTPS with a self-signed certificate.
"""

import json
import os
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps

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

from config import Config

app = Flask(__name__)


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

        reports.append({"date": date_str, "session_count": session_count})

    reports.sort(key=lambda r: r["date"], reverse=True)
    return reports


# --- Routes ---


@app.route("/")
@login_required
def index():
    reports = _list_available_reports()
    today = datetime.now().strftime("%Y-%m-%d")

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
    )


@app.route("/report/<date>")
@login_required
def report(date):
    data = _load_json_report(date)
    if data is None:
        flash(f"Report not found for {date}.")
        return redirect(url_for("index"))

    return render_template(
        "report.html",
        date=date,
        sessions=data.get("sessions", []),
        timezone=data.get("timezone", ""),
        generated_at=data.get("generated_at", ""),
    )


@app.route("/report/<date>/download")
@login_required
def download(date):
    reports_dir = _get_reports_dir()
    for filename in os.listdir(reports_dir):
        if filename.endswith(".xlsx") and date in filename:
            return send_file(
                os.path.join(reports_dir, filename),
                as_attachment=True,
                download_name=filename,
            )
    flash(f"Excel file not found for {date}.")
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
