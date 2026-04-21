#!/usr/bin/env bash
# install.sh — ZPA Status Mini-SIEM installer for RHEL 9/10
#
# Interactive installer that configures:
#   - rsyslog drop-in config for ZPA syslog reception
#   - logrotate policy (30-day retention, daily rotation, gzip)
#   - Firewall rules
#   - Python venv + application in /opt/zpa-siem/
#   - systemd timer for daily report generation
#   - HTTPS self-signed certificate for web dashboard
#   - systemd service for web dashboard
#
# Usage:
#   sudo bash install.sh              # Full interactive install
#   sudo bash install.sh --configure  # Reconfigure only
#   sudo bash install.sh --status     # Show service status
#   sudo bash install.sh --uninstall  # Remove installation
#
# This script is idempotent — safe to run multiple times.

set -euo pipefail

# ---------- constants ----------

INSTALL_DIR="/opt/zpa-siem"
CONFIG_FILE="$INSTALL_DIR/config.ini"
CERT_DIR="$INSTALL_DIR/certs"
VENV_DIR="$INSTALL_DIR/venv"
REPORTS_DIR="$INSTALL_DIR/reports"

# ---------- colors ----------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

header()  { echo -e "\n${BLUE}${BOLD}═══ $1 ═══${NC}\n"; }
info()    { echo -e "  ${CYAN}▸${NC} $1"; }
success() { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
error()   { echo -e "  ${RED}✗${NC} $1" >&2; }

# ---------- checks ----------

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root."
    echo "  Usage: sudo bash install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- validation functions (T020) ----------

validate_timezone() {
    local tz="$1"
    TZ_INPUT="$tz" python3 -c "import os; from zoneinfo import ZoneInfo; ZoneInfo(os.environ['TZ_INPUT'])" 2>/dev/null
}

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

validate_schedule() {
    local schedule="$1"
    [[ "$schedule" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]
}

# ---------- prompt helper ----------

prompt() {
    local var_name="$1"
    local prompt_text="$2"
    local default="$3"
    local value

    read -rp "  ${prompt_text} [${default}]: " value
    value="${value:-$default}"
    printf -v "$var_name" '%s' "$value"
}

prompt_password() {
    local var_name="$1"
    local prompt_text="$2"
    local has_existing="$3"    # "true" if an existing hash can be kept
    local value

    while true; do
        if [ "$has_existing" = "true" ]; then
            read -rsp "  ${prompt_text} (Enter to keep current): " value
        else
            read -rsp "  ${prompt_text}: " value
        fi
        echo
        if [ -z "$value" ]; then
            if [ "$has_existing" = "true" ]; then
                printf -v "$var_name" '%s' ""
                return
            fi
            warn "Password cannot be empty."
            continue
        fi
        local confirm
        read -rsp "  Confirm password: " confirm
        echo
        if [ "$value" != "$confirm" ]; then
            warn "Passwords do not match. Try again."
            continue
        fi
        break
    done
    printf -v "$var_name" '%s' "$value"
}

prompt_yesno() {
    local var_name="$1"
    local prompt_text="$2"
    local default="$3"
    local value

    read -rp "  ${prompt_text} [${default}]: " value
    value="${value:-$default}"
    value=$(echo "$value" | tr '[:upper:]' '[:lower:]')
    if [[ "$value" == "y" || "$value" == "yes" || "$value" == "true" ]]; then
        printf -v "$var_name" '%s' "true"
    else
        printf -v "$var_name" '%s' "false"
    fi
}

# ---------- load existing config ----------

load_existing_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # Read values from existing config using python, safely via while-read
        while IFS='=' read -r key val; do
            printf -v "$key" '%s' "$val"
        done < <(python3 -c "
import configparser, shlex
c = configparser.ConfigParser()
c.read('$CONFIG_FILE')
for section in c.sections():
    for key, val in c.items(section):
        print(f'EXISTING_{section.upper()}_{key.upper()}={val}')
" 2>/dev/null || true)
        return 0
    fi
    return 1
}

# ---------- mode dispatch ----------

case "${1:-}" in
    --status)
        header "ZPA Status Mini-SIEM — Status"
        echo
        info "Services:"
        echo -e "  rsyslog:        $(systemctl is-active rsyslog 2>/dev/null || echo 'not found')"
        echo -e "  zpa-report.timer: $(systemctl is-active zpa-report.timer 2>/dev/null || echo 'not found')"
        echo -e "  zpa-dashboard:  $(systemctl is-active zpa-dashboard 2>/dev/null || echo 'not found')"
        echo
        if [ -f "$CONFIG_FILE" ]; then
            info "Configuration ($CONFIG_FILE):"
            python3 -c "
import configparser
c = configparser.ConfigParser()
c.read('$CONFIG_FILE')
for section in c.sections():
    print(f'  [{section}]')
    for key, val in c.items(section):
        if 'password' in key.lower():
            val = '****'
        print(f'    {key} = {val}')
" 2>/dev/null || warn "Could not read config."
        else
            warn "Config file not found: $CONFIG_FILE"
        fi
        echo
        if command -v zpa-siem-ctl &>/dev/null; then
            success "CLI tool: zpa-siem-ctl installed"
        else
            warn "CLI tool: zpa-siem-ctl not found in PATH"
        fi
        echo
        if [ -d "$REPORTS_DIR" ]; then
            local_count=$(find "$REPORTS_DIR" -name "*.xlsx" 2>/dev/null | wc -l)
            info "Reports: $local_count Excel files in $REPORTS_DIR"
        fi
        exit 0
        ;;
    --uninstall)
        header "ZPA Status Mini-SIEM — Uninstall"
        echo
        warn "This will remove:"
        echo "    - $INSTALL_DIR (application, config, reports, certs)"
        echo "    - systemd units (zpa-report, zpa-dashboard)"
        echo "    - /etc/rsyslog.d/10-zpa.conf"
        echo "    - /etc/logrotate.d/zpa"
        echo
        read -rp "  Are you sure? Type 'yes' to confirm: " confirm
        if [ "$confirm" != "yes" ]; then
            info "Uninstall cancelled."
            exit 0
        fi
        echo
        systemctl stop zpa-report.timer 2>/dev/null || true
        systemctl stop zpa-dashboard 2>/dev/null || true
        systemctl disable zpa-report.timer 2>/dev/null || true
        systemctl disable zpa-dashboard 2>/dev/null || true
        rm -f /etc/systemd/system/zpa-report.service
        rm -f /etc/systemd/system/zpa-report.timer
        rm -f /etc/systemd/system/zpa-dashboard.service
        systemctl daemon-reload
        rm -f /etc/rsyslog.d/10-zpa.conf
        rm -f /etc/logrotate.d/zpa
        rm -f /usr/local/bin/zpa-siem-ctl
        rm -rf "$INSTALL_DIR"
        success "ZPA Status Mini-SIEM uninstalled."
        info "Syslog logs in /var/log/zpa/ were preserved."
        exit 0
        ;;
    --configure)
        CONFIGURE_ONLY=true
        ;;
    "")
        CONFIGURE_ONLY=false
        ;;
    *)
        error "Unknown option: $1"
        echo "  Usage: sudo bash install.sh [--configure|--status|--uninstall]"
        exit 1
        ;;
esac

# ---------- banner ----------

header "ZPA Status Mini-SIEM — Installer"

if [ "$CONFIGURE_ONLY" = true ]; then
    info "Reconfiguration mode — updating settings only."
    if [ ! -f "$CONFIG_FILE" ]; then
        error "No existing config found. Run a full install first."
        exit 1
    fi
fi

# ---------- load existing config for defaults ----------

EXISTING_GENERAL_TIMEZONE="UTC"
EXISTING_GENERAL_MAX_CLIENT_VERSION="10"
EXISTING_SYSLOG_PORT="514"
EXISTING_SYSLOG_PROTOCOL="tcp"
EXISTING_REPORTS_SCHEDULE="06:00"
EXISTING_REPORTS_RETENTION_DAYS="180"
EXISTING_REPORTS_FILENAME_PATTERN="zpa-report-{date}"
EXISTING_DASHBOARD_ENABLED="true"
EXISTING_DASHBOARD_PORT="8443"
EXISTING_DASHBOARD_USERNAME="admin"
EXISTING_DASHBOARD_SESSION_TIMEOUT="30"
EXISTING_SHARE_ENABLED="false"
EXISTING_SHARE_METHOD="smb"
EXISTING_SHARE_FORMAT="xlsx"
EXISTING_SHARE_SMB_SHARE=""
EXISTING_SHARE_SMB_USERNAME=""
EXISTING_SHARE_SMB_PASSWORD=""
EXISTING_SHARE_SMB_DOMAIN=""
EXISTING_SHARE_SCP_TARGET=""

load_existing_config 2>/dev/null || true

# ---------- interactive prompts ----------

header "General Settings"

while true; do
    prompt CFG_TIMEZONE "Timezone (e.g., Europe/Rome, America/New_York)" "$EXISTING_GENERAL_TIMEZONE"
    if validate_timezone "$CFG_TIMEZONE"; then
        break
    fi
    warn "Invalid timezone: $CFG_TIMEZONE"
done

prompt CFG_MAX_CLIENT_VERSION "Max client version major (ignore logs with major version above this, 0=disabled)" "$EXISTING_GENERAL_MAX_CLIENT_VERSION"

header "Syslog Settings"

while true; do
    prompt CFG_SYSLOG_PORT "Syslog port" "$EXISTING_SYSLOG_PORT"
    if validate_port "$CFG_SYSLOG_PORT"; then
        break
    fi
    warn "Invalid port: $CFG_SYSLOG_PORT (must be 1-65535)"
done

prompt CFG_SYSLOG_PROTOCOL "Syslog protocol (tcp/udp)" "$EXISTING_SYSLOG_PROTOCOL"

header "Report Settings"

CFG_SCHEDULE="00:05"
info "Report generation: daily at 00:05 (covers previous day, midnight to midnight)"

prompt CFG_RETENTION "Report retention (days)" "$EXISTING_REPORTS_RETENTION_DAYS"
prompt CFG_FILENAME "Report filename pattern ({date} = YYYY-MM-DD)" "$EXISTING_REPORTS_FILENAME_PATTERN"

header "Web Dashboard"

prompt_yesno CFG_DASHBOARD_ENABLED "Enable web dashboard? (yes/no)" \
    "$([ "$EXISTING_DASHBOARD_ENABLED" = "true" ] && echo "yes" || echo "no")"

if [ "$CFG_DASHBOARD_ENABLED" = true ]; then
    while true; do
        prompt CFG_DASHBOARD_PORT "Dashboard HTTPS port" "$EXISTING_DASHBOARD_PORT"
        if validate_port "$CFG_DASHBOARD_PORT"; then
            break
        fi
        warn "Invalid port: $CFG_DASHBOARD_PORT"
    done

    prompt CFG_DASHBOARD_USERNAME "Dashboard username" "$EXISTING_DASHBOARD_USERNAME"

    # Check if an existing password hash is available (re-install / reconfigure)
    HAS_EXISTING_HASH="false"
    if [ -n "$EXISTING_DASHBOARD_PASSWORD_HASH" ] && [ "$EXISTING_DASHBOARD_PASSWORD_HASH" != '""' ]; then
        HAS_EXISTING_HASH="true"
    fi

    prompt_password CFG_DASHBOARD_PASSWORD "Dashboard password" "$HAS_EXISTING_HASH"
    prompt CFG_DASHBOARD_TIMEOUT "Session timeout (minutes, 0=no timeout)" "$EXISTING_DASHBOARD_SESSION_TIMEOUT"

    if [ -z "$CFG_DASHBOARD_PASSWORD" ] && [ "$HAS_EXISTING_HASH" = "true" ]; then
        # Keep existing hash — no re-hashing needed
        CFG_DASHBOARD_HASH="$EXISTING_DASHBOARD_PASSWORD_HASH"
    else
        # New password — will be hashed after venv is created (bcrypt not available in system Python)
        CFG_DASHBOARD_HASH="__PENDING__"
    fi
else
    CFG_DASHBOARD_PORT="$EXISTING_DASHBOARD_PORT"
    CFG_DASHBOARD_USERNAME="$EXISTING_DASHBOARD_USERNAME"
    CFG_DASHBOARD_HASH=""
    CFG_DASHBOARD_TIMEOUT="$EXISTING_DASHBOARD_SESSION_TIMEOUT"
fi

header "File Share Upload"

prompt_yesno CFG_SHARE_ENABLED "Enable report upload to file share? (yes/no)" \
    "$([ "$EXISTING_SHARE_ENABLED" = "true" ] && echo "yes" || echo "no")"

CFG_SHARE_METHOD="$EXISTING_SHARE_METHOD"
CFG_SHARE_FORMAT="$EXISTING_SHARE_FORMAT"
CFG_SMB_SHARE="$EXISTING_SHARE_SMB_SHARE"
CFG_SMB_USERNAME="$EXISTING_SHARE_SMB_USERNAME"
CFG_SMB_PASSWORD="$EXISTING_SHARE_SMB_PASSWORD"
CFG_SMB_DOMAIN="$EXISTING_SHARE_SMB_DOMAIN"
CFG_SCP_TARGET="$EXISTING_SHARE_SCP_TARGET"

if [ "$CFG_SHARE_ENABLED" = true ]; then
    prompt CFG_SHARE_METHOD "Upload method (smb/scp)" "$EXISTING_SHARE_METHOD"
    prompt CFG_SHARE_FORMAT "Upload file format (xlsx/csv)" "$EXISTING_SHARE_FORMAT"

    if [ "$CFG_SHARE_METHOD" = "smb" ]; then
        prompt CFG_SMB_SHARE "SMB share path (e.g., //server/share)" "$EXISTING_SHARE_SMB_SHARE"
        prompt CFG_SMB_USERNAME "SMB username" "$EXISTING_SHARE_SMB_USERNAME"
        read -rsp "  SMB password: " CFG_SMB_PASSWORD
        echo
        prompt CFG_SMB_DOMAIN "SMB domain (leave empty if not needed)" "$EXISTING_SHARE_SMB_DOMAIN"
    elif [ "$CFG_SHARE_METHOD" = "scp" ]; then
        prompt CFG_SCP_TARGET "SCP target (user@host:/path)" "$EXISTING_SHARE_SCP_TARGET"
    fi
fi

# ---------- confirm ----------

header "Configuration Summary"

echo -e "  Timezone:       ${BOLD}$CFG_TIMEZONE${NC}"
echo -e "  Max version:    ${BOLD}$CFG_MAX_CLIENT_VERSION${NC} (0=disabled)"
echo -e "  Syslog:         ${BOLD}$CFG_SYSLOG_PROTOCOL/$CFG_SYSLOG_PORT${NC}"
echo -e "  Report time:    ${BOLD}00:05 (midnight-to-midnight)${NC}"
echo -e "  Retention:      ${BOLD}$CFG_RETENTION days${NC}"
echo -e "  Filename:       ${BOLD}$CFG_FILENAME${NC}"
echo -e "  Dashboard:      ${BOLD}$CFG_DASHBOARD_ENABLED${NC}"
if [ "$CFG_DASHBOARD_ENABLED" = true ]; then
    echo -e "  Dashboard port: ${BOLD}$CFG_DASHBOARD_PORT${NC}"
    echo -e "  Dashboard user: ${BOLD}$CFG_DASHBOARD_USERNAME${NC}"
fi
echo -e "  Share upload:   ${BOLD}$CFG_SHARE_ENABLED${NC}"
if [ "$CFG_SHARE_ENABLED" = true ]; then
    echo -e "  Share method:   ${BOLD}$CFG_SHARE_METHOD${NC}"
    echo -e "  Share format:   ${BOLD}$CFG_SHARE_FORMAT${NC}"
fi
echo

read -rp "  Proceed with installation? [yes]: " proceed
proceed="${proceed:-yes}"
if [[ "$proceed" != "yes" && "$proceed" != "y" ]]; then
    info "Installation cancelled."
    exit 0
fi

# ============================================================
# INSTALLATION
# ============================================================

if [ "$CONFIGURE_ONLY" = false ]; then

    # ---------- 1. rsyslog ----------

    header "Configuring rsyslog"

    mkdir -p /var/log/zpa
    chmod 750 /var/log/zpa

    cp "$SCRIPT_DIR/config/rsyslog-zpa.conf" /etc/rsyslog.d/10-zpa.conf
    chmod 644 /etc/rsyslog.d/10-zpa.conf

    systemctl restart rsyslog
    success "rsyslog configured and restarted."

    # ---------- 2. logrotate ----------

    header "Configuring logrotate"

    cp "$SCRIPT_DIR/config/logrotate-zpa" /etc/logrotate.d/zpa
    chmod 644 /etc/logrotate.d/zpa

    success "logrotate configured."

    # ---------- 3. firewall ----------

    header "Configuring firewall"

    if command -v firewall-cmd &>/dev/null; then
        # Syslog port
        if firewall-cmd --query-port="${CFG_SYSLOG_PORT}/${CFG_SYSLOG_PROTOCOL}" --quiet 2>/dev/null; then
            info "${CFG_SYSLOG_PROTOCOL^^}/${CFG_SYSLOG_PORT} already open."
        else
            firewall-cmd --add-port="${CFG_SYSLOG_PORT}/${CFG_SYSLOG_PROTOCOL}" --permanent --quiet
            success "${CFG_SYSLOG_PROTOCOL^^}/${CFG_SYSLOG_PORT} opened."
        fi
        # Dashboard port
        if [ "$CFG_DASHBOARD_ENABLED" = true ]; then
            if firewall-cmd --query-port="${CFG_DASHBOARD_PORT}/tcp" --quiet 2>/dev/null; then
                info "TCP/${CFG_DASHBOARD_PORT} (dashboard) already open."
            else
                firewall-cmd --add-port="${CFG_DASHBOARD_PORT}/tcp" --permanent --quiet
                success "TCP/${CFG_DASHBOARD_PORT} (dashboard) opened."
            fi
        fi
        firewall-cmd --reload --quiet
    else
        warn "firewall-cmd not found — skipping firewall configuration."
    fi

    # ---------- 4. python venv + application ----------

    header "Installing application"

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$REPORTS_DIR"

    if [ ! -d "$VENV_DIR" ]; then
        python3 -m venv "$VENV_DIR"
        success "Python virtual environment created."
    else
        info "Virtual environment already exists."
    fi

    "$VENV_DIR/bin/pip" install --quiet --upgrade pip

    # Vendored deps (T018)
    if [ -d "$SCRIPT_DIR/vendor" ] && ls "$SCRIPT_DIR/vendor"/*.whl 1>/dev/null 2>&1; then
        info "Installing from vendored dependencies..."
        "$VENV_DIR/bin/pip" install --quiet --no-index --find-links "$SCRIPT_DIR/vendor" -r "$SCRIPT_DIR/requirements.txt"
        success "Dependencies installed (offline)."
    else
        info "Installing dependencies from PyPI..."
        "$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
        success "Dependencies installed (online)."
    fi

    # Copy application files
    for pyfile in report_generator.py session_parser.py config.py share_upload.py web_dashboard.py zpa_siem_ctl.py; do
        if [ -f "$SCRIPT_DIR/src/$pyfile" ]; then
            cp "$SCRIPT_DIR/src/$pyfile" "$INSTALL_DIR/$pyfile"
        fi
    done

    # Copy templates directory (remove old first to avoid nested copy)
    if [ -d "$SCRIPT_DIR/src/templates" ]; then
        rm -rf "$INSTALL_DIR/templates"
        cp -r "$SCRIPT_DIR/src/templates" "$INSTALL_DIR/templates"
    fi

    success "Application files installed to $INSTALL_DIR."

    # CLI tool: zpa-siem-ctl → /usr/local/bin
    cat > /usr/local/bin/zpa-siem-ctl <<'CTLEOF'
#!/usr/bin/env bash
exec /opt/zpa-siem/venv/bin/python3 /opt/zpa-siem/zpa_siem_ctl.py "$@"
CTLEOF
    chmod +x /usr/local/bin/zpa-siem-ctl
    success "CLI tool installed: zpa-siem-ctl"

    # ---------- 5. HTTPS certificates (T017) ----------

    header "HTTPS Certificates"

    mkdir -p "$CERT_DIR"

    if [ -f "$CERT_DIR/cert.pem" ] && [ -f "$CERT_DIR/key.pem" ]; then
        info "Certificates already exist — skipping generation."
    else
        openssl req -x509 -newkey rsa:2048 \
            -keyout "$CERT_DIR/key.pem" \
            -out "$CERT_DIR/cert.pem" \
            -days 3650 -nodes \
            -subj "/CN=zpa-siem/O=ZPA-SIEM" 2>/dev/null
        chmod 600 "$CERT_DIR/key.pem"
        chmod 644 "$CERT_DIR/cert.pem"
        success "Self-signed certificate generated (valid 10 years)."
    fi

fi  # end if not configure-only

# ---------- hash dashboard password (needs venv with bcrypt) ----------

if [ "$CFG_DASHBOARD_HASH" = "__PENDING__" ]; then
    if [ ! -f "$VENV_DIR/bin/python3" ]; then
        # In configure mode, venv should already exist
        error "Python venv not found at $VENV_DIR. Run a full install first."
        exit 1
    fi
    CFG_DASHBOARD_HASH=$(printf '%s' "$CFG_DASHBOARD_PASSWORD" | "$VENV_DIR/bin/python3" -c "import sys,bcrypt; print(bcrypt.hashpw(sys.stdin.buffer.read(),bcrypt.gensalt()).decode())")
    unset CFG_DASHBOARD_PASSWORD
fi

# ---------- 6. generate config.ini (T015) ----------

header "Generating configuration"

cat > "$CONFIG_FILE" <<CFGEOF
# ZPA Status Mini-SIEM Configuration
# Generated by install.sh on $(date '+%Y-%m-%d %H:%M:%S')
# Edit manually or re-run: install.sh --configure

[general]
# IANA timezone for report timestamps (e.g., Europe/Rome, America/New_York, UTC)
timezone = $CFG_TIMEZONE
# Ignore logs from clients with major version above this value (0 = no filter)
# Useful to filter out VM noise (e.g., version 25.x) while keeping real clients (e.g., 4.x)
max_client_version = $CFG_MAX_CLIENT_VERSION

[syslog]
# Syslog reception port
port = $CFG_SYSLOG_PORT
# Protocol: tcp or udp
protocol = $CFG_SYSLOG_PROTOCOL
# Directory where rsyslog writes ZPA log files
log_dir = /var/log/zpa

[reports]
# Directory for generated Excel and JSON reports
output_dir = $REPORTS_DIR
# Daily report generation time (HH:MM, 24-hour format)
schedule = $CFG_SCHEDULE
# Days to keep generated reports (older reports auto-deleted)
retention_days = $CFG_RETENTION
# Report filename template ({date} replaced with YYYY-MM-DD)
filename_pattern = $CFG_FILENAME

[dashboard]
# Enable web dashboard (true/false)
enabled = $CFG_DASHBOARD_ENABLED
# HTTPS port
port = $CFG_DASHBOARD_PORT
# Login username
username = $CFG_DASHBOARD_USERNAME
# Bcrypt-hashed password (change via: install.sh --configure)
password_hash = $CFG_DASHBOARD_HASH
# Session timeout in minutes (0 = no timeout)
session_timeout = $CFG_DASHBOARD_TIMEOUT

[share]
# Enable report upload to file share (true/false)
enabled = $CFG_SHARE_ENABLED
# Upload method: smb or scp
method = $CFG_SHARE_METHOD
# File format to upload: xlsx or csv
format = $CFG_SHARE_FORMAT
# SMB settings
smb_share = $CFG_SMB_SHARE
smb_username = $CFG_SMB_USERNAME
smb_password = $CFG_SMB_PASSWORD
smb_domain = $CFG_SMB_DOMAIN
# SCP settings
scp_target = $CFG_SCP_TARGET
CFGEOF

chmod 600 "$CONFIG_FILE"
success "Configuration saved to $CONFIG_FILE"

# ---------- 7. systemd units (T019) ----------

header "Configuring systemd"

# Report service — finds all log files covering yesterday and date-filters
cat > /etc/systemd/system/zpa-report.service <<'EOF'
[Unit]
Description=ZPA Status Mini-SIEM — daily report generator
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/zpa-siem/venv/bin/python3 /opt/zpa-siem/report_generator.py
WorkingDirectory=/opt/zpa-siem
EOF

# Report timer — fixed at 00:05, covers previous day midnight-to-midnight
cat > /etc/systemd/system/zpa-report.timer <<'EOF'
[Unit]
Description=Run ZPA report generator daily after midnight

[Timer]
OnCalendar=*-*-* 00:05:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --quiet zpa-report.timer
systemctl restart zpa-report.timer
success "Report timer set to daily at 00:05 (midnight-to-midnight coverage)."

# Dashboard service
if [ "$CFG_DASHBOARD_ENABLED" = true ]; then
    cat > /etc/systemd/system/zpa-dashboard.service <<EOF
[Unit]
Description=ZPA Status Mini-SIEM — web dashboard
After=network.target

[Service]
Type=simple
ExecStart=$VENV_DIR/bin/python3 $INSTALL_DIR/web_dashboard.py
WorkingDirectory=$INSTALL_DIR
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --quiet zpa-dashboard
    systemctl restart zpa-dashboard 2>/dev/null || warn "Dashboard service not started (web_dashboard.py may not exist yet)."
    success "Dashboard service enabled on port $CFG_DASHBOARD_PORT."
else
    systemctl stop zpa-dashboard 2>/dev/null || true
    systemctl disable zpa-dashboard 2>/dev/null || true
    rm -f /etc/systemd/system/zpa-dashboard.service
    systemctl daemon-reload
    info "Dashboard disabled."
fi

# ---------- done ----------

header "Installation Complete"

echo -e "  ${GREEN}Syslog:${NC}    rsyslog listening on ${CFG_SYSLOG_PROTOCOL^^}/${CFG_SYSLOG_PORT} → /var/log/zpa/"
echo -e "  ${GREEN}Rotate:${NC}    daily, 30-day retention, gzip"
echo -e "  ${GREEN}Reports:${NC}   daily at $CFG_SCHEDULE → $REPORTS_DIR"
echo -e "  ${GREEN}Retention:${NC} $CFG_RETENTION days"
if [ "$CFG_DASHBOARD_ENABLED" = true ]; then
    echo -e "  ${GREEN}Dashboard:${NC} https://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):$CFG_DASHBOARD_PORT"
fi
if [ "$CFG_SHARE_ENABLED" = true ]; then
    echo -e "  ${GREEN}Share:${NC}     $CFG_SHARE_METHOD upload enabled ($CFG_SHARE_FORMAT format)"
fi
echo -e "  ${GREEN}Config:${NC}    $CONFIG_FILE"
echo
echo -e "  Manage: ${BOLD}install.sh --status${NC} | ${BOLD}--configure${NC} | ${BOLD}--uninstall${NC}"
echo
