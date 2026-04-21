"""Configuration loader for ZPA Status Mini-SIEM.

Reads config.ini and provides typed access to all settings with fallback defaults.
"""

import configparser
import os
from typing import Optional
from zoneinfo import ZoneInfo

DEFAULT_CONFIG_PATH = "/opt/zpa-siem/config.ini"

DEFAULTS = {
    "general": {
        "timezone": "UTC",
        "max_client_version": "10",
    },
    "syslog": {
        "port": "514",
        "protocol": "tcp",
        "log_dir": "/var/log/zpa",
    },
    "reports": {
        "output_dir": "/opt/zpa-siem/reports",
        "schedule": "06:00",
        "retention_days": "180",
        "filename_pattern": "zpa-report-{date}",
    },
    "dashboard": {
        "enabled": "true",
        "port": "8443",
        "username": "admin",
        "password_hash": "",
        "session_timeout": "30",
    },
    "share": {
        "enabled": "false",
        "method": "smb",
        "format": "xlsx",
        "smb_share": "",
        "smb_username": "",
        "smb_password": "",
        "smb_domain": "",
        "scp_target": "",
    },
}


class Config:
    """Configuration wrapper with typed accessors."""

    def __init__(self, path: Optional[str] = None):
        self._parser = configparser.ConfigParser()
        # Set defaults for all sections
        for section, values in DEFAULTS.items():
            if not self._parser.has_section(section):
                self._parser.add_section(section)
            for key, val in values.items():
                self._parser.set(section, key, val)

        # Load config file if it exists
        if path is None:
            path = os.getenv("ZPA_SIEM_CONFIG", DEFAULT_CONFIG_PATH)
        if os.path.exists(path):
            self._parser.read(path)
        self.path = path

    def _get(self, section: str, key: str) -> str:
        return self._parser.get(section, key)

    def _getint(self, section: str, key: str) -> int:
        return self._parser.getint(section, key)

    def _getbool(self, section: str, key: str) -> bool:
        return self._parser.getboolean(section, key)

    # --- general ---
    @property
    def timezone(self) -> ZoneInfo:
        return ZoneInfo(self._get("general", "timezone"))

    @property
    def timezone_name(self) -> str:
        return self._get("general", "timezone")

    @property
    def max_client_version(self) -> int:
        return self._getint("general", "max_client_version")

    # --- syslog ---
    @property
    def syslog_port(self) -> int:
        return self._getint("syslog", "port")

    @property
    def syslog_protocol(self) -> str:
        return self._get("syslog", "protocol")

    @property
    def log_dir(self) -> str:
        return self._get("syslog", "log_dir")

    # --- reports ---
    @property
    def output_dir(self) -> str:
        return self._get("reports", "output_dir")

    @property
    def schedule(self) -> str:
        return self._get("reports", "schedule")

    @property
    def retention_days(self) -> int:
        return self._getint("reports", "retention_days")

    @property
    def filename_pattern(self) -> str:
        return self._get("reports", "filename_pattern")

    # --- dashboard ---
    @property
    def dashboard_enabled(self) -> bool:
        return self._getbool("dashboard", "enabled")

    @property
    def dashboard_port(self) -> int:
        return self._getint("dashboard", "port")

    @property
    def dashboard_username(self) -> str:
        return self._get("dashboard", "username")

    @property
    def dashboard_password_hash(self) -> str:
        return self._get("dashboard", "password_hash")

    @property
    def dashboard_session_timeout(self) -> int:
        return self._getint("dashboard", "session_timeout")

    # --- share ---
    @property
    def share_enabled(self) -> bool:
        return self._getbool("share", "enabled")

    @property
    def share_method(self) -> str:
        return self._get("share", "method")

    @property
    def share_format(self) -> str:
        return self._get("share", "format")

    @property
    def smb_share(self) -> str:
        return self._get("share", "smb_share")

    @property
    def smb_username(self) -> str:
        return self._get("share", "smb_username")

    @property
    def smb_password(self) -> str:
        return self._get("share", "smb_password")

    @property
    def smb_domain(self) -> str:
        return self._get("share", "smb_domain")

    @property
    def scp_target(self) -> str:
        return self._get("share", "scp_target")
