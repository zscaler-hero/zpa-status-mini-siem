"""File share upload for ZPA Status Mini-SIEM.

Supports uploading reports to SMB/CIFS shares (via smbclient) and SCP targets.
"""

import os
import subprocess


def upload_report(file_path: str, config) -> tuple[bool, str]:
    """Upload a report file to the configured share.

    Returns (success, message) tuple.
    """
    if not os.path.exists(file_path):
        return False, f"File not found: {file_path}"

    method = config.share_method.lower()
    if method == "smb":
        return _upload_smb(file_path, config)
    elif method == "scp":
        return _upload_scp(file_path, config)
    else:
        return False, f"Unknown share method: {method}"


def _upload_smb(file_path: str, config) -> tuple[bool, str]:
    """Upload via smbclient CLI."""
    share = config.smb_share
    if not share:
        return False, "SMB share path not configured"

    filename = os.path.basename(file_path)

    cmd = ["smbclient", share]

    username = config.smb_username
    password = config.smb_password
    domain = config.smb_domain

    if username:
        user_arg = f"{domain}\\{username}" if domain else username
        cmd.extend(["-U", user_arg])
    else:
        cmd.append("-N")

    cmd.extend(["-c", f'put "{file_path}" "{filename}"'])

    # Pass password via environment to avoid exposure in process list
    env = os.environ.copy()
    if password:
        env["PASSWD"] = password

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
        if result.returncode == 0:
            return True, f"Uploaded {filename} to {share}"
        else:
            return False, f"smbclient error: {result.stderr.strip()}"
    except FileNotFoundError:
        return False, "smbclient not found — install samba-client package"
    except subprocess.TimeoutExpired:
        return False, "smbclient timed out after 60 seconds"


def _upload_scp(file_path: str, config) -> tuple[bool, str]:
    """Upload via scp CLI.

    Connection is built from discrete fields (no embedded user@host:port/path string):
      - scp_host (required)
      - scp_port (optional, default 22)
      - scp_path (required, remote directory)
      - scp_username (optional)
      - scp_password (optional, triggers sshpass-based password auth)

    With password auth, sshpass reads the password from the SSHPASS env var to
    avoid exposing it in the process list. Without password, SSH key auth is
    used (the runtime user must have keys authorized on the remote host).
    """
    host = config.scp_host
    if not host:
        return False, "SCP host not configured (scp_host)"

    path = config.scp_path
    if not path:
        return False, "SCP remote path not configured (scp_path)"

    port = config.scp_port
    username = config.scp_username
    password = config.scp_password

    # Build target: [user@]host:path/filename
    user_prefix = f"{username}@" if username else ""
    sep = "" if path.endswith("/") else "/"
    filename = os.path.basename(file_path)
    dest = f"{user_prefix}{host}:{path}{sep}{filename}"

    base_opts = ["-o", "ConnectTimeout=30"]
    if port:
        base_opts += ["-P", str(port)]

    env = os.environ.copy()
    if password:
        # sshpass reads password from SSHPASS env var (-e), avoiding process-list exposure.
        # accept-new auto-trusts unknown host keys on first connection.
        cmd = [
            "sshpass", "-e",
            "scp",
            *base_opts,
            "-o", "StrictHostKeyChecking=accept-new",
            file_path,
            dest,
        ]
        env["SSHPASS"] = password
    else:
        cmd = ["scp", *base_opts, file_path, dest]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
        if result.returncode == 0:
            return True, f"Uploaded {filename} to {dest}"
        else:
            return False, f"scp error: {result.stderr.strip()}"
    except FileNotFoundError:
        if password:
            return False, "sshpass not found — install with: dnf install epel-release && dnf install sshpass"
        return False, "scp not found — install openssh-clients package"
    except subprocess.TimeoutExpired:
        return False, "scp timed out after 120 seconds"
