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
    """Upload via scp CLI."""
    target = config.scp_target
    if not target:
        return False, "SCP target not configured"

    filename = os.path.basename(file_path)

    cmd = [
        "scp",
        "-o", "ConnectTimeout=30",
        file_path,
        f"{target}/{filename}" if not target.endswith("/") else f"{target}{filename}",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return True, f"Uploaded {filename} to {target}"
        else:
            return False, f"scp error: {result.stderr.strip()}"
    except FileNotFoundError:
        return False, "scp not found — install openssh-clients package"
    except subprocess.TimeoutExpired:
        return False, "scp timed out after 120 seconds"
