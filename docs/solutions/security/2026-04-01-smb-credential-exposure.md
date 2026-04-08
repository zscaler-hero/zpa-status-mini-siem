---
date: "2026-04-01"
problem_type: security-vulnerability
component: share_upload.py
symptoms:
  - "SMB password visible in process list (ps aux) during upload"
  - "Password passed as part of -U user%password CLI argument"
root_cause: insecure-defaults
resolution_type: fix
severity: high
tags:
  - smb
  - smbclient
  - credentials
  - process-list
custom_fields: {}
---

# SMB Credential Exposure via Process List

## Problem

When using `smbclient` to upload files to an SMB share, the common pattern of
passing credentials via `-U user%password` exposes the password in the process
list. Any user on the system who can run `ps aux` will see the full password.

## Root Cause

`smbclient` accepts passwords on the command line for convenience, but this is
inherently insecure on multi-user systems. The password appears in `/proc/PID/cmdline`
for the lifetime of the process.

## Solution

Use `smbclient`'s `PASSWD` environment variable instead of the CLI argument:

```python
env = os.environ.copy()
if password:
    env["PASSWD"] = password

cmd = ["smbclient", share, "-U", username]
result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
```

Environment variables are NOT visible in the process list (they are in
`/proc/PID/environ` which is restricted to the process owner and root).

Also quote filenames in smbclient's `-c` command to prevent metacharacter injection:
```python
cmd.extend(["-c", f'put "{file_path}" "{filename}"'])
```

## Prevention

- Never pass credentials as CLI arguments to subprocess calls
- Use environment variables, stdin, or credential files instead
- For `smbclient` specifically: `PASSWD` env var or `--authentication-file`
- For `scp`: use SSH key-based auth, not passwords
- Audit all `subprocess.run()` calls for credential exposure
