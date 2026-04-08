---
date: "2026-04-01"
problem_type: security-vulnerability
component: install.sh
symptoms:
  - "Passwords with special characters (quotes, backslashes) break the installer"
  - "User input visible in process list via ps aux"
  - "eval used for variable assignment from user input"
root_cause: missing-input-validation
resolution_type: fix
severity: critical
tags:
  - bash
  - command-injection
  - installer
  - eval
custom_fields: {}
---

# Bash eval and String Interpolation in Installers

## Problem

Interactive bash installers that use `eval` for indirect variable assignment and
interpolate user input into `python3 -c` commands are vulnerable to command injection
and breakage with special characters. Three patterns were found:

1. `eval "$var_name=\"\$value\""` — fragile with shell metacharacters
2. `python3 -c "...('$user_input')..."` — breaks on quotes, enables code injection
3. `eval "$(python3 -c "...print(f'VAR={val}')...")"` — config values become shell code

## Root Cause

Using `eval` and string interpolation is a common bash habit for indirect variable
assignment. It works for simple values but fails when values contain shell or Python
metacharacters. In an installer running as root, this is a privilege escalation vector.

## Solution

1. **Replace `eval` with `printf -v`** for indirect variable assignment:
   ```bash
   # Bad
   eval "$var_name=\"\$value\""
   # Good
   printf -v "$var_name" '%s' "$value"
   ```

2. **Pass values via stdin or environment** instead of string interpolation:
   ```bash
   # Bad
   python3 -c "ZoneInfo('$tz')"
   # Good
   TZ_INPUT="$tz" python3 -c "import os; ZoneInfo(os.environ['TZ_INPUT'])"

   # Bad
   python3 -c "bcrypt.hashpw('$password'.encode(), ...)"
   # Good
   printf '%s' "$password" | python3 -c "import sys; sys.stdin.buffer.read()"
   ```

3. **Read config via while-read loop** instead of eval on Python output:
   ```bash
   while IFS='=' read -r key val; do
       printf -v "$key" '%s' "$val"
   done < <(python3 -c "print(f'KEY={val}')")
   ```

## Prevention

- Never use `eval` with user-provided values in bash scripts
- Never interpolate variables into `python3 -c` strings
- Use `printf -v` for indirect variable assignment
- Pass sensitive values via stdin or environment variables
- Review all `eval`, `$()`, and string interpolation in scripts running as root
