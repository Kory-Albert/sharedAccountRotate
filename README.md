# sharedAccountRotate

A Windows service that automatically rotates Active Directory passwords for auto‑logon accounts (kiosks, shared workstations). It runs as SYSTEM, waits for the workstation to go idle, then rotates the password in both AD and the LSA secret, and logs off the user.

No PowerShell. No manual intervention. No "why do we have hundreds of passwords that don't expire".

---

## Quick Start

### Prerequisites

1. The computer's Active Directory object must have **"Reset Password"** delegated on the target user account.
2. Windows (this is Windows‑only; cross‑compile from Linux with `GOOS=windows`).
3. Administrator rights to install Windows services.

### Installation

```cmd
sharedAccountRotate.exe --service install --domain corp.example.com --days 30
```

This automatically:
- Creates `C:\Program Files\sharedAccountRotate\` (binaries)
- Creates `C:\ProgramData\sharedAccountRotate\` (logs, state, idle file)
- Registers the service with `StartType=Automatic`
- Starts the service
- Installs a Startup folder shortcut for the idle monitor helper

> You will need to reboot or logout the kiosk account for the monitor to start properly!

The service will now rotate the password every 30 days when the workstation has been idle for 2 hours (defaults).

---

## Usage

### Service Commands

| Action   | Command |
|----------|---------|
| Install  | `--service install --domain <domain>` |
| Start    | `--service start` |
| Stop     | `--service stop` |
| Remove   | `--service remove` |
| Update   | `--service update` |

### Common Flags

| Flag             | Default         | Description |
|------------------|-----------------|-------------|
| `--days`         | `30`            | Days between rotations |
| `--idle-hours`   | `2.0`           | Required idle time (hours) |
| `--domain`       | *required*      | AD domain (e.g., `corp.example.com`) |
| `--ldap-server`  | same as domain  | LDAP server address (optional) |
| `--username`     | machine name    | AD account to rotate |
| `--loglevel`     | `INFO`          | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `--dev`          | `false`         | Rotate immediately (skip idle/checks) |

### Examples

```cmd
# Install with custom rotation and idle times
sharedAccountRotate.exe --service install --domain corp.example.com --days 14 --idle-hours 3

# Foreground testing
sharedAccountRotate.exe --domain corp.example.com --loglevel DEBUG

# Run idle monitor manually (for debugging)
AccountRotateMonitor.exe --loglevel DEBUG
```

---

## Build

> Optional install [rcedit](https://github.com/electron/rcedit) to modify windows binary details.

```bash
# Set version (optional)
VERSION=$(date -u +%Y.%m.%d)

# Build service
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.buildTimestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o sharedAccountRotate.exe ./cmd/sharedAccountRotate

# Build monitor (no console window)
GOOS=windows GOARCH=amd64 go build -ldflags "-H=windowsgui -X main.buildTimestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o accountRotateMonitor.exe ./cmd/accountrotate-monitor

# (Optional) Add Windows version metadata with `rcedit`
rcedit sharedAccountRotate.exe --set-file-version "$VERSION" \
  --set-product-version "$VERSION" \
  --set-version-string "ProductName" "Shared Account Rotate" \
  --set-version-string "CompanyName" "github.com/Kory-Albert" \
  --set-version-string "LegalCopyright" "Copyright (c) github.com/Kory-Albert" \
  --set-icon "sharedAccountrotate.ico"

# Set Windows file properties for monitor
rcedit accountRotateMonitor.exe --set-file-version "$VERSION" \
  --set-product-version "$VERSION" \
  --set-version-string "ProductName" "Shared Account Rotate" \
  --set-version-string "CompanyName" "github.com/Kory-Albert" \
  --set-version-string "LegalCopyright" "Copyright (c) github.com/Kory-Albert" \
  --set-icon "accountRotateMonitor.ico"
```

---

## Architecture

- **`internal/service`** – Orchestrates the rotation loop: check state, wait for idle, call AD/LSA, verify, logoff.
- **`internal/ad`** – LDAPS (port 636) with machine account authentication. Updates `unicodePwd` via `Replace` (requires "Reset Password" right).
- **`internal/lsa`** – Stores the password in LSA secret and updates Winlogon registry keys for auto‑logon.
- **`internal/state`** – JSON persistence: rotation timestamp, count, out‑of‑sync flag, plus idle status (written by monitor, read by service).
- **`accountRotateMonitor.exe`** – Runs in the user session, polls `GetLastInputInfo`, writes idle status to a shared file. Launched from Startup folder.

### Why a separate monitor process?

`GetLastInputInfo` only works in an interactive session. A SYSTEM service (Session 0) always sees zero idle time. The monitor runs as the logged‑on user and bridges that gap.

### Application Flow

![Flow chart](flow.svg)

---

## Important File Locations

| Path | Purpose |
|------|---------|
| `C:\ProgramData\sharedAccountRotate\sharedAccountRotate.log` | Service logs |
| `C:\ProgramData\sharedAccountRotate\sharedAccountRotate_monitor.log` | Monitor logs |
| `C:\ProgramData\sharedAccountRotate\sharedAccountRotate_state.json` | Rotation state (service writes) |
| `C:\ProgramData\sharedAccountRotate\sharedAccountRotate_idle.json` | Idle status (monitor writes, service reads) |
| `C:\Program Files\sharedAccountRotate\` | Installed binaries |
| `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\AccountRotateMonitor.lnk` | Startup shortcut for monitor |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | Auto‑logon registry keys |

---

## Security Notes

- Runs as **SYSTEM** (required for LSA and Winlogon access).
- Authenticates to AD using the **machine account** – no hardcoded credentials.
- Passwords are **never logged**; byte slices are zeroed after use.
- All AD communication is over **LDAPS** (TLS).

---

## License

MIT — see [LICENSE](LICENSE) for details.