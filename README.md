# 🔐 sharedAccountRotate

> *Because manually rotating passwords is so last millennium.*

A Windows service that automatically rotates Active Directory passwords for auto-logon accounts (think: kiosks, shared workstations). It runs silently under the SYSTEM account, waits for the workstation to go idle, and then performs a seamless password rotation—complete with LSA secret storage, AD updates, and automatic session logoff.

No PowerShell. No manual intervention. No "why do we have hundreds of passwords that don't expire".

---

## ✨ Quick Start

### Prerequisites

- Windows (this is a Windows-only project, compiled under linux using GOOS=windows GOARCH=amd64 go build)
- Active Directory domain
- The computer account needs delegated "Reset Password" permission on the target user object
- Rights to install Windows services (typically Administrators)

### Installation (5 Minutes or Less)

1. **Download** the binary and drop it anywhere convenient (Downloads folder works fine)

2. **Install the service**:
   ```cmd
   sharedAccountRotate.exe --service install --domain corp.example.com --days 30
   ```
   This automatically:
   - Creates `C:\Program Files\sharedAccountRotate\`
   - Copies the binary there
   - Registers the service with Windows
   - Sets it to start automatically

3. **Clean up**: Delete the original binary from Downloads—it's now living happily in Program Files

4. **Start the service**:
   ```cmd
   sharedAccountRotate.exe --service start
   ```

That's it! The service will now rotate the password every 30 days when the workstation has been idle for 2 hours.

---

## 🎮 Usage

### Service Control

| Action | Command |
|--------|---------|
| Install | `sharedAccountRotate.exe --service install --domain <domain>` |
| Start | `sharedAccountRotate.exe --service start` |
| Stop | `sharedAccountRotate.exe --service stop` |
| Remove | `sharedAccountRotate.exe --service remove` |

### Common Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--days` | `30` | Days between password rotations |
| `--idle-hours` | `2.0` | Hours of idle time required before rotation |
| `--domain` | *required* | Your AD domain (e.g., `corp.example.com`) |
| `--ldap-server` | `nil` | LDAP server address; if not specified, uses `--domain` |
| `--username` | *hostname* | AD account to rotate (defaults to machine name) |
| `--loglevel` | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `--dev` | `false` | Skip all checks, rotate immediately (useful for testing) |

### Examples

```cmd
# Install with custom rotation interval (14 days) and longer idle requirement (3 hours)
sharedAccountRotate.exe --service install --domain corp.example.com --days 14 --idle-hours 3

# Dev mode - test rotation immediately without waiting
sharedAccountRotate.exe --dev --domain corp.example.com --loglevel DEBUG

# Run in foreground (for debugging or development)
sharedAccountRotate.exe --domain corp.example.com --days 7
```

---

## 🏗️ Architecture & Development

> *For those who like to peek under the hood.*

### Project Structure

```
.
├── cmd/sharedAccountRotate/     # Entry point (CLI flag parsing, service dispatch)
│   └── main.go
├── internal/
│   ├── activity/                 # Idle time detection (GetLastInputInfo)
│   ├── ad/                       # Active Directory operations via LDAPS
│   ├── lsa/                      # LSA secrets + Winlogon registry
│   ├── session/                  # Windows session enumeration/logoff
│   ├── password/                 # Cryptographically secure password generation
│   ├── state/                    # Persistent state management (JSON)
│   ├── logger/                   # Dual-output logging (stdout + file)
│   └── service/                  # SCM integration + rotation orchestration
└── go.mod
```

### Key Components

#### `internal/service` - The Conductor

The `service` package is the orchestration layer. It implements the service lifecycle and the main rotation loop:

1. **State Check**: Load `C:\Program Files\sharedAccountRotate\sharedAccountRotate_state.json` and check if rotation is due
2. **Idle Wait**: Poll `GetLastInputInfo` until the workstation has been idle for `--idle-hours`
3. **Rotation**: Generate password → Update AD → Store in LSA → Verify → Logoff session
4. **Persist**: Save success timestamp for next interval calculation

The service can run in two modes:
- **Service mode**: Runs under SCM (Windows Service Control Manager)
- **Foreground mode**: Runs in a terminal for testing/debugging

#### `internal/ad` - The Directory Whisperer

Active Directory integration using LDAPS (port 636) with NTLM authentication:

- **Bind**: Authenticates using the machine account credentials (no hardcoded passwords)
- **Search**: Finds the target user DN via LDAP search
- **Modify**: Updates the `unicodePwd` attribute using the proper delete+add sequence
- **Verify**: Performs a test bind with the new password to confirm replication

#### `internal/lsa` - The Vault Keeper

Manages the LSA secret that Windows uses for auto-logon:

- **Store**: Creates/updates the `DefaultPassword` LSA secret
- **Registry**: Updates `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` keys
- **Verify**: Reads back the secret to confirm storage succeeded

> **Security Note**: This requires running as SYSTEM, which is why this is a Windows service.

#### `internal/password` - The Entropy Generator

Generates cryptographically secure passwords using `crypto/rand`:

- Minimum 24 characters (configurable)
- Multiple character classes (upper, lower, digits, symbols)
- Secure zeroing of byte slices after use

#### `internal/state` - The Memory

Simple JSON-based persistence for rotation tracking:

- **Location**: `C:\Program Files\sharedAccountRotate\sharedAccountRotate_state.json`
- **Content**: Last rotation timestamp, rotation count
- **Behavior**: Creates fresh state if file is missing or corrupt

### Build System

Since this is Windows-only code, cross-compilation is required when developing on other platforms:

```bash
# Build for Windows (64-bit)
GOOS=windows GOARCH=amd64 go build -o sharedAccountRotate.exe ./cmd/sharedAccountRotate

# Build with embedded timestamp
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.buildTimestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o sharedAccountRotate.exe ./cmd/sharedAccountRotate
```

### Adding Features

**To add a new CLI flag:**
1. Add the flag variable in `cmd/sharedAccountRotate/main.go`
2. Add it to the `service.Config` struct
3. Pass it when constructing the config in `main()`
4. Update usage examples in `init()`

**To add new logging levels:**
1. Add the method to `internal/logger/logger.go`
2. Update `LogLevel` constants if needed
3. Remember to check `shouldLog()` before writing

**To modify the rotation flow:**
1. Look in `internal/service/service_windows.go`
2. The `runLoop()` method controls the main flow
3. The `rotate()` method performs the actual password change

### Testing

> ⚠️ **Heads up**: Tests requiring Windows APIs will fail on non-Windows systems. Use a Windows VM or CI/CD for full test coverage.

```bash
# Run tests (some may be skipped on non-Windows)
go test ./...
```

### Important File Locations

| File | Purpose |
|------|---------|
| `C:\Program Files\sharedAccountRotate\sharedAccountRotate.log` | Service logs (when running as SCM service) |
| `C:\Windows\Temp\sharedAccountRotate.log` | Service logs (install, dev, and foreground modes) |
| `C:\Program Files\sharedAccountRotate\sharedAccountRotate_state.json` | Rotation state |
| `C:\Program Files\sharedAccountRotate\sharedAccountRotate.exe` | Installed binary |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | Auto-logon registry |

---

## 🛡️ Security Considerations

- **Runs as SYSTEM**: Required for LSA secret access and Winlogon registry modifications
- **Machine account authentication**: Uses the computer's own AD credentials (no hardcoded passwords)
- **Passwords never logged**: Byte slices are zeroed after use; no password ever touches the logs
- **LDAPS only**: All AD communication happens over TLS (port 636)
- **Verification**: Both AD and LSA writes are verified before considering rotation successful

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](https://opensource.org/license/MIT) for details.

---

## 🤝 Contributing

This README is designed to be easily updated. When adding features:

1. Update the Quick Start section if installation changes
2. Update the Usage table if adding/removing flags
3. Update the Architecture section if changing core behavior
4. Keep the fun tone in the intro—password rotation is boring enough already

---

*May your passwords be strong, your sessions never expire, and your helpdesk tickets stay at zero.* 🔐