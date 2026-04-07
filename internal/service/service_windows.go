// Package service integrates with the Windows Service Control Manager (SCM)
// and contains the main rotation orchestration loop.
//
// Service lifecycle:
//   install  → registers the service with the SCM
//   start    → tells the SCM to start the service
//   run      → called by the SCM; runs the rotation loop until stop is signalled
//   stop     → asks the SCM to stop the service
//   remove   → unregisters the service
//
// The rotation loop:
//   1. Check whether a rotation is due (based on last-rotation timestamp + --days).
//   2. If not due, sleep until the next check and repeat.
//   3. If due, wait until the workstation has been idle for --idle-hours.
//   4. Generate a new random password.
//   5. Store the password in the LSA secret (Autologon) – written first so a
//      failure here leaves AD untouched and the machine in a safe state.
//   6. Set the password in Active Directory – retried for up to 5 minutes on
//      failure; on hard failure the out-of-sync flag is set and rotations halt.
//   7. Verify both writes.
//   8. Log off the target user's session.
//   9. Record the successful rotation and go back to step 1.

//go:build windows

package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/sharedAccountRotate/sharedAccountRotate/internal/ad"
	"github.com/sharedAccountRotate/sharedAccountRotate/internal/logger"
	"github.com/sharedAccountRotate/sharedAccountRotate/internal/lsa"
	"github.com/sharedAccountRotate/sharedAccountRotate/internal/password"
	"github.com/sharedAccountRotate/sharedAccountRotate/internal/session"
	"github.com/sharedAccountRotate/sharedAccountRotate/internal/state"
)

const (
	serviceName        = "SharedAccountRotate"
	serviceDisplayName = "Shared Account Password Rotator"
	serviceDescription = "Rotates Active Directory auto-logon account password on a schedule."

	// How often to poll the state file when a rotation is not yet due.
	duePollInterval = 1 * time.Hour

	// Password length (characters).
	passwordLength = 32
)

// Config holds all runtime configuration for the service and rotation loop.
type Config struct {
	Log          *logger.Logger
	Domain       string
	LDAPServer   string
	LDAPPort     int
	Username     string
	RotationDays int
	IdleHours    float64
	DevMode      bool
	SvcAction    string
}

// ─── Service control actions ──────────────────────────────────────────────────

// HandleServiceAction dispatches on cfg.SvcAction.
func HandleServiceAction(cfg *Config) error {
	switch cfg.SvcAction {
	case "install":
		return installService(cfg)
	case "remove":
		return removeService(cfg.Log)
	case "start":
		return startService(cfg.Log)
	case "stop":
		return stopService(cfg.Log)
	case "run":
		// The SCM invokes this verb; run the service handler.
		return runServiceHandler(cfg)
	default:
		return fmt.Errorf("unknown service action %q – valid: install, remove, start, stop, run", cfg.SvcAction)
	}
}

const installDir = `C:\Program Files\sharedAccountRotate`

// installService installs the service to Program Files and registers with SCM.
// It copies the binary to a standard location before creating the service.
func installService(cfg *Config) error {
	cfg.Log.Infof("service: installing %q", serviceName)

	// Get the current executable path
	srcPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("service install – get executable path: %w", err)
	}
	// Resolve any symlinks to get the real path
	srcPath, err = filepath.EvalSymlinks(srcPath)
	if err != nil {
		return fmt.Errorf("service install – resolve executable path: %w", err)
	}

	// Ensure installation directories exist
	cfg.Log.Infof("service: creating installation directory %s", installDir)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("service install – create directory: %w", err)
	}
	cfg.Log.Infof("service: creating data directory %s", state.DataDir())
	if err := os.MkdirAll(state.DataDir(), 0755); err != nil {
		return fmt.Errorf("service install – create data directory: %w", err)
	}

	// Copy binary to installation directory
	destPath := filepath.Join(installDir, "sharedAccountRotate.exe")
	cfg.Log.Infof("service: copying binary to %s", destPath)
	if err := copyFile(srcPath, destPath); err != nil {
		return fmt.Errorf("service install – copy binary: %w", err)
	}

	// Verify the copy succeeded
	if _, err := os.Stat(destPath); err != nil {
		return fmt.Errorf("service install – verify binary copy: %w", err)
	}
	cfg.Log.Infof("service: binary copied successfully")

	// Connect to SCM and create service
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service install – connect SCM: %w", err)
	}
	defer m.Disconnect()

	// CreateService properly handles argument escaping. Pass the exe path
	// separately from the command-line arguments.
	s, err := m.CreateService(
		serviceName, destPath, mgr.Config{
			DisplayName: serviceDisplayName,
			Description: serviceDescription,
			StartType:   mgr.StartAutomatic,
		},
		"--service", "run",
		"--domain", cfg.Domain,
		"--ldap-server", cfg.LDAPServer,
		"--ldap-port", fmt.Sprintf("%d", cfg.LDAPPort),
		"--username", cfg.Username,
		"--days", fmt.Sprintf("%d", cfg.RotationDays),
		"--idle-hours", fmt.Sprintf("%.2f", cfg.IdleHours),
	)
	if err != nil {
		return fmt.Errorf("service install – create: %w", err)
	}
	defer s.Close()

	// Create a startup shortcut (.lnk) in the user's Startup folder so the
	// monitor helper runs each time the user logs on. The monitor tracks
	// idle status to the shared state file.
	if err := installStartupShortcut(destPath); err != nil {
		cfg.Log.Errorf("service: could not install startup shortcut: %v (non-fatal)", err)
	}

	cfg.Log.Infof("service: %q installed successfully (StartType=Automatic)", serviceName)
	return nil
}

// copyFile copies a file from src to dst, overwriting dst if it exists.
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	// Get source file info for permissions
	stat, err := sourceFile.Stat()
	if err != nil {
		return err
	}

	// Create destination file
	destFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, stat.Mode())
	if err != nil {
		return err
	}
	defer destFile.Close()

	// Copy content
	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	// Ensure data is written to disk
	return destFile.Sync()
}

// installStartupShortcut creates a .lnk in the all-users Startup folder
// so the monitor runs for whichever user auto-logs in. Uses the common
// startup folder (C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp).
func installStartupShortcut(exePath string) error {
	// Common Startup folder – applies to all users, including the auto-logon account.
	startupDir := `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
	shortcutPath := filepath.Join(startupDir, "AccountRotateMonitor.lnk")

	// The monitor binary is compiled alongside the service binary with -H=windowsgui
	// (no console window). It lives in the same install directory.
	monitorPath := filepath.Join(filepath.Dir(exePath), "AccountRotateMonitor.exe")

	// PowerShell script to create a COM-based .lnk file
	script := fmt.Sprintf(`
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("%s")
$Shortcut.TargetPath = "%s"
$Shortcut.WorkingDirectory = (Split-Path -Parent "%s")
$Shortcut.Description = "Shared Account Rotate - Idle Monitor"
$Shortcut.Save()
`, shortcutPath, monitorPath, monitorPath)

	cmd := exec.Command("powershell", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("create startup shortcut: %w (output: %s)", err, string(output))
	}

	if _, err := os.Stat(shortcutPath); err != nil {
		return fmt.Errorf("verify startup shortcut: %w", err)
	}

	return nil
}

// removeService deletes the service from the SCM.
func removeService(log *logger.Logger) error {
	log.Infof("service: removing %q", serviceName)
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service remove – connect SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service remove – open: %w", err)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return fmt.Errorf("service remove – delete: %w", err)
	}
	log.Infof("service: %q removed", serviceName)
	return nil
}

// startService tells the SCM to start the service.
func startService(log *logger.Logger) error {
	log.Infof("service: starting %q", serviceName)
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service start – connect SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service start – open: %w", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("service start – start: %w", err)
	}
	log.Infof("service: %q start requested", serviceName)
	return nil
}

// stopService sends a stop control to the service.
func stopService(log *logger.Logger) error {
	log.Infof("service: stopping %q", serviceName)
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service stop – connect SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service stop – open: %w", err)
	}
	defer s.Close()

	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("service stop – control: %w", err)
	}
	log.Infof("service: %q stop requested", serviceName)
	return nil
}

// ─── Service handler (called by SCM) ─────────────────────────────────────────

// windowsService implements svc.Handler.
type windowsService struct{ cfg *Config }

func runServiceHandler(cfg *Config) error {
	return svc.Run(serviceName, &windowsService{cfg: cfg})
}

// Execute is called by the SCM. It starts the rotation goroutine and handles
// SCM control requests (Stop, Pause, etc.).
func (ws *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificExitCode bool, errno uint32) {
	// Initialize COM on the service thread. Windows services run in Session 0
	// which does not have COM pre-initialized. Several Windows APIs used during
	// TLS certificate validation (crypt32/cert validation paths) and Kerberos
	// SSP indirectly invoke COM and will fail with 0x8000FFFF if it is not
	// initialized.
	windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED)
	defer windows.CoUninitialize()

	changes <- svc.Status{State: svc.StartPending}

	// Start the rotation loop in a goroutine so we can also service SCM cmds.
	stop := make(chan struct{})
	done := make(chan error, 1)
	svcObj := New(ws.cfg)
	go func() {
		done <- svcObj.runLoop(stop)
	}()

	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}
	ws.cfg.Log.Info("service: running")

loop:
	for {
		select {
		case err := <-done:
			if err != nil {
				ws.cfg.Log.Errorf("service: rotation loop exited with error: %v", err)
			}
			break loop
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				ws.cfg.Log.Info("service: stop/shutdown received")
				changes <- svc.Status{State: svc.StopPending}
				close(stop)
				<-done // wait for the loop to exit cleanly
				break loop
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				ws.cfg.Log.Warnf("service: unexpected control command %d", c.Cmd)
			}
		}
	}

	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

// ─── Rotation service ─────────────────────────────────────────────────────────

// Service orchestrates the rotation loop.
type Service struct {
	cfg     *Config
	adCli   *ad.Client
	lsaCli  *lsa.Client
	sessCli *session.Client
	states  *state.Manager
	idle    *state.IdleMonitor
}

// New constructs a Service with all dependencies wired up.
func New(cfg *Config) *Service {
	return &Service{
		cfg:     cfg,
		adCli:   ad.New(cfg.Log, cfg.Domain, cfg.LDAPServer, cfg.LDAPPort),
		lsaCli:  lsa.New(cfg.Log),
		sessCli: session.New(cfg.Log),
		states:  state.New(),
		idle:    state.NewIdleMonitor(),
	}
}

// Run is the entry point for foreground / interactive mode.
func (s *Service) Run() error {
	stop := make(chan struct{})
	return s.runLoop(stop)
}

// runLoop is the main rotation loop. It runs until the stop channel is closed.
func (s *Service) runLoop(stop <-chan struct{}) error {
	s.cfg.Log.Infof("rotation: starting loop (domain=%s username=%s days=%d idle=%.1fh dev=%v)",
		s.cfg.Domain, s.cfg.Username, s.cfg.RotationDays, s.cfg.IdleHours, s.cfg.DevMode)

	for {
		// ── Phase 1: Load state and check if rotation is due ──────────────────
		st, err := s.states.Load()
		if err != nil {
			s.cfg.Log.Errorf("rotation: could not load state file: %v – treating as first run", err)
			st = &state.State{}
		}

		if due, err := s.states.IsDue(st, s.cfg.RotationDays, s.cfg.DevMode); err != nil {
			// OutOfSync: LSA and AD are mismatched. Log loudly every poll cycle
			// so the condition is visible in the log file, then sleep and recheck
			// (an operator may clear the flag while the service is running).
			s.cfg.Log.Errorf("rotation: HALTED – %v", err)
			s.cfg.Log.Error("rotation: manual intervention required before rotations will resume")
			select {
			case <-stop:
				s.cfg.Log.Info("rotation: stop signal received – exiting loop")
				return nil
			case <-time.After(duePollInterval):
				continue
			}
		} else if !due {
			next := st.LastRotation.AddDate(0, 0, s.cfg.RotationDays)
			s.cfg.Log.Infof("rotation: not due yet (last=%s next=%s) – sleeping %v",
				st.LastRotation.Format(time.RFC3339),
				next.Format(time.RFC3339),
				duePollInterval)

			select {
			case <-stop:
				s.cfg.Log.Info("rotation: stop signal received – exiting loop")
				return nil
			case <-time.After(duePollInterval):
				continue
			}
		}

		s.cfg.Log.Info("rotation: rotation is due – beginning pre-rotation checks")

		// ── Phase 2: Wait for workstation idle (reported by monitor via state file) ─
		if !s.cfg.DevMode {
			minIdle := time.Duration(s.cfg.IdleHours * float64(time.Hour))
			s.cfg.Log.Infof("rotation: waiting for %.1f hours of idle (monitor report)", s.cfg.IdleHours)

			// Poll the monitor's dedicated idle file every 5 seconds. The monitor
			// writes is_idle=true when GetLastInputInfo reports the session is idle.
			// We wait until is_idle is true and the session has been continuously
			// idle for at least --idle-hours.
			consecutiveIdleStart := time.Time{}
		idleWait:
			for {
				idleStatus := s.idle.LoadIdle()
				if idleStatus.IsIdle {
					if consecutiveIdleStart.IsZero() {
						consecutiveIdleStart = idleStatus.IdleUpdated
						s.cfg.Log.Info("rotation: session reported as idle by monitor")
					}
					elapsed := time.Since(consecutiveIdleStart)
					if elapsed >= minIdle {
						s.cfg.Log.Infof("rotation: idle threshold met (%.1f hours)", s.cfg.IdleHours)
						break idleWait
					}
					s.cfg.Log.Infof("rotation: session idle %v of %.1fh required",
						elapsed.Round(time.Second), s.cfg.IdleHours)
				} else {
					if !consecutiveIdleStart.IsZero() {
						s.cfg.Log.Infof("rotation: session became active – resetting idle timer (was idle %v)",
							time.Since(consecutiveIdleStart).Round(time.Second))
						consecutiveIdleStart = time.Time{}
					}
				}

				select {
				case <-stop:
					s.cfg.Log.Info("rotation: stop signal received during idle wait – exiting")
					return nil
				case <-time.After(5 * time.Second):
				}
			}
		} else {
			s.cfg.Log.Info("rotation: [DEV MODE] skipping idle check")
		}

		// ── Phase 3: Perform the rotation ─────────────────────────────────────
		if err := s.rotate(); err != nil {
			// Check for the special out-of-sync case: LSA was updated but AD
			// write failed after all retries. Further rotation attempts would
			// produce yet another mismatched pair, so we persist the flag and
			// halt. The error message in the state file and logs tells the
			// operator exactly what to do.
			var oos *outOfSyncError
			if errors.As(err, &oos) {
				s.cfg.Log.Errorf("rotation: OUT OF SYNC – %v", err)
				s.cfg.Log.Error("rotation: HALTING – no further rotations until operator clears out_of_sync in state file")
				s.states.MarkOutOfSync(st)
				if saveErr := s.states.Save(st); saveErr != nil {
					s.cfg.Log.Errorf("rotation: could not persist out-of-sync flag: %v – flag is in memory only until service restart", saveErr)
				}
				// Continue looping so the service stays alive and keeps logging
				// the halted state (operator may be watching the log remotely).
				select {
				case <-stop:
					return nil
				case <-time.After(duePollInterval):
				}
				continue
			}

			s.cfg.Log.Errorf("rotation: FAILED: %v", err)
			// Back off before retrying to avoid hammering AD on persistent failures.
			backoff := 15 * time.Minute
			s.cfg.Log.Infof("rotation: will retry in %v", backoff)
			select {
			case <-stop:
				return nil
			case <-time.After(backoff):
			}
			continue
		}

		// ── Phase 4: Persist success ──────────────────────────────────────────
		s.states.MarkSuccess(st)
		if err := s.states.Save(st); err != nil {
			// Non-fatal: the passwords are already updated. We log the error
			// but do not fail – the worst case is the rotation runs again before
			// the next scheduled interval.
			s.cfg.Log.Errorf("rotation: could not save state file: %v (rotation succeeded; update state manually if needed)", err)
		} else {
			s.cfg.Log.Infof("rotation: state saved (count=%d last=%s)",
				st.RotationCount, st.LastRotation.Format(time.RFC3339))
		}

		s.cfg.Log.Info("rotation: ✓ complete – waiting for next scheduled rotation")
		if s.cfg.DevMode {
			os.Exit(0)
		}

		// Immediately check for stop before sleeping.
		select {
		case <-stop:
			return nil
		default:
		}
	}
}

// rotate performs the full password rotation sequence:
//
//  1. Generate password
//  2. Store in LSA  ← first, so a crash here leaves AD untouched
//  3. Set in AD     ← retried aggressively; signals out-of-sync on hard failure
//  4. Verify both
//  5. Log off user
//
// Order rationale: true atomicity is impossible because AD and LSA are
// independent systems with no shared transaction. Writing LSA first is the
// safer choice:
//
//   - If the LSA write fails  → AD is untouched → old password still valid →
//     clean retry next cycle. No lockout risk.
//   - If the AD write fails after LSA succeeds → passwords are mismatched.
//     The service retries the AD write for adSyncRetryDuration before giving
//     up. On hard failure it persists OutOfSync=true in the state file and
//     refuses further rotations until an operator intervenes. This is
//     preferable to silently rotating again (which would write yet another
//     mismatched pair).
//
// Rollback is intentionally not attempted: we do not know the previous AD
// password, so we cannot restore it. The out-of-sync flag is the recovery
// signal.
func (s *Service) rotate() error {
	s.cfg.Log.Info("rotation: ── PHASE 1: generating new password ──────────────────")
	pw, err := password.Generate(passwordLength)
	if err != nil {
		return fmt.Errorf("password generate: %w", err)
	}
	// Zero the password on all exit paths. The defer runs after the AD retry
	// loop, so pw remains valid for the full duration of the function.
	defer password.Zero(pw)
	s.cfg.Log.Infof("rotation: generated %d-character password (not logged)", len(pw))

	// ── Phase 2: LSA / Autologon (written first) ──────────────────────────────
	// Writing LSA before AD means a crash or LSA failure leaves AD untouched.
	// The old password remains valid everywhere and the next retry cycle starts
	// cleanly.
	s.cfg.Log.Info("rotation: ── PHASE 2: storing password in LSA (Autologon) ───────")
	if err := s.lsaCli.StoreAutologonPassword(s.cfg.Domain, s.cfg.Username, pw); err != nil {
		// LSA failed – AD has not been touched. Safe to return; next retry
		// will generate a fresh password and try again from a clean state.
		return fmt.Errorf("LSA store password: %w", err)
	}
	s.cfg.Log.Info("rotation: LSA password stored")

	// ── Phase 3: Active Directory ─────────────────────────────────────────────
	// LSA now holds the new password. We MUST get AD to match before returning.
	// Retry aggressively for adSyncRetryDuration to ride out transient DC
	// connectivity issues (the most common real-world failure cause).
	s.cfg.Log.Info("rotation: ── PHASE 3: setting password in Active Directory ──────")
	adErr := s.setADPasswordWithRetry(pw)
	if adErr != nil {
		// Hard failure: LSA has the new password but AD does not. The machine
		// will be locked out on the next logon. Persist the out-of-sync flag
		// so the service halts and the operator is alerted via the log.
		return &outOfSyncError{cause: adErr}
	}
	s.cfg.Log.Info("rotation: AD password set")

	// ── Phase 4: Verification ─────────────────────────────────────────────────
	s.cfg.Log.Info("rotation: ── PHASE 4: verifying both writes ────────────────────")

	s.cfg.Log.Info("rotation: verifying AD password (test bind)")
	if err := s.adCli.VerifyPasswordChange(s.cfg.Username, pw); err != nil {
		// AD replication can cause a brief delay. Retry once after a short wait.
		s.cfg.Log.Warnf("rotation: AD verify failed on first attempt: %v – retrying in 30s", err)
		time.Sleep(30 * time.Second)
		if err2 := s.adCli.VerifyPasswordChange(s.cfg.Username, pw); err2 != nil {
			return fmt.Errorf("AD verify password (after retry): %w", err2)
		}
	}
	s.cfg.Log.Info("rotation: AD password verified ✓")

	s.cfg.Log.Info("rotation: verifying LSA secret")
	if err := s.lsaCli.VerifyAutologonPassword(pw); err != nil {
		return fmt.Errorf("LSA verify password: %w", err)
	}
	s.cfg.Log.Info("rotation: LSA password verified ✓")

	// ── Phase 5: Log off the user ─────────────────────────────────────────────
	s.cfg.Log.Info("rotation: ── PHASE 5: logging off user session ──────────────────")
	if err := s.sessCli.LogoffUser(s.cfg.Username); err != nil {
		// Logoff failure is not treated as a rotation failure – the passwords
		// are already updated. The auto-logon will occur on the next reboot
		// or manual logoff.
		s.cfg.Log.Warnf("rotation: session logoff failed (non-fatal): %v", err)
		s.cfg.Log.Warn("rotation: passwords are updated; user will need to log off manually or reboot")
	} else {
		s.cfg.Log.Info("rotation: user logged off – awaiting auto-logon")
	}

	s.cfg.Log.Info("rotation: ── ALL PHASES COMPLETE ────────────────────────────────")
	return nil
}

// adSyncRetryDuration is how long to keep retrying the AD password write after
// a successful LSA write. Covers transient DC connectivity blips while bounding
// the window during which LSA and AD are mismatched.
const adSyncRetryDuration = 5 * time.Minute

// adSyncRetryInterval is how long to wait between AD retry attempts.
const adSyncRetryInterval = 30 * time.Second

// setADPasswordWithRetry attempts to set the AD password, retrying on failure
// for up to adSyncRetryDuration. It is called only after the LSA write has
// already succeeded, so every second of retry is a second the passwords are
// mismatched — hence the tight interval and bounded total duration.
func (s *Service) setADPasswordWithRetry(pw []byte) error {
	deadline := time.Now().Add(adSyncRetryDuration)
	attempt := 0
	for {
		attempt++
		err := s.adCli.SetPassword(s.cfg.Username, pw)
		if err == nil {
			if attempt > 1 {
				s.cfg.Log.Infof("rotation: AD password set after %d attempt(s)", attempt)
			}
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("AD set password failed after %d attempt(s) over %v: %w",
				attempt, adSyncRetryDuration, err)
		}

		s.cfg.Log.Errorf(
			"rotation: AD set password attempt %d failed (LSA already updated – retrying in %v): %v",
			attempt, adSyncRetryInterval, err,
		)
		time.Sleep(adSyncRetryInterval)
	}
}

// outOfSyncError is returned by rotate() when the LSA write succeeded but the
// AD write failed after all retries. The runLoop checks for this type to
// persist the OutOfSync flag before returning the error.
type outOfSyncError struct {
	cause error
}

func (e *outOfSyncError) Error() string {
	return fmt.Sprintf(
		"CRITICAL – LSA updated but AD write failed after all retries: %v. "+
			"Auto-logon will fail on next logon. "+
			"Manually set the AD password to match the LSA secret, "+
			"then clear out_of_sync in the state file to resume rotations.",
		e.cause,
	)
}

func (e *outOfSyncError) Unwrap() error { return e.cause }