// Package service integrates with the Windows Service Control Manager (SCM).
// Service lifecycle: install, start, run, stop, remove.
// Rotation loop: check due, wait idle, generate password, store LSA, set AD,
// verify both, logoff user, record success.

package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Kory-Albert/sharedAccountRotate/internal/ad"
	"github.com/Kory-Albert/sharedAccountRotate/internal/logger"
	"github.com/Kory-Albert/sharedAccountRotate/internal/lsa"
	"github.com/Kory-Albert/sharedAccountRotate/internal/password"
	"github.com/Kory-Albert/sharedAccountRotate/internal/session"
	"github.com/Kory-Albert/sharedAccountRotate/internal/state"
)

const (
	serviceName        = "SharedAccountRotate"
	serviceDisplayName = "Shared Account Password Rotator"
	serviceDescription = "Rotates Active Directory auto-logon account password on a schedule."

	duePollInterval = 1 * time.Hour
	passwordLength  = 32
)

// Config holds runtime configuration for the service and rotation loop.
type Config struct {
	Log          *logger.Logger
	Domain       string
	LDAPServer   string
	LDAPPort     int
	Username     string
	RotationDays int
	IdleHours    float64
	LogLevel     string
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
	case "update":
		return updateService(cfg)
	case "run":
		return runServiceHandler(cfg)
	default:
		return fmt.Errorf("unknown service action %q – valid: install, remove, start, stop, update, run", cfg.SvcAction)
	}
}

const installDir = `C:\Program Files\sharedAccountRotate`

// installService installs the service to Program Files and registers with SCM.
func installService(cfg *Config) error {
	cfg.Log.Infof("service: installing %q", serviceName)

	srcPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("service install – get executable path: %w", err)
	}
	srcPath, err = filepath.EvalSymlinks(srcPath)
	if err != nil {
		return fmt.Errorf("service install – resolve executable path: %w", err)
	}

	cfg.Log.Infof("service: creating installation directory %s", installDir)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("service install – create directory: %w", err)
	}
	cfg.Log.Infof("service: creating data directory %s", state.DataDir())
	if err := os.MkdirAll(state.DataDir(), 0755); err != nil {
		return fmt.Errorf("service install – create data directory: %w", err)
	}

	installBinDir := filepath.Dir(srcPath)

	serviceDestPath := filepath.Join(installDir, "sharedAccountRotate.exe")
	cfg.Log.Infof("service: copying service binary to %s", serviceDestPath)
	if err := copyFile(srcPath, serviceDestPath); err != nil {
		return fmt.Errorf("service install – copy service binary: %w", err)
	}

	monitorSrcPath := filepath.Join(installBinDir, "AccountRotateMonitor.exe")
	monitorDestPath := filepath.Join(installDir, "AccountRotateMonitor.exe")
	cfg.Log.Infof("service: copying monitor binary from %s to %s", monitorSrcPath, monitorDestPath)
	if err := copyFile(monitorSrcPath, monitorDestPath); err != nil {
		return fmt.Errorf("service install – copy monitor binary: %w", err)
	}

	if _, err := os.Stat(serviceDestPath); err != nil {
		return fmt.Errorf("service install – verify service binary copy: %w", err)
	}
	if _, err := os.Stat(monitorDestPath); err != nil {
		return fmt.Errorf("service install – verify monitor binary copy: %w", err)
	}
	cfg.Log.Infof("service: both binaries copied successfully")

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service install – connect SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.CreateService(
		serviceName, serviceDestPath, mgr.Config{
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
		"--loglevel", cfg.LogLevel,
	)
	if err != nil {
		return fmt.Errorf("service install – create: %w", err)
	}
	defer s.Close()

	if err := installStartupShortcut(monitorDestPath); err != nil {
		cfg.Log.Errorf("service: could not install startup shortcut: %v (non-fatal)", err)
	}

	if err := startService(cfg.Log); err != nil {
		cfg.Log.Errorf("service: installed but could not start: %v (service will start on next boot)", err)
	} else {
		cfg.Log.Infof("service: %q installed and started successfully", serviceName)
		return nil
	}

	cfg.Log.Infof("service: %q installed successfully (StartType=Automatic, will start on boot)", serviceName)
	return nil
}

// copyFile copies a file from src to dst, overwriting dst if it exists.
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	stat, err := sourceFile.Stat()
	if err != nil {
		return err
	}

	destFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, stat.Mode())
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return destFile.Sync()
}

// installStartupShortcut creates a .lnk in the all-users Startup folder.
func installStartupShortcut(exePath string) error {
	startupDir := `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
	shortcutPath := filepath.Join(startupDir, "AccountRotateMonitor.lnk")

	monitorPath := filepath.Join(filepath.Dir(exePath), "AccountRotateMonitor.exe")

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

// removeService stops the service, removes it from SCM, and deletes installation files.
func removeService(log *logger.Logger) error {
	log.Infof("service: removing %q and all related files", serviceName)

	log.Info("service: stopping service (if running)")
	m, err := mgr.Connect()
	if err != nil {
		log.Warnf("service: could not connect to SCM (service may already be removed): %v", err)
		m = nil
	}

	var svcHandle *mgr.Service
	if m != nil {
		svcHandle, err = m.OpenService(serviceName)
		if err != nil {
			log.Warnf("service: could not open service (may already be removed): %v", err)
		} else {
			defer svcHandle.Close()

			status, err := svcHandle.Query()
			if err == nil && status.State == svc.Running {
				if _, err := svcHandle.Control(svc.Stop); err != nil {
					log.Warnf("service: could not stop service gracefully: %v", err)
				} else {
					log.Info("service: waiting for service to stop...")
					for i := 0; i < 30; i++ {
						time.Sleep(time.Second)
						status, err := svcHandle.Query()
						if err != nil || status.State != svc.Running {
							log.Info("service: stopped")
							break
						}
					}
				}
			}
		}
	}

	if m != nil {
		m.Disconnect()
	}

	log.Info("service: terminating monitor process (AccountRotateMonitor.exe)")
	if err := killProcessByName("AccountRotateMonitor.exe"); err != nil {
		log.Warnf("service: could not kill monitor process (may not be running): %v", err)
	}

	log.Info("service: removing service from SCM")
	m, err = mgr.Connect()
	if err != nil {
		return fmt.Errorf("service remove – connect SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Warnf("service: service already removed from SCM: %v", err)
	} else {
		defer s.Close()
		if err := s.Delete(); err != nil {
			return fmt.Errorf("service remove – delete: %w", err)
		}
		log.Info("service: removed from SCM")
	}

	log.Info("service: removing installation files")

	startupDir := `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
	shortcutPath := filepath.Join(startupDir, "AccountRotateMonitor.lnk")
	if err := os.Remove(shortcutPath); err != nil && !os.IsNotExist(err) {
		log.Warnf("service: could not remove startup shortcut: %v", err)
	} else if err == nil {
		log.Infof("service: removed shortcut: %s", shortcutPath)
	}

	installDir := `C:\Program Files\sharedAccountRotate`
	if err := os.RemoveAll(installDir); err != nil {
		log.Warnf("service: could not remove installation directory: %v", err)
	} else {
		log.Infof("service: removed directory: %s", installDir)
	}

	dataDir := state.DataDir()
	if err := os.RemoveAll(dataDir); err != nil {
		log.Warnf("service: could not remove data directory: %v", err)
	} else {
		log.Infof("service: removed directory: %s", dataDir)
	}

	log.Info("service: removal complete")
	return nil
}

// updateService upgrades the service in place, preserving state and logs.
func updateService(cfg *Config) error {
	cfg.Log.Info("service: updating installation")

	if err := stopService(cfg.Log); err != nil {
		cfg.Log.Warnf("service: could not stop service: %v", err)
	}

	time.Sleep(2 * time.Second)

	cfg.Log.Info("service: terminating monitor process")
	if err := killProcessByName("AccountRotateMonitor.exe"); err != nil {
		cfg.Log.Warnf("service: could not kill monitor: %v", err)
	}

	srcPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("service update – get executable path: %w", err)
	}
	srcPath, err = filepath.EvalSymlinks(srcPath)
	if err != nil {
		return fmt.Errorf("service update – resolve executable path: %w", err)
	}

	installDir := `C:\Program Files\sharedAccountRotate`
	binDir := filepath.Dir(srcPath)

	serviceDestPath := filepath.Join(installDir, "sharedAccountRotate.exe")
	cfg.Log.Infof("service: copying new service binary to %s", serviceDestPath)
	if err := copyFile(srcPath, serviceDestPath); err != nil {
		return fmt.Errorf("service update – copy service binary: %w", err)
	}

	monitorSrcPath := filepath.Join(binDir, "AccountRotateMonitor.exe")
	monitorDestPath := filepath.Join(installDir, "AccountRotateMonitor.exe")
	cfg.Log.Infof("service: copying new monitor binary to %s", monitorDestPath)
	if err := copyFile(monitorSrcPath, monitorDestPath); err != nil {
		return fmt.Errorf("service update – copy monitor binary: %w", err)
	}

	cfg.Log.Info("service: re-registering service with SCM")
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service update – connect SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service update – service not found (need to install first): %w", err)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		cfg.Log.Warnf("service: could not delete old service: %v", err)
	}
	m.Disconnect()

	m, err = mgr.Connect()
	if err != nil {
		return fmt.Errorf("service update – reconnect SCM: %w", err)
	}
	defer m.Disconnect()

	_, err = m.CreateService(
		serviceName, serviceDestPath, mgr.Config{
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
		"--loglevel", cfg.LogLevel,
	)
	if err != nil {
		return fmt.Errorf("service update – recreate service: %w", err)
	}

	if err := startService(cfg.Log); err != nil {
		cfg.Log.Errorf("service: update complete but could not start: %v", err)
	} else {
		cfg.Log.Info("service: update complete and running")
	}

	cfg.Log.Info("service: update complete")
	return nil
}

// killProcessByName terminates all processes with the given executable name.
func killProcessByName(processName string) error {
	cmd := exec.Command("taskkill", "/F", "/IM", processName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "not found") || strings.Contains(string(output), "No tasks") {
			return nil
		}
		return fmt.Errorf("taskkill failed: %w (output: %s)", err, string(output))
	}
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

type windowsService struct{ cfg *Config }

func runServiceHandler(cfg *Config) error {
	return svc.Run(serviceName, &windowsService{cfg: cfg})
}

// Execute is called by the SCM. It starts the rotation goroutine and handles SCM control requests.
func (ws *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificExitCode bool, errno uint32) {
	windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED)
	defer windows.CoUninitialize()

	changes <- svc.Status{State: svc.StartPending}

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
				<-done
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

// runLoop is the main rotation loop. Runs until stop channel is closed.
func (s *Service) runLoop(stop <-chan struct{}) error {
	s.cfg.Log.Infof("rotation: starting loop (domain=%s username=%s days=%d idle=%.1fh dev=%v)",
		s.cfg.Domain, s.cfg.Username, s.cfg.RotationDays, s.cfg.IdleHours, s.cfg.DevMode)

	for {
		st, err := s.states.Load()
		if err != nil {
			s.cfg.Log.Errorf("rotation: could not load state file: %v – treating as first run", err)
			st = &state.State{}
		}

		if due, err := s.states.IsDue(st, s.cfg.RotationDays, s.cfg.DevMode); err != nil {
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

		if !s.cfg.DevMode {
			minIdle := time.Duration(s.cfg.IdleHours * float64(time.Hour))
			s.cfg.Log.Infof("rotation: waiting for %.1f hours of idle (monitor report)", s.cfg.IdleHours)

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

		if err := s.rotate(); err != nil {
			var oos *outOfSyncError
			if errors.As(err, &oos) {
				s.cfg.Log.Errorf("rotation: OUT OF SYNC – %v", err)
				s.cfg.Log.Error("rotation: HALTING – no further rotations until operator clears out_of_sync in state file")
				s.states.MarkOutOfSync(st)
				if saveErr := s.states.Save(st); saveErr != nil {
					s.cfg.Log.Errorf("rotation: could not persist out-of-sync flag: %v – flag is in memory only until service restart", saveErr)
				}
				select {
				case <-stop:
					return nil
				case <-time.After(duePollInterval):
				}
				continue
			}

			s.cfg.Log.Errorf("rotation: FAILED: %v", err)
			backoff := 15 * time.Minute
			s.cfg.Log.Infof("rotation: will retry in %v", backoff)
			select {
			case <-stop:
				return nil
			case <-time.After(backoff):
			}
			continue
		}

		s.states.MarkSuccess(st)
		if err := s.states.Save(st); err != nil {
			s.cfg.Log.Errorf("rotation: could not save state file: %v (rotation succeeded; update state manually if needed)", err)
		} else {
			s.cfg.Log.Infof("rotation: state saved (count=%d last=%s)",
				st.RotationCount, st.LastRotation.Format(time.RFC3339))
		}

		s.cfg.Log.Info("rotation: ✓ complete – waiting for next scheduled rotation")
		if s.cfg.DevMode {
			os.Exit(0)
		}

		select {
		case <-stop:
			return nil
		default:
		}
	}
}

// rotate performs the full password rotation sequence.
// Order: AD first (more likely to fail), then LSA. On LSA failure after AD success, marks out-of-sync.
func (s *Service) rotate() error {
	s.cfg.Log.Info("rotation: ── PHASE 1: generating new password ──────────────────")
	pw, err := password.Generate(passwordLength)
	if err != nil {
		return fmt.Errorf("password generate: %w", err)
	}
	defer password.Zero(pw)
	s.cfg.Log.Infof("rotation: generated %d-character password (not logged)", len(pw))

	s.cfg.Log.Info("rotation: ── PHASE 2: setting password in Active Directory ──────")
	adErr := s.adCli.SetPassword(s.cfg.Username, pw)
	if adErr != nil {
		return fmt.Errorf("AD set password: %w", adErr)
	}
	s.cfg.Log.Info("rotation: AD password set")

	s.cfg.Log.Info("rotation: ── PHASE 3: storing password in LSA (Autologon) ───────")
	if err := s.setLSAPasswordWithRetry(pw); err != nil {
		return &outOfSyncError{cause: err}
	}
	s.cfg.Log.Info("rotation: LSA password stored")

	s.cfg.Log.Info("rotation: ── PHASE 4: verifying both writes ────────────────────")

	s.cfg.Log.Info("rotation: verifying AD password (test bind)")
	if err := s.adCli.VerifyPasswordChange(s.cfg.Username, pw); err != nil {
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

	s.cfg.Log.Info("rotation: ── PHASE 5: logging off user session ──────────────────")
	if err := s.sessCli.LogoffUser(s.cfg.Username); err != nil {
		s.cfg.Log.Warnf("rotation: session logoff failed (non-fatal): %v", err)
		s.cfg.Log.Warn("rotation: passwords are updated; user will need to log off manually or reboot")
	} else {
		s.cfg.Log.Info("rotation: user logged off – awaiting auto-logon")
	}

	s.cfg.Log.Info("rotation: ── ALL PHASES COMPLETE ────────────────────────────────")
	return nil
}

const (
	adSyncRetryDuration = 5 * time.Minute
	adSyncRetryInterval = 30 * time.Second
)

// setLSAPasswordWithRetry attempts to set LSA secret, retrying up to adSyncRetryDuration.
func (s *Service) setLSAPasswordWithRetry(pw []byte) error {
	deadline := time.Now().Add(adSyncRetryDuration)
	attempt := 0
	for {
		attempt++
		err := s.lsaCli.StoreAutologonPassword(s.cfg.Domain, s.cfg.Username, pw)
		if err == nil {
			if attempt > 1 {
				s.cfg.Log.Infof("rotation: LSA password stored after %d attempt(s)", attempt)
			}
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("LSA store password failed after %d attempt(s) over %v: %w",
				attempt, adSyncRetryDuration, err)
		}

		s.cfg.Log.Errorf(
			"rotation: LSA store password attempt %d failed (AD already updated – retrying in %v): %v",
			attempt, adSyncRetryInterval, err,
		)
		time.Sleep(adSyncRetryInterval)
	}
}

// outOfSyncError indicates LSA updated but AD write failed permanently.
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
