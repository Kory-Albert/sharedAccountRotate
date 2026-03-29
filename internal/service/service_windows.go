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
//   5. Set the password in Active Directory.
//   6. Store the password in the LSA secret (Autologon).
//   7. Verify both writes.
//   8. Log off the target user's session.
//   9. Record the successful rotation and go back to step 1.

//go:build windows

package service

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/sharedAccountRotate/sharedAccountRotate/internal/activity"
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

	// How often to check idle time while waiting for the workstation to go idle.
	idlePollInterval = 5 * time.Minute

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

// installService registers sharedAccountRotate with the Windows SCM.
func installService(cfg *Config) error {
	cfg.Log.Infof("service: installing %q", serviceName)

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("service install – get executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service install – connect SCM: %w", err)
	}
	defer m.Disconnect()

	// Build the command line that the SCM will use to start the service.
	// Pass through all required flags so the service starts correctly.
	args := fmt.Sprintf(
		"--service run --domain %s --ldap-server %s --ldap-port %d --username %s --days %d --idle-hours %.2f",
		cfg.Domain, cfg.LDAPServer, cfg.LDAPPort, cfg.Username, cfg.RotationDays, cfg.IdleHours,
	)

	s, err := m.CreateService(serviceName, exePath+" "+args, mgr.Config{
		DisplayName:  serviceDisplayName,
		Description:  serviceDescription,
		StartType:    mgr.StartAutomatic,
		ServiceType:  1, // SERVICE_WIN32_OWN_PROCESS
	})
	if err != nil {
		return fmt.Errorf("service install – create: %w", err)
	}
	defer s.Close()

	cfg.Log.Infof("service: %q installed successfully (StartType=Automatic)", serviceName)
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
}

// New constructs a Service with all dependencies wired up.
func New(cfg *Config) *Service {
	return &Service{
		cfg:     cfg,
		adCli:   ad.New(cfg.Log, cfg.Domain, cfg.LDAPServer, cfg.LDAPPort),
		lsaCli:  lsa.New(cfg.Log),
		sessCli: session.New(cfg.Log),
		states:  state.New(),
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

		if !s.states.IsDue(st, s.cfg.RotationDays, s.cfg.DevMode) {
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

		// ── Phase 2: Wait for workstation idle ────────────────────────────────
		if !s.cfg.DevMode {
			minIdle := time.Duration(s.cfg.IdleHours * float64(time.Hour))
			s.cfg.Log.Infof("rotation: waiting for %.1f hours of idle time", s.cfg.IdleHours)

			// Run idle polling in a loop so we can also honour a stop signal.
		idleWait:
			for {
				idle, err := activity.IdleTime()
				if err != nil {
					s.cfg.Log.Errorf("rotation: idle check error: %v", err)
				} else if idle >= minIdle {
					s.cfg.Log.Infof("rotation: idle threshold met (%v)", idle.Round(time.Second))
					break idleWait
				} else {
					remaining := minIdle - idle
					s.cfg.Log.Infof("rotation: idle=%v, need %v more", idle.Round(time.Second), remaining.Round(time.Second))
				}

				select {
				case <-stop:
					s.cfg.Log.Info("rotation: stop signal received during idle wait – exiting")
					return nil
				case <-time.After(idlePollInterval):
				}
			}
		} else {
			s.cfg.Log.Info("rotation: [DEV MODE] skipping idle check")
		}

		// ── Phase 3: Perform the rotation ─────────────────────────────────────
		if err := s.rotate(); err != nil {
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

		// Immediately check for stop before sleeping.
		select {
		case <-stop:
			return nil
		default:
		}
	}
}

// rotate performs the full password rotation sequence:
//  1. Generate password
//  2. Set in AD
//  3. Store in LSA
//  4. Verify both
//  5. Log off user
func (s *Service) rotate() error {
	s.cfg.Log.Info("rotation: ── PHASE 1: generating new password ──────────────────")
	pw, err := password.Generate(passwordLength)
	if err != nil {
		return fmt.Errorf("password generate: %w", err)
	}
	// The password slice is zeroed on all exit paths.
	defer password.Zero(pw)
	s.cfg.Log.Infof("rotation: generated %d-character password (not logged)", len(pw))

	// ── Phase 2: Active Directory ─────────────────────────────────────────────
	s.cfg.Log.Info("rotation: ── PHASE 2: setting password in Active Directory ──────")
	if err := s.adCli.SetPassword(s.cfg.Username, pw); err != nil {
		return fmt.Errorf("AD set password: %w", err)
	}

	// ── Phase 3: LSA / Autologon ──────────────────────────────────────────────
	s.cfg.Log.Info("rotation: ── PHASE 3: storing password in LSA (Autologon) ───────")
	if err := s.lsaCli.StoreAutologonPassword(s.cfg.Domain, s.cfg.Username, pw); err != nil {
		return fmt.Errorf("LSA store password: %w", err)
	}

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
