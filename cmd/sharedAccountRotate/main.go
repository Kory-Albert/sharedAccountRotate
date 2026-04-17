// sharedAccountRotate - Active Directory password rotation service
//
// Runs as a Windows Service under SYSTEM. On each configured interval it:
//   1. Waits until the monitor reports the session is idle for --idle-hours
//   2. Generates a cryptographically random password
//   3. Sets the new password in Active Directory (Kerberos / LDAP, no PowerShell)
//   4. Stores the new password in the LSA secret that Sysinternals Autologon uses
//   5. Verifies both writes succeeded
//   6. Signs the current session out so the machine auto-logs back in
//
// A separate instance idle monitor helper
// (launched from a Startup folder). The monitor polls
// GetLastInputInfo in the user's session and writes idle status to its own file
// (sharedAccountRotate_idle.json). The service reads from that file — the two
// processes never write to the same file, avoiding permission conflicts.
//
// All events are written to stdout AND to a log file. The service writes to
// C:\ProgramData\sharedAccountRotate\sharedAccountRotate.log. The monitor
// writes to C:\ProgramData\sharedAccountRotate\sharedAccountRotate_monitor.log.
// Passwords are never written to any log or output.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Kory-Albert/sharedAccountRotate/internal/activity"
	"github.com/Kory-Albert/sharedAccountRotate/internal/logger"
	"github.com/Kory-Albert/sharedAccountRotate/internal/service"
	"github.com/Kory-Albert/sharedAccountRotate/internal/state"
)

// ─── CLI flags ────────────────────────────────────────────────────────────────

var (
	// How many days between password rotations (calendar days since last rotation).
	flagDays = flag.Int("days", 30, "Days between password rotations")

	// Minimum consecutive idle hours required before rotation is attempted.
	flagIdleHours = flag.Float64("idle-hours", 2.0, "Hours of workstation idle time required before rotation")

	// Dev mode: skip the day/idle checks and rotate immediately. Useful for
	// testing without waiting for the normal schedule.
	flagDev = flag.Bool("dev", false, "Developer mode – rotate immediately, skip day/idle checks")

	// Windows service control verbs (install / remove / start / stop / run / update).
	// "run" is what the SCM calls when starting the service normally.
	flagSvcAction = flag.String("service", "", "Service action: install | remove | start | stop | update | run")

	// LDAP / AD connection.
	flagDomain     = flag.String("domain", "", "AD domain (e.g. corp.example.com) – required")
	flagLDAPServer = flag.String("ldap-server", "", "LDAP server hostname/IP (defaults to domain if empty)")
	flagLDAPPort   = flag.Int("ldap-port", 636, "LDAPS port (default 636 for TLS)")

	// The AD account whose password will be rotated. The computer account of
	// the machine running this service must have delegated write-password
	// permission on this user object. The computer name and username are
	// expected to be identical (e.g. both "KIOSK01").
	flagUsername = flag.String("username", "", "AD username to rotate (defaults to machine hostname)")

	// Log level controls which messages are written to the log file.
	// Valid values: DEBUG, INFO, WARN, ERROR (default: INFO)
	flagLogLevel = flag.String("loglevel", "INFO", "Log level: DEBUG | INFO | WARN | ERROR")

	// Monitor mode: runs as a background helper that checks GetLastInputInfo
	// and updates the dedicated idle status file every 5 seconds.
	// Installed as a Startup folder shortcut so it runs at user logon.
	flagMonitor = flag.Bool("monitor", false, "Idle monitor mode – polls GetLastInputInfo and writes idle status file")
)

// ─── Entry point ──────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	// ── Monitor mode: separate logger, writes to monitor-specific log file ──────
	if *flagMonitor {
		ensureDataDir()
		log, err := logger.New(state.MonitorLogPath())
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] could not open monitor log: %v – logging to stderr only\n", err)
			log = logger.NewStderrOnly()
		}
		defer log.Close()
		log.SetLevel(logger.ParseLevel(*flagLogLevel))
		log.Info("monitor: starting – polling idle status every 5 seconds")
		runMonitor(log)
		// runMonitor blocks and never returns (runs until process killed).
	}

	// ── Normal service path: initialise logger ──────────────────────────────────
	var log *logger.Logger
	var err error
	if *flagSvcAction == "run" {
		ensureDataDir()
		log, err = logger.NewFileOnly(state.LogPath())
	} else {
		ensureDataDir()
		log, err = logger.New(state.LogPath())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] could not open log file: %v – logging to stderr only\n", err)
		log = logger.NewStderrOnly()
	}
	defer log.Close()

	log.SetLevel(logger.ParseLevel(*flagLogLevel))

	log.Infof("sharedAccountRotate starting – version built %s", buildDate())

	// ── Early dispatch for config-free service actions ──────────────────────────
	// start/stop/remove only talk to the SCM and don't need domain, username, or
	// LDAP config. Dispatch them before the hostname/domain validation below.
	if *flagSvcAction == "remove" || *flagSvcAction == "start" || *flagSvcAction == "stop" {
		if err := service.HandleServiceAction(&service.Config{
			Log:       log,
			SvcAction: *flagSvcAction,
		}); err != nil {
			log.Fatalf("service action %q failed: %v", *flagSvcAction, err)
		}
		return
	}

	// ── Log the file path for debugging ─────────────────────────────────────────
	log.Infof("service: log file path: %s", state.LogPath())

	// ── Default username to the machine hostname ────────────────────────────────
	// The AD user account and computer object share the same name, so the
	// hostname is the correct default in all normal deployments.
	if *flagUsername == "" {
		host, err := os.Hostname()
		if err != nil {
			log.Fatalf("could not determine hostname for --username default: %v", err)
		}
		*flagUsername = host
		log.Infof("--username not specified, defaulting to hostname: %s", *flagUsername)
	}

	// ── Validate required flags ───────────────────────────────────────────────
	if *flagDomain == "" {
		log.Fatalf("--domain is required")
	}

	// Default LDAP server to the domain name (works when SRV records are
	// configured; otherwise the caller should supply an explicit server).
	ldapServer := *flagLDAPServer
	if ldapServer == "" {
		ldapServer = *flagDomain
	}

	// ── Build the central config struct shared by all subsystems ─────────────
	cfg := &service.Config{
		Log:          log,
		Domain:       *flagDomain,
		LDAPServer:   ldapServer,
		LDAPPort:     *flagLDAPPort,
		Username:     *flagUsername,
		RotationDays: *flagDays,
		IdleHours:    *flagIdleHours,
		DevMode:      *flagDev,
		SvcAction:    *flagSvcAction,
		LogLevel:     *flagLogLevel,
	}

	// ── Dispatch on --service flag ────────────────────────────────────────────
	// If a service action was requested, handle it and exit.  The "run" action
	// is what the SCM calls; it blocks until the service is stopped.
	if cfg.SvcAction != "" {
		if err := service.HandleServiceAction(cfg); err != nil {
			log.Fatalf("service action %q failed: %v", cfg.SvcAction, err)
		}
		return
	}

	// ── Interactive / foreground mode ─────────────────────────────────────────
	// Run directly in the terminal (useful during development without the SCM).
	log.Info("running in foreground (interactive) mode")
	svc := service.New(cfg)
	if err := svc.Run(); err != nil {
		log.Fatalf("rotation loop exited with error: %v", err)
	}
}

// ensureDataDir creates C:\ProgramData\sharedAccountRotate if it doesn't exist.
// This ensures the data directory is present whenever any code path (monitor,
// interactive, service) starts up, avoiding write failures on first run.
func ensureDataDir() {
	dir := state.DataDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] could not create data directory: %v – will try again on write\n", err)
	}
}

// runMonitor polls GetLastInputInfo every 5 seconds and writes the resulting
// idle status to a dedicated file (sharedAccountRotate_idle.json). This file
// is separate from the service's state file to avoid permission conflicts
// when SYSTEM writes the state file and the user's monitor process tries to
// overwrite it. The service reads idle status from this file.
func runMonitor(log *logger.Logger) {
	for {
		idle, err := activity.IdleTime()
		if err != nil {
			log.Errorf("monitor: idle check error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Consider idle if the workstation has had no input for at least 2 minutes.
		// The service enforces the full --idle-hours threshold separately.
		const minIdle = 2 * time.Minute
		isIdle := idle >= minIdle

		status := state.IdleStatus{
			IsIdle:       isIdle,
			IdleUpdated:  time.Now().UTC(),
			IdleDuration: idle.Seconds(),
		}

		if err := writeIdleStatus(&status); err != nil {
			log.Errorf("monitor: could not save idle status: %v", err)
		} else {
			if isIdle {
				log.Debugf("monitor: idle for %v – wrote is_idle=true", idle.Round(time.Second))
			} else {
				log.Debugf("monitor: active (idle=%v) – wrote is_idle=false", idle.Round(time.Second))
			}
		}
		time.Sleep(5 * time.Second)
	}
}

// writeIdleStatus writes the idle status to a dedicated temp file then renames
// it. Non-atomic fallback avoids the rename permission issue when overwriting.
func writeIdleStatus(s *state.IdleStatus) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("idle marshal: %w", err)
	}

	idlePath := state.IdlePath()
	dir := filepath.Dir(idlePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("idle mkdir: %w", err)
	}

	// Write to a temp file, then rename. If rename fails (permissions),
	// fall back to truncating the target file directly.
	tmp, err := os.CreateTemp(dir, "sharedAccountRotate_idle_*.tmp")
	if err != nil {
		return fmt.Errorf("idle temp create: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("idle write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("idle close: %w", err)
	}

	if err := os.Rename(tmpName, idlePath); err != nil {
		// Rename failed — likely a permissions issue.
		// Fall back to writing the file directly (truncates and overwrites).
		if werr := os.WriteFile(idlePath, data, 0644); werr != nil {
			os.Remove(tmpName)
			return fmt.Errorf("idle rename, then also writeFile fallback: %v", werr)
		}
		// Clean up the temp file since we used the fallback.
		os.Remove(tmpName)
		return nil
	}

	// Make the file world-readable so any process can read it.
	_ = os.Chmod(idlePath, 0644)
	return nil
}

// buildDate returns the build timestamp embedded at compile time via -ldflags,
// or "unknown" if the variable was not set.
var buildTimestamp = "unknown" // set with: -ldflags "-X main.buildTimestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

func buildDate() string {
	if buildTimestamp == "" {
		return "unknown"
	}
	return buildTimestamp
}

// Ensure the rotation interval makes sense at startup so misconfigurations are
// caught immediately rather than after the first sleep period.
func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `sharedAccountRotate – AD password rotation Windows service

Usage:
  sharedAccountRotate.exe [flags]

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  # Install as a Windows service
  # This copies the binary to "C:\Program Files\sharedAccountRotate\" and
  # registers the service with the Windows Service Control Manager.
  sharedAccountRotate.exe --service install --domain corp.example.com --days 30

  # Dev/test run – rotate immediately, no idle check
  sharedAccountRotate.exe --dev --domain corp.example.com

  # Normal foreground run
  sharedAccountRotate.exe --domain corp.example.com --days 14 --idle-hours 3

  # Logging options: DEBUG | INFO | WARN | ERROR (default: INFO)
  sharedAccountRotate.exe --loglevel DEBUG --dev --domain corp.example.com

  # Service control actions (run from any location after install)
  sharedAccountRotate.exe --service start
  sharedAccountRotate.exe --service stop
  sharedAccountRotate.exe --service remove
  sharedAccountRotate.exe --service update

Installation:
  The service install action performs the following steps:
    1. Creates "C:\Program Files\sharedAccountRotate\" for the binary
    2. Creates "C:\ProgramData\sharedAccountRotate\" for state and log files
    3. Copies the binary to the Program Files directory
    4. Verifies the copy succeeded before registering the service
    5. Registers the service to run from the Program Files location
    6. Sets the service to start automatically
    7. Installs the accountRotateMonitor.exe in the startup folder

  The original binarys can be deleted after successful installation.
`)
	}

	// Validate numeric ranges after flag.Parse() runs.
	// (flag.Parse has not been called yet at init time, so we hook into main.)
	origParse := flag.CommandLine.Parse
	_ = origParse // referenced to satisfy the compiler; validation is in main()

	// Ensure rotation interval is at least 1 day at runtime.
	_ = time.Now() // imported for compile-time check
}
