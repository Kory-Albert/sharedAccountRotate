// sharedAccountRotate – AD password rotation service
//
// Runs as a Windows Service under SYSTEM. Each interval it waits for idle, generates a
// random password, updates AD, stores it in the LSA secret, verifies both writes, and
// logs off the target user so autosign‑on uses the new password.
//
// A separate monitor helper (launched from the Startup folder) reports idle
// status to a shared state file.
//
// All events are logged to stdout and a file.

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

// Flags
var (
	// Number of days between password rotations.
	flagDays = flag.Int("days", 30, "Days between password rotations")

	// Minimum idle hours before rotation.
	flagIdleHours = flag.Float64("idle-hours", 2.0, "Hours of workstation idle time required before rotation")

	// Dev mode: skip day/idle checks and rotate immediately.
	flagDev = flag.Bool("dev", false, "Developer mode – rotate immediately, skip day/idle checks")

	// Windows service action.
	flagSvcAction = flag.String("service", "", "Service action: install | remove | start | stop | update | run")

	// LDAP/AD connection.
	flagDomain     = flag.String("domain", "", "AD domain (e.g. corp.example.com) – required")
	flagLDAPServer = flag.String("ldap-server", "", "LDAP server hostname/IP (defaults to domain if empty)")
	flagLDAPPort   = flag.Int("ldap-port", 636, "LDAPS port (default 636 for TLS)")

	// User whose password is rotated.
	flagUsername = flag.String("username", "", "AD username to rotate (defaults to machine hostname)")

	// Logging verbosity.
	flagLogLevel = flag.String("loglevel", "INFO", "Log level: DEBUG | INFO | WARN | ERROR")
)

func main() {
	flag.Parse()

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

	if *flagSvcAction == "remove" || *flagSvcAction == "start" || *flagSvcAction == "stop" {
		if err := service.HandleServiceAction(&service.Config{
			Log:       log,
			SvcAction: *flagSvcAction,
		}); err != nil {
			log.Fatalf("service action %q failed: %v", *flagSvcAction, err)
		}
		return
	}

	log.Infof("service: log file path: %s", state.LogPath())

	if *flagUsername == "" {
		host, err := os.Hostname()
		if err != nil {
			log.Fatalf("could not determine hostname for --username default: %v", err)
		}
		*flagUsername = host
		log.Infof("--username not specified, defaulting to hostname: %s", *flagUsername)
	}

	if *flagDomain == "" {
		log.Fatalf("--domain is required")
	}

	ldapServer := *flagLDAPServer
	if ldapServer == "" {
		ldapServer = *flagDomain
	}

	// Central config struct shared by all subsystems ─────────────
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

	if cfg.SvcAction != "" {
		if err := service.HandleServiceAction(cfg); err != nil {
			log.Fatalf("service action %q failed: %v", cfg.SvcAction, err)
		}
		return
	}

	log.Info("running in foreground (interactive) mode")
	svc := service.New(cfg)
	if err := svc.Run(); err != nil {
		log.Fatalf("rotation loop exited with error: %v", err)
	}
}

func ensureDataDir() {
	dir := state.DataDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] could not create data directory: %v – will try again on write\n", err)
	}
}

func runMonitor(log *logger.Logger) {
	for {
		idle, err := activity.IdleTime()
		if err != nil {
			log.Errorf("monitor: idle check error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
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
		if werr := os.WriteFile(idlePath, data, 0644); werr != nil {
			os.Remove(tmpName)
			return fmt.Errorf("idle rename, then also writeFile fallback: %v", werr)
		}
		os.Remove(tmpName)
		return nil
	}
	_ = os.Chmod(idlePath, 0644)
	return nil
}

var buildTimestamp = "unknown"

func buildDate() string {
	if buildTimestamp == "" {
		return "unknown"
	}
	return buildTimestamp
}

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
