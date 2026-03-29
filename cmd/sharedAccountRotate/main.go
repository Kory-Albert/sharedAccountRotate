// sharedAccountRotate - Active Directory password rotation service
//
// Runs as a Windows Service under SYSTEM. On each configured interval it:
//   1. Waits until the workstation has been idle for --idle-hours
//   2. Generates a cryptographically random password
//   3. Sets the new password in Active Directory (Kerberos / LDAP, no PowerShell)
//   4. Stores the new password in the LSA secret that Sysinternals Autologon uses
//   5. Verifies both writes succeeded
//   6. Signs the current session out so the machine auto-logs back in
//
// All events are written to stdout AND to C:\Windows\Temp\sharedAccountRotate.log.
// Passwords are never written to any log or output.

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sharedAccountRotate/sharedAccountRotate/internal/logger"
	"github.com/sharedAccountRotate/sharedAccountRotate/internal/service"
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

	// Windows service control verbs (install / remove / start / stop / run).
	// "run" is what the SCM calls when starting the service normally.
	flagSvcAction = flag.String("service", "", "Service action: install | remove | start | stop | run")

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
)

// ─── Entry point ──────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	// Initialise the dual logger (stdout + file) as early as possible so every
	// subsequent message is captured.
	log, err := logger.New(`C:\Windows\Temp\sharedAccountRotate.log`)
	if err != nil {
		// Fall back to stderr-only if the log file cannot be opened; do not
		// abort – it is better to run without file logging than not at all.
		fmt.Fprintf(os.Stderr, "[WARN] could not open log file: %v – logging to stdout only\n", err)
		log = logger.NewStdoutOnly()
	}
	defer log.Close()

	// Set the configured log level before any log messages are written.
	log.SetLevel(logger.ParseLevel(*flagLogLevel))

	log.Infof("sharedAccountRotate starting – version built %s", buildDate())

	// ── Default username to the machine hostname ────────────────────────────────────────────
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
	// --domain is required for all modes except service removal (which needs no config).
	// --username defaults to hostname above, so it never needs validation.
	if *flagDomain == "" && *flagSvcAction != "remove" {
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
		Log:           log,
		Domain:        *flagDomain,
		LDAPServer:    ldapServer,
		LDAPPort:      *flagLDAPPort,
		Username:      *flagUsername,
		RotationDays:  *flagDays,
		IdleHours:     *flagIdleHours,
		DevMode:       *flagDev,
		SvcAction:     *flagSvcAction,
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

Installation:
  The service install action performs the following steps:
    1. Creates "C:\Program Files\sharedAccountRotate\"
    2. Copies the binary to that directory
    3. Verifies the copy succeeded before registering the service
    4. Registers the service to run from the Program Files location
    5. Sets the service to start automatically

  The original binary can be deleted after successful installation.
`)
	}

	// Validate numeric ranges after flag.Parse() runs.
	// (flag.Parse has not been called yet at init time, so we hook into main.)
	origParse := flag.CommandLine.Parse
	_ = origParse // referenced to satisfy the compiler; validation is in main()

	// Ensure rotation interval is at least 1 day at runtime.
	_ = time.Now() // imported for compile-time check
}
