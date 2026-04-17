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
	"github.com/Kory-Albert/sharedAccountRotate/internal/state"
)

// ─── CLI flags ────────────────────────────────────────────────────────────────

var (
	// Log level controls which messages are written to the log file.
	// Valid values: DEBUG, INFO, WARN, ERROR (default: INFO)
	flagLogLevel = flag.String("loglevel", "INFO", "Log level: DEBUG | INFO | WARN | ERROR")
)

// ─── Entry point ──────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	// Ensure data directory exists
	ensureDataDir()

	// Create logger that writes to the monitor-specific log file
	log, err := logger.New(state.MonitorLogPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] could not open monitor log: %v – logging to stderr only\n", err)
		log = logger.NewStderrOnly()
	}
	defer log.Close()

	log.SetLevel(logger.ParseLevel(*flagLogLevel))

	// Run the monitor loop (same logic as in main.go)
	runMonitor(log)
}

// ensureDataDir creates C:\ProgramData\sharedAccountRotate if it doesn't exist.
func ensureDataDir() {
	dir := state.DataDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] could not create data directory: %v – will try again on write\n", err)
	}
}

// runMonitor polls GetLastInputInfo every 5 seconds and writes the resulting
// idle status to a dedicated file (sharedAccountRotate_idle.json).
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
