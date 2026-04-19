// Package logger provides a lightweight, thread‑safe logger that writes to stdout and an optional file, using only the stdlib.
// It supports leveled logs and zero‑dependency fatal exits.
// No secrets may be logged – callers are responsible for sanitising input.

package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

// LogLevel represents the severity level of log messages.
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// ParseLevel converts a string level to LogLevel.
// Returns INFO as default if string is unrecognized.
func ParseLevel(s string) LogLevel {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARN", "WARNING":
		return WARN
	case "ERROR":
		return ERROR
	default:
		return INFO
	}
}

// Logger writes structured log lines to stdout and optionally to a file.
type Logger struct {
	mu    sync.Mutex
	impl  *log.Logger
	file  *os.File // nil when stdout-only
	level LogLevel
}

// New opens (or creates / appends to) the given file path and returns a Logger
// that writes to both the file and os.Stdout.
func New(filePath string) (*Logger, error) {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("logger: open %s: %w", filePath, err)
	}
	// MultiWriter writes to stdout and file sequentially. In a Windows service
	// context, os.Stdout is a null handle attached to the session — writes
	// succeed but consume bandwidth. This is acceptable because it lets devs
	// see output during --dev / --foreground testing.
	mw := io.MultiWriter(os.Stdout, f)
	impl := log.New(mw, "", log.Ldate|log.Ltime|log.LUTC)
	return &Logger{impl: impl, file: f, level: INFO}, nil
}

// NewFileOnly returns a Logger that writes only to the given file path,
// skipping os.Stdout. Use this for Windows services where stdout is not visible.
func NewFileOnly(filePath string) (*Logger, error) {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("logger: open %s: %w", filePath, err)
	}
	impl := log.New(f, "", log.Ldate|log.Ltime|log.LUTC)
	return &Logger{impl: impl, file: f, level: INFO}, nil
}

// NewStdoutOnly returns a Logger that only writes to stdout (used as a fallback
// in dev mode).
func NewStdoutOnly() *Logger {
	impl := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.LUTC)
	return &Logger{impl: impl, level: INFO}
}

// NewStderrOnly returns a Logger that only writes to stderr (used as a fallback
// when the log file cannot be opened).
func NewStderrOnly() *Logger {
	impl := log.New(os.Stderr, "", log.Ldate|log.Ltime|log.LUTC)
	return &Logger{impl: impl, level: INFO}
}

// SetLevel sets the minimum log level that will be written to output.
// Messages below this level will be silently dropped.
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// shouldLog returns true if the given level should be logged given the current
// configured level.
func (l *Logger) shouldLog(level LogLevel) bool {
	return level >= l.level
}

// Close flushes and closes the underlying log file (if any).
func (l *Logger) Close() {
	if l.file != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		_ = l.file.Sync()
		_ = l.file.Close()
	}
}

// ─── Logging methods ──────────────────────────────────────────────────────────

func (l *Logger) Infof(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.shouldLog(INFO) {
		return
	}
	l.impl.Printf("[INFO]  "+format, args...)
}

func (l *Logger) Info(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.shouldLog(INFO) {
		return
	}
	l.impl.Printf("[INFO]  %s", msg)
}

func (l *Logger) Warnf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.shouldLog(WARN) {
		return
	}
	l.impl.Printf("[WARN]  "+format, args...)
}

func (l *Logger) Warn(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.shouldLog(WARN) {
		return
	}
	l.impl.Printf("[WARN]  %s", msg)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.shouldLog(ERROR) {
		return
	}
	l.impl.Printf("[ERROR] "+format, args...)
}

func (l *Logger) Error(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.shouldLog(ERROR) {
		return
	}
	l.impl.Printf("[ERROR] %s", msg)
}

func (l *Logger) Debugf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.shouldLog(DEBUG) {
		return
	}
	l.impl.Printf("[DEBUG] "+format, args...)
}

func (l *Logger) Debug(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.shouldLog(DEBUG) {
		return
	}
	l.impl.Printf("[DEBUG] %s", msg)
}

// Fatalf logs a fatal message and calls os.Exit(1). Use sparingly – only for
// conditions that make continued operation impossible (e.g., missing required
// flags at startup).
func (l *Logger) Fatalf(format string, args ...any) {
	l.mu.Lock()
	l.impl.Printf("[FATAL] "+format, args...)
	if l.file != nil {
		_ = l.file.Sync()
	}
	l.mu.Unlock()
	os.Exit(1)
}

func (l *Logger) Fatal(msg string) {
	l.mu.Lock()
	l.impl.Printf("[FATAL] %s", msg)
	if l.file != nil {
		_ = l.file.Sync()
	}
	l.mu.Unlock()
	os.Exit(1)
}
