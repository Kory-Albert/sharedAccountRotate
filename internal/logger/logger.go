// Package logger provides a simple structured logger that writes to both
// os.Stdout and a rotating log file simultaneously.
//
// Design goals:
//   - Zero external dependencies (stdlib only)
//   - Thread-safe (single mutex)
//   - Timestamps on every line
//   - Fatal() calls os.Exit(1) so callers can abort on unrecoverable errors
//   - Passwords must NEVER be passed to any log function; the logger itself
//     has no special redaction – callers are responsible for not logging secrets.

package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// Logger writes structured log lines to stdout and optionally to a file.
type Logger struct {
	mu   sync.Mutex
	impl *log.Logger
	file *os.File // nil when stdout-only
}

// New opens (or creates / appends to) the given file path and returns a Logger
// that writes to both that file and os.Stdout.
func New(filePath string) (*Logger, error) {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("logger: open %s: %w", filePath, err)
	}
	mw := io.MultiWriter(os.Stdout, f)
	impl := log.New(mw, "", log.Ldate|log.Ltime|log.LUTC)
	return &Logger{impl: impl, file: f}, nil
}

// NewStdoutOnly returns a Logger that only writes to stdout (used as a fallback
// when the log file cannot be opened).
func NewStdoutOnly() *Logger {
	impl := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.LUTC)
	return &Logger{impl: impl}
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
	l.impl.Printf("[INFO]  "+format, args...)
}

func (l *Logger) Info(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.impl.Printf("[INFO]  %s", msg)
}

func (l *Logger) Warnf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.impl.Printf("[WARN]  "+format, args...)
}

func (l *Logger) Warn(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.impl.Printf("[WARN]  %s", msg)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.impl.Printf("[ERROR] "+format, args...)
}

func (l *Logger) Error(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.impl.Printf("[ERROR] %s", msg)
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
