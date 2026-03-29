// Package session handles Windows session enumeration and logoff.
//
// After a successful password rotation we must sign out the target user so
// that Winlogon can use the new password to auto-log back in. We use
// WTSEnumerateSessions / WTSLogoffSession from wtsapi32.dll so we can target
// only the correct user session without disturbing any admin sessions.

//go:build windows

package session

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/sharedAccountRotate/sharedAccountRotate/internal/logger"
)

var (
	modWtsapi32           = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateSessions = modWtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSLogoffSession  = modWtsapi32.NewProc("WTSLogoffSession")
	procWTSFreeMemory     = modWtsapi32.NewProc("WTSFreeMemory")
	procWTSQuerySessionInfo = modWtsapi32.NewProc("WTSQuerySessionInformationW")
)

// WTS_SESSION_INFO mirrors the Windows WTS_SESSION_INFOW structure.
type wtsSessionInfo struct {
	SessionID         uint32
	pWinStationName   *uint16
	State             uint32
}

const (
	wtsCurrentServerHandle uintptr = 0
	wtsUserName            uint32  = 5  // WTSUserName info class
	wtsActive              uint32  = 0  // WTSConnectState: active session
)

// Client handles session management.
type Client struct {
	log *logger.Logger
}

// New returns a session client.
func New(log *logger.Logger) *Client {
	return &Client{log: log}
}

// LogoffUser finds all active sessions belonging to username and logs them off.
// It is not an error if no session is found (the user may not be logged in yet).
func (c *Client) LogoffUser(username string) error {
	c.log.Infof("session: enumerating sessions to find user %q", username)

	sessions, err := enumerateSessions()
	if err != nil {
		return fmt.Errorf("session enumerate: %w", err)
	}
	c.log.Infof("session: found %d total sessions", len(sessions))

	loggedOff := 0
	for _, s := range sessions {
		// Query the username associated with this session.
		sessUser, err := querySessionUsername(s.SessionID)
		if err != nil {
			c.log.Warnf("session: could not query user for session %d: %v", s.SessionID, err)
			continue
		}

		if !strings_EqualFold(sessUser, username) {
			continue
		}

		c.log.Infof("session: logging off session %d (user=%q state=%d)", s.SessionID, sessUser, s.State)
		if err := logoffSession(s.SessionID); err != nil {
			c.log.Warnf("session: logoff of session %d failed: %v", s.SessionID, err)
			continue
		}
		c.log.Infof("session: session %d logged off successfully", s.SessionID)
		loggedOff++
	}

	if loggedOff == 0 {
		c.log.Warnf("session: no active sessions found for user %q – nothing to log off", username)
	} else {
		c.log.Infof("session: logged off %d session(s) for user %q", loggedOff, username)
	}
	return nil
}

// ─── Low-level WTS helpers ────────────────────────────────────────────────────

func enumerateSessions() ([]wtsSessionInfo, error) {
	var pSessions *wtsSessionInfo
	var count uint32

	r0, _, err := procWTSEnumerateSessions.Call(
		wtsCurrentServerHandle,
		0, 1, // Reserved, Version
		uintptr(unsafe.Pointer(&pSessions)),
		uintptr(unsafe.Pointer(&count)),
	)
	if r0 == 0 {
		return nil, fmt.Errorf("WTSEnumerateSessionsW: %w", err)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pSessions)))

	// Copy the structs out before freeing.
	slice := unsafe.Slice(pSessions, count)
	result := make([]wtsSessionInfo, count)
	copy(result, slice)
	return result, nil
}

func querySessionUsername(sessionID uint32) (string, error) {
	var pBuf *uint16
	var bytesReturned uint32

	r0, _, err := procWTSQuerySessionInfo.Call(
		wtsCurrentServerHandle,
		uintptr(sessionID),
		uintptr(wtsUserName),
		uintptr(unsafe.Pointer(&pBuf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r0 == 0 {
		return "", fmt.Errorf("WTSQuerySessionInformationW: %w", err)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pBuf)))

	if pBuf == nil || bytesReturned == 0 {
		return "", nil
	}
	return windows.UTF16PtrToString(pBuf), nil
}

func logoffSession(sessionID uint32) error {
	r0, _, err := procWTSLogoffSession.Call(
		wtsCurrentServerHandle,
		uintptr(sessionID),
		1, // bWait = TRUE: block until logoff completes
	)
	if r0 == 0 {
		return fmt.Errorf("WTSLogoffSession: %w", err)
	}
	return nil
}

// strings_EqualFold is a dependency-free case-insensitive string compare.
func strings_EqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
