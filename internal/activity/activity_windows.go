// Package activity detects workstation idle time using the Windows
// GetLastInputInfo API, which tracks the most recent keyboard or mouse event
// across all sessions.
//
// This is the same mechanism used by screen savers and power management to
// determine user presence. It is non-invasive (read-only, no hooks installed)
// and accurate enough for our purpose.
//
// The IsIdle function returns true only when the system has not received
// any mouse or keyboard input for at least the configured duration.

//go:build windows

package activity

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32            = windows.NewLazySystemDLL("user32.dll")
	procGetLastInputInfo = modUser32.NewProc("GetLastInputInfo")
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64   = modKernel32.NewProc("GetTickCount64")
	procGetActiveConsoleSessionID = modKernel32.NewProc("WTSGetActiveConsoleSessionId")

	modWtsapi32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = modWtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = modWtsapi32.NewProc("WTSFreeMemory")
)

// LASTINPUTINFO mirrors the Windows structure.
// cbSize must be set to sizeof(LASTINPUTINFO) before calling GetLastInputInfo.
type lastInputInfo struct {
	cbSize uint32
	dwTime uint32 // tick count of last input event (wraps every ~49.7 days)
}

// IdleTime returns how long the workstation has been idle (no keyboard/mouse).
//
// When running as a Windows service (Session 0), GetLastInputInfo fails with
// 0x8000FFFF because it tracks the interactive desktop. In that case we fall back
// to querying the active console session's last input time via the WTS API, which
// works from Session 0.
func IdleTime() (time.Duration, error) {
	// ── Fast path: try GetLastInputInfo (works in interactive sessions) ────────
	t, err := idleTimeFromDesktop()
	if err == nil {
		return t, nil
	}

	// ── Fallback: use WTS API for Session 0 (service context) ─────────────────
	return idleTimeFromWTS()
}

// idleTimeFromDesktop uses GetLastInputInfo (fails in Session 0).
func idleTimeFromDesktop() (time.Duration, error) {
	info := lastInputInfo{
		cbSize: uint32(unsafe.Sizeof(lastInputInfo{})),
	}
	r0, _, err := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&info)))
	if r0 == 0 {
		return 0, err // returns syscall.Errno
	}

	// GetTickCount64 avoids the 49.7-day wrap-around of the 32-bit version.
	r1, _, _ := procGetTickCount64.Call()
	nowTick := uint64(r1)
	lastTick := uint64(info.dwTime)

	// Handle potential 32-bit wrap in dwTime by masking to 32 bits.
	nowTick32 := nowTick & 0xFFFFFFFF
	var idleTicks uint64
	if nowTick32 >= lastTick {
		idleTicks = nowTick32 - lastTick
	} else {
		// Wrapped: add the full 32-bit range to compensate.
		idleTicks = (0x100000000 - lastTick) + nowTick32
	}
	return time.Duration(idleTicks) * time.Millisecond, nil
}

// idleTimeFromWTS uses WTS API to get the last input time of the active console
// session. Works from Session 0 (service context).
func idleTimeFromWTS() (time.Duration, error) {
	// Get the active console session ID from kernel32
	r0, _, err := procGetActiveConsoleSessionID.Call()
	if r0 == 0xFFFFFFFF {
		return 0, fmt.Errorf("WTSGetActiveConsoleSessionId: %w", err)
	}
	consoleSessionID := uint32(r0)

	// WTSLastInputTime (class 22) returns a FILETIME for the session's last input
	const wtsLastInputTime uint32 = 22
	var pBuf *byte
	var dataLen uint32

	r0, _, err = procWTSQuerySessionInformationW.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		uintptr(consoleSessionID),
		uintptr(wtsLastInputTime),
		uintptr(unsafe.Pointer(&pBuf)),
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if r0 == 0 {
		return 0, fmt.Errorf("WTSQuerySessionInformationW(class=WTSLastInputTime): %w", err)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pBuf)))

	if dataLen < 8 {
		return 0, fmt.Errorf("WTSLastInputTime: unexpected data length %d (expected 8)", dataLen)
	}

	// FILETIME is two uint32 values (low, high) in 100ns intervals since 1601-01-01
	lastInputFT := windows.Filetime{
		LowDateTime:  *(*uint32)(unsafe.Pointer(pBuf)),
		HighDateTime: *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(pBuf)) + 4)),
	}

	lastInput := time.Unix(0, lastInputFT.Nanoseconds())
	idleDuration := time.Since(lastInput)

	if idleDuration < 0 {
		idleDuration = 0
	}
	return idleDuration, nil
}

// IsIdle returns true if the workstation has been idle for at least minIdle.
func IsIdle(minIdle time.Duration) (bool, error) {
	idle, err := IdleTime()
	if err != nil {
		return false, err
	}
	return idle >= minIdle, nil
}

// WaitForIdle blocks until the workstation has been idle for at least minIdle,
// checking every checkInterval. It logs periodic status updates via logFn.
//
// Example: WaitForIdle(2*time.Hour, 5*time.Minute, log.Infof)
func WaitForIdle(minIdle, checkInterval time.Duration, logFn func(string, ...any)) {
	logFn("activity: waiting for %v of idle time (checking every %v)", minIdle, checkInterval)
	for {
		idle, err := IdleTime()
		if err != nil {
			logFn("activity: error reading idle time: %v – will retry in %v", err, checkInterval)
			time.Sleep(checkInterval)
			continue
		}

		if idle >= minIdle {
			logFn("activity: workstation has been idle for %v (threshold %v) – proceeding", idle.Round(time.Second), minIdle)
			return
		}

		remaining := minIdle - idle
		logFn("activity: workstation active – idle for %v, need %v more before rotation",
			idle.Round(time.Second), remaining.Round(time.Second))
		time.Sleep(checkInterval)
	}
}
