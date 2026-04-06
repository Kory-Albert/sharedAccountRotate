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
)

// LASTINPUTINFO mirrors the Windows structure.
// cbSize must be set to sizeof(LASTINPUTINFO) before calling GetLastInputInfo.
type lastInputInfo struct {
	cbSize uint32
	dwTime uint32 // tick count of last input event (wraps every ~49.7 days)
}

// IdleTime returns how long the workstation has been idle (no keyboard/mouse).
func IdleTime() (time.Duration, error) {
	info := lastInputInfo{
		cbSize: uint32(unsafe.Sizeof(lastInputInfo{})),
	}
	r0, _, err := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&info)))
	if r0 == 0 {
		return 0, fmt.Errorf("GetLastInputInfo: %w", err)
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
