// Package lsa provides functions to read and write LSA (Local Security
// Authority) secret values on Windows using the native LsaStorePrivateData /
// LsaRetrievePrivateData APIs.
//
// Sysinternals Autologon stores the auto-logon password in the LSA secret
// named "DefaultPassword" (the same name used by the Windows GINA / Winlogon
// credential provider). We replicate that exact behaviour.
//
// The registry keys written by Autologon under
//
//	HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
//
// are also updated here to ensure DefaultUserName, DefaultDomainName,
// AutoAdminLogon, and ForceAutoLogon are set correctly.
//
// All operations require SeSecurityPrivilege or SYSTEM-level access.
// Running as SYSTEM (via a Windows service) satisfies this requirement.

//go:build windows

package lsa

import (
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Kory-Albert/sharedAccountRotate/internal/logger"
)

// ─── Windows API declarations ─────────────────────────────────────────────────

var (
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procLsaOpenPolicy          = modAdvapi32.NewProc("LsaOpenPolicy")
	procLsaStorePrivateData    = modAdvapi32.NewProc("LsaStorePrivateData")
	procLsaRetrievePrivateData = modAdvapi32.NewProc("LsaRetrievePrivateData")
	procLsaClose               = modAdvapi32.NewProc("LsaClose")
	procLsaFreeMemory          = modAdvapi32.NewProc("LsaFreeMemory")
	procLsaNtStatusToWinError  = modAdvapi32.NewProc("LsaNtStatusToWinError")
)

// LSA_OBJECT_ATTRIBUTES – all fields zeroed is valid for LsaOpenPolicy.
type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            windows.Handle
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// LSA_UNICODE_STRING mirrors the Windows structure.
type lsaUnicodeString struct {
	Length        uint16 // byte length (not including null)
	MaximumLength uint16 // byte length of Buffer
	Buffer        *uint16
}

const (
	// POLICY_CREATE_SECRET | POLICY_GET_PRIVATE_INFORMATION
	policyAllAccess uint32 = 0x000F0FFF
)

// ─── Public API ───────────────────────────────────────────────────────────────

// Client wraps LSA policy handle operations.
type Client struct {
	log *logger.Logger
}

// New returns an LSA client.
func New(log *logger.Logger) *Client {
	return &Client{log: log}
}

// StoreAutologonPassword writes the new password into the LSA secret
// "DefaultPassword" – the same location Sysinternals Autologon uses – and
// updates the Winlogon registry keys.
//
// domain and username are stored in clear-text in the Winlogon registry key
// (this is normal Windows behaviour; only the password is protected by LSA).
func (c *Client) StoreAutologonPassword(domain, username string, password []byte) error {
	c.log.Info("LSA: opening policy handle")
	policyHandle, err := lsaOpenPolicy()
	if err != nil {
		return fmt.Errorf("LSA open policy: %w", err)
	}
	defer func() {
		lsaClose(policyHandle)
		c.log.Info("LSA: policy handle closed")
	}()

	// ── Write LSA secret ──────────────────────────────────────────────────────
	c.log.Info("LSA: storing password in DefaultPassword secret")
	if err := lsaStorePrivateData(policyHandle, "DefaultPassword", password); err != nil {
		return fmt.Errorf("LSA store DefaultPassword: %w", err)
	}
	c.log.Info("LSA: DefaultPassword secret updated")

	// ── Update Winlogon registry keys ─────────────────────────────────────────
	c.log.Info("LSA: updating Winlogon registry values")
	if err := c.setWinlogonKeys(domain, username); err != nil {
		return fmt.Errorf("LSA update Winlogon registry: %w", err)
	}
	c.log.Info("LSA: Winlogon registry values updated")

	return nil
}

// VerifyAutologonPassword reads back the LSA secret and confirms it matches the
// supplied password. The in-memory comparison is done byte-by-byte and both
// sides are zeroed immediately after.
func (c *Client) VerifyAutologonPassword(password []byte) error {
	c.log.Info("LSA: verifying DefaultPassword secret")
	policyHandle, err := lsaOpenPolicy()
	if err != nil {
		return fmt.Errorf("LSA verify – open policy: %w", err)
	}
	defer lsaClose(policyHandle)

	stored, err := lsaRetrievePrivateData(policyHandle, "DefaultPassword")
	if err != nil {
		return fmt.Errorf("LSA verify – retrieve: %w", err)
	}
	defer zeroBytes(stored)

	// Compare without revealing either value.
	// We encode our candidate the same way the store function does (UTF-16LE).
	candidate := utf16LEBytes(password)
	defer zeroBytes(candidate)

	if len(stored) != len(candidate) {
		return fmt.Errorf("LSA verify: length mismatch (stored %d bytes, candidate %d bytes)", len(stored), len(candidate))
	}
	var diff byte
	for i := range stored {
		diff |= stored[i] ^ candidate[i]
	}
	if diff != 0 {
		return fmt.Errorf("LSA verify: stored password does not match new password")
	}

	c.log.Info("LSA: DefaultPassword verification succeeded")
	return nil
}

// ─── Registry helpers ─────────────────────────────────────────────────────────

const winlogonKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

func (c *Client) setWinlogonKeys(domain, username string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open Winlogon key: %w", err)
	}
	defer k.Close()

	values := map[string]string{
		"AutoAdminLogon":    "1",
		"ForceAutoLogon":    "1",
		"DefaultDomainName": domain,
		"DefaultUserName":   username,
		// DefaultPassword registry value is intentionally left blank –
		// the LSA secret is the authoritative location. Winlogon reads the
		// LSA secret preferentially when it is set.
	}

	for name, val := range values {
		if err := k.SetStringValue(name, val); err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
		c.log.Infof("LSA: registry Winlogon\\%s set", name)
	}
	return nil
}

// ─── Low-level LSA wrappers ───────────────────────────────────────────────────

// lsaOpenPolicy opens a handle to the local LSA policy object with
// POLICY_ALL_ACCESS rights.
func lsaOpenPolicy() (windows.Handle, error) {
	var attrs lsaObjectAttributes
	attrs.Length = uint32(unsafe.Sizeof(attrs))

	var handle windows.Handle
	r0, _, _ := procLsaOpenPolicy.Call(
		0, // SystemName = NULL → local machine
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(policyAllAccess),
		uintptr(unsafe.Pointer(&handle)),
	)
	if r0 != 0 {
		return 0, ntStatusError("LsaOpenPolicy", r0)
	}
	return handle, nil
}

// lsaStorePrivateData stores data under the named LSA secret key.
// Windows encodes the value as UTF-16LE internally; we encode it here so the
// stored bytes exactly match what Autologon writes.
func lsaStorePrivateData(policy windows.Handle, name string, data []byte) error {
	keyStr := newLSAString(name)
	encoded := utf16LEBytes(data)
	defer zeroBytes(encoded) // single allocation — zeroed on all exit paths

	dataStr := lsaUnicodeString{
		Length:        uint16(len(encoded)),
		MaximumLength: uint16(len(encoded)),
	}
	if len(encoded) > 0 {
		// Cast the first byte of the already-allocated encoded slice directly to
		// *uint16 instead of calling utf16StringFromBytes, which would create a
		// second []uint16 heap allocation holding the cleartext password with no
		// corresponding zeroBytes call. encoded is UTF-16LE so the byte layout is
		// identical to what *uint16 expects; the defer above zeros this memory.
		dataStr.Buffer = (*uint16)(unsafe.Pointer(&encoded[0]))
	}

	r0, _, _ := procLsaStorePrivateData.Call(
		uintptr(policy),
		uintptr(unsafe.Pointer(&keyStr)),
		uintptr(unsafe.Pointer(&dataStr)),
	)
	if r0 != 0 {
		return ntStatusError("LsaStorePrivateData", r0)
	}
	return nil
}

// lsaRetrievePrivateData retrieves the raw bytes stored under the named secret.
func lsaRetrievePrivateData(policy windows.Handle, name string) ([]byte, error) {
	keyStr := newLSAString(name)
	var outStr *lsaUnicodeString

	r0, _, _ := procLsaRetrievePrivateData.Call(
		uintptr(policy),
		uintptr(unsafe.Pointer(&keyStr)),
		uintptr(unsafe.Pointer(&outStr)),
	)
	if r0 != 0 {
		return nil, ntStatusError("LsaRetrievePrivateData", r0)
	}
	defer procLsaFreeMemory.Call(uintptr(unsafe.Pointer(outStr)))

	if outStr == nil || outStr.Length == 0 {
		return []byte{}, nil
	}
	// Copy the bytes out before freeing.
	raw := make([]byte, outStr.Length)
	src := unsafe.Slice((*byte)(unsafe.Pointer(outStr.Buffer)), outStr.Length)
	copy(raw, src)
	return raw, nil
}

// lsaClose closes a policy handle.
func lsaClose(handle windows.Handle) {
	procLsaClose.Call(uintptr(handle))
}

// ─── Conversion helpers ───────────────────────────────────────────────────────

// newLSAString converts a Go string to an LSA_UNICODE_STRING.
func newLSAString(s string) lsaUnicodeString {
	encoded := utf16.Encode([]rune(s))
	if len(encoded) == 0 {
		return lsaUnicodeString{}
	}
	byteLen := uint16(len(encoded) * 2)
	return lsaUnicodeString{
		Length:        byteLen,
		MaximumLength: byteLen,
		Buffer:        &encoded[0],
	}
}

// utf16LEBytes encodes a byte slice (treated as ASCII/UTF-8) into UTF-16LE.
func utf16LEBytes(b []byte) []byte {
	runes := []rune(string(b))
	chars := utf16.Encode(runes)
	result := make([]byte, len(chars)*2)
	for i, c := range chars {
		result[i*2] = byte(c)
		result[i*2+1] = byte(c >> 8)
	}
	return result
}

// utf16StringFromBytes reinterprets a byte slice as a []uint16 slice.
// The slice must have even length.
//
// Note: this is intentionally NOT used in lsaStorePrivateData. Calling it
// there would create a second heap allocation containing the cleartext password
// with no corresponding zeroBytes cleanup. lsaStorePrivateData instead casts
// the encoded []byte buffer pointer directly to *uint16.
func utf16StringFromBytes(b []byte) []uint16 {
	if len(b) == 0 {
		return nil
	}
	n := len(b) / 2
	result := make([]uint16, n)
	for i := 0; i < n; i++ {
		result[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}
	return result
}

// ntStatusError converts an NTSTATUS return value to a Go error.
func ntStatusError(fn string, status uintptr) error {
	r0, _, _ := procLsaNtStatusToWinError.Call(status)
	return fmt.Errorf("%s NTSTATUS=0x%08X WinError=%d", fn, status, r0)
}

// zeroBytes overwrites a byte slice with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
