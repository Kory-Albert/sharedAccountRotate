// Package ad handles all Active Directory operations using pure Go LDAP over
// TLS (LDAPS port 636). No PowerShell is invoked.
//
// Authentication: The service runs as SYSTEM. GSSAPIBind with SSPI client
// uses the machine account process token for authentication.
// The machine account must have delegated "Reset Password" on the target user.
//
// LDAP library: github.com/go-ldap/ldap/v3
// GSSAPI package: github.com/go-ldap/ldap/v3/gssapi

//go:build windows

package ad

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"

	"github.com/Kory-Albert/sharedAccountRotate/internal/logger"
)

// Client wraps an LDAP connection to Active Directory.
type Client struct {
	log    *logger.Logger
	domain string
	server string
	port   int
	baseDN string
}

// New creates an AD client (lazy-connect).
func New(log *logger.Logger, domain, server string, port int) *Client {
	return &Client{
		log:    log,
		domain: domain,
		server: server,
		port:   port,
		baseDN: domainToBaseDN(domain),
	}
}

// SetPassword changes the unicodePwd attribute of the named user in AD.
// The password slice must be zeroed by the caller after this returns.
// Requires the machine account to have "Reset Password" delegated on the user.
func (c *Client) SetPassword(username string, newPassword []byte) error {
	c.log.Infof("AD: connecting to %s:%d", c.server, c.port)

	conn, err := c.connect()
	if err != nil {
		c.log.Errorf("AD: connection failed: %v", err)
		return fmt.Errorf("AD connect: %w", err)
	}
	defer func() {
		conn.Close()
		c.log.Info("AD: connection closed")
	}()

	// ── GSSAPI/SSPI bind using machine account process token ──────────────────
	// GSSAPIBind with an SSPI client uses Windows integrated authentication.
	// When running as SYSTEM, this authenticates as the machine account (HOSTNAME$).
	// The SPN format is "ldap/hostname" (e.g., "ldap/tfhd-dc1.tfhd.ad").
	c.log.Info("AD: binding with GSSAPI/SSPI (machine account credential)")

	sspiClient, err := gssapi.NewSSPIClient()
	if err != nil {
		c.log.Errorf("AD: failed to create SSPI client: %v", err)
		return fmt.Errorf("AD SSPI client creation: %w", err)
	}
	defer sspiClient.Close()

	// SPN format: ldap/hostname (must match the DC's host name for Kerberos)
	spn := "ldap/" + c.server
	c.log.Debugf("AD: GSSAPI bind with SPN=%q", spn)

	if err := conn.GSSAPIBind(sspiClient, spn, ""); err != nil {
		c.log.Errorf("AD: GSSAPI bind failed: %v", err)
		c.log.Error("AD: Troubleshooting checklist:")
		c.log.Error("  1. Verify service is running as SYSTEM (required for machine account auth)")
		c.log.Error("  2. Verify machine account can reach DC on port 636 (telnet <dc> 636)")
		c.log.Error("  3. Verify machine account has 'Reset Password' delegated on target user")
		c.log.Error("  4. Check DC event logs for authentication failures from this machine")
		return fmt.Errorf("AD GSSAPI bind: %w – ensure machine account has delegated Reset Password on the user object and can reach DC on port %d", err, c.port)
	}
	c.log.Info("AD: GSSAPI/SSPI bind successful")

	// ── Find user DN ──────────────────────────────────────────────────────────
	c.log.Infof("AD: searching for user %q in %s", username, c.baseDN)
	dn, err := c.findUserDN(conn, username)
	if err != nil {
		return fmt.Errorf("AD find user: %w", err)
	}
	c.log.Infof("AD: found user DN: %s", dn)

	// ── Encode password as UTF-16LE wrapped in double quotes (AD requirement) ─
	encoded, err := encodePassword(newPassword)
	if err != nil {
		return fmt.Errorf("AD encode password: %w", err)
	}
	defer zeroBytes(encoded)

	// Log password length and character class counts (not the password itself)
	upperCount, lowerCount, digitCount, specialCount := countCharClasses(newPassword)
	c.log.Debugf("AD: password length=%d (upper=%d lower=%d digit=%d special=%d), encoded=%d bytes",
		len(newPassword), upperCount, lowerCount, digitCount, specialCount, len(encoded))

	if len(encoded) == 0 {
		c.log.Error("AD: ERROR - encoded password is empty!")
		return fmt.Errorf("AD modify unicodePwd: encoded password is empty")
	}

	// ── Modify unicodePwd ─────────────────────────────────────────────────────
	// When the caller holds "Reset Password" (not "Change Password"), AD expects
	// a Replace operation rather than Delete+Add. Delete+Add is for self-changes
	// where the old password must be supplied in the Delete value. With delegated
	// Reset Password rights, Replace atomically overwrites unicodePwd regardless
	// of the current value — no knowledge of the old password required.
	//
	// unicodePwd is a binary attribute. Go strings are byte sequences (not
	// UTF-8 encoded on assignment), so string(encoded) preserves the raw
	// UTF-16LE bytes exactly as-is when go-ldap writes them onto the wire.
	c.log.Info("AD: sending unicodePwd replace request")
	modReq := ldap.NewModifyRequest(dn, nil)
	modReq.Replace("unicodePwd", []string{string(encoded)})

	c.log.Debugf("AD: encoded password length for LDAP: %d", len(encoded))
	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("AD modify unicodePwd: %w", err)
	}

	c.log.Info("AD: password updated successfully in Active Directory")
	return nil
}

// VerifyPasswordChange confirms the AD password update by test-binding with
// the new credentials. The password is used in-memory only and never logged.
func (c *Client) VerifyPasswordChange(username string, newPassword []byte) error {
	c.log.Info("AD: verifying password change by test-bind")

	conn, err := c.connect()
	if err != nil {
		return fmt.Errorf("AD verify connect: %w", err)
	}
	defer conn.Close()

	upn := username + "@" + c.domain
	if err := conn.Bind(upn, string(newPassword)); err != nil {
		return fmt.Errorf("AD verify bind failed – password may not have replicated yet: %w", err)
	}

	c.log.Info("AD: password verification bind succeeded")
	return nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func (c *Client) connect() (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", c.server, c.port)
	tlsCfg := &tls.Config{
		ServerName: c.server,
		MinVersion: tls.VersionTLS12,
	}
	conn, err := ldap.DialTLS("tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("LDAPS dial %s: %w", addr, err)
	}
	return conn, nil
}

func (c *Client) findUserDN(conn *ldap.Conn, username string) (string, error) {
	filter := fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))",
		ldap.EscapeFilter(username))

	req := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2, 30, false,
		filter,
		[]string{"distinguishedName"},
		nil,
	)

	result, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("LDAP search: %w", err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("user %q not found in %s", username, c.baseDN)
	}
	if len(result.Entries) > 1 {
		return "", fmt.Errorf("ambiguous: %d entries matched user %q", len(result.Entries), username)
	}
	return result.Entries[0].DN, nil
}

// encodePassword returns UTF-16LE( '"' + password + '"' ) as required by AD.
func encodePassword(pw []byte) ([]byte, error) {
	quoted := make([]byte, 0, len(pw)+2)
	quoted = append(quoted, '"')
	quoted = append(quoted, pw...)
	quoted = append(quoted, '"')

	runes := []rune(string(quoted))
	utf16Chars := utf16.Encode(runes)
	buf := make([]byte, len(utf16Chars)*2)
	for i, ch := range utf16Chars {
		binary.LittleEndian.PutUint16(buf[i*2:], ch)
	}

	return buf, nil
}

// domainToBaseDN converts "corp.example.com" to "DC=corp,DC=example,DC=com".
func domainToBaseDN(domain string) string {
	result := ""
	part := ""
	for _, ch := range domain + "." {
		if ch == '.' {
			if part != "" {
				if result != "" {
					result += ","
				}
				result += "DC=" + part
			}
			part = ""
		} else {
			part += string(ch)
		}
	}
	return result
}

// zeroBytes overwrites a byte slice with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// countCharClasses counts characters in each class for debug logging.
func countCharClasses(pw []byte) (upper, lower, digit, special int) {
	for _, c := range pw {
		switch {
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lower++
		case c >= '0' && c <= '9':
			digit++
		default:
			special++
		}
	}
	return
}
