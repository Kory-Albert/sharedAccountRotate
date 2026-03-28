// Package password generates cryptographically random passwords that satisfy
// typical Active Directory complexity requirements:
//
//   - Minimum 24 characters
//   - At least one uppercase letter
//   - At least one lowercase letter
//   - At least one digit
//   - At least one special character from a safe subset
//   - No characters that are ambiguous in LDAP strings or Windows registry
//     values (NUL, DEL, single/double quotes are excluded)
//
// Passwords are returned as a []byte so the caller can zero the memory after
// use. They are NEVER logged.

package password

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	minLength = 24

	// Character classes – carefully chosen to avoid characters that break
	// LDAP distinguished names, registry strings, or command-line quoting.
	upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"        // no I, O (ambiguous visually)
	lower   = "abcdefghjkmnpqrstuvwxyz"          // no i, l, o (ambiguous)
	digits  = "23456789"                          // no 0, 1 (ambiguous)
	special = "!@#$%^&*()-_=+[]{}|;:,.<>?"       // no quotes, backtick, slash
	all     = upper + lower + digits + special
)

// Generate returns a random password of the given length (minimum 24).
// The returned slice should be zeroed by the caller when no longer needed:
//
//	defer zero(pw)
func Generate(length int) ([]byte, error) {
	if length < minLength {
		length = minLength
	}

	pw := make([]byte, length)

	// ── Guarantee at least one character from each required class ─────────────
	required := []string{upper, lower, digits, special}
	for i, class := range required {
		c, err := randomFrom(class)
		if err != nil {
			return nil, err
		}
		pw[i] = c
	}

	// ── Fill the rest from the full alphabet ──────────────────────────────────
	for i := len(required); i < length; i++ {
		c, err := randomFrom(all)
		if err != nil {
			return nil, err
		}
		pw[i] = c
	}

	// ── Fisher-Yates shuffle to remove the predictable class ordering ─────────
	if err := shuffle(pw); err != nil {
		return nil, err
	}

	return pw, nil
}

// Zero overwrites a password byte slice with zeros. Call this as a deferred
// cleanup after the password has been consumed.
func Zero(pw []byte) {
	for i := range pw {
		pw[i] = 0
	}
}

// randomFrom returns a cryptographically random byte from the given alphabet.
func randomFrom(alphabet string) (byte, error) {
	if len(alphabet) == 0 {
		return 0, errors.New("password: empty alphabet")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
	if err != nil {
		return 0, err
	}
	return alphabet[n.Int64()], nil
}

// shuffle performs a Fisher-Yates shuffle on b using crypto/rand for index
// selection. This ensures no statistical bias in character position.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := n.Int64()
		b[i], b[j] = b[j], b[i]
	}
	return nil
}
