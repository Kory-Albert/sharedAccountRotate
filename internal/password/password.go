// Package password generates secure passwords that satisfy
// Active Directory complexity rules. Minimum 24 characters and
// required character classes are included. Returned as []byte; caller
// should zero; never logged.
package password

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	minLength = 24

	upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	lower   = "abcdefghjkmnpqrstuvwxyz"
	digits  = "23456789"
	special = "!@#$%^&*()-_=+[]{}:,.<>?"
	all     = upper + lower + digits + special
)

// Generate returns a random password of the given length.
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

// Zero overwrites a password byte slice with zeros.
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
