// Package state manages the persistent state file that records when the last
// successful password rotation occurred.
//
// The file is written atomically (write to a temp file, then rename) to avoid
// corruption if the service is killed mid-write.
//
// Location: C:\Program Files\sharedAccountRotate\sharedAccountRotate_state.json
// Permissions: created 0600 (owner-read/write only, enforced via Windows ACL
// when possible). The file contains no secrets – only the timestamp.
//
// OutOfSync flag: if the LSA write succeeds but the AD write subsequently fails
// hard (all retries exhausted), the state file is written with OutOfSync=true.
// The service will refuse to rotate again until an operator clears the flag,
// preventing a second rotation that would produce yet another mismatched pair.

package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const defaultStateDir = `C:\Program Files\sharedAccountRotate`
const defaultStatePath = defaultStateDir + `\sharedAccountRotate_state.json`

// State holds the persisted rotation history.
type State struct {
	LastRotation  time.Time `json:"last_rotation"`  // UTC timestamp of last successful rotation
	RotationCount int       `json:"rotation_count"` // total successful rotations (informational)

	// OutOfSync is set to true when the LSA write succeeded but the AD write
	// failed after all retries. In this state the local LSA secret holds a
	// password that does not match Active Directory, making auto-logon
	// impossible. The service will refuse further rotations until an operator
	// manually resolves the mismatch and clears this flag (set to false and
	// save the file, or delete the state file entirely to reset).
	OutOfSync bool `json:"out_of_sync,omitempty"`
}

// Manager reads and writes the state file.
type Manager struct {
	path string
}

// New returns a Manager using the default state file path.
func New() *Manager {
	return &Manager{path: defaultStatePath}
}

// Load reads the state file, returning a zero-value State if the file does not
// exist (first run).
func (m *Manager) Load() (*State, error) {
	data, err := os.ReadFile(m.path)
	if os.IsNotExist(err) {
		// First run – return a zero state (rotation is overdue immediately).
		return &State{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state load %s: %w", m.path, err)
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("state parse %s: %w", m.path, err)
	}
	return &s, nil
}

// Save writes the state atomically to disk.
func (m *Manager) Save(s *State) error {
	// Ensure the state directory exists
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("state create directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("state marshal: %w", err)
	}

	// Write to a sibling temp file then rename for atomicity.
	tmp, err := os.CreateTemp(dir, "sharedAccountRotate_state_*.tmp")
	if err != nil {
		return fmt.Errorf("state temp create: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("state write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("state close: %w", err)
	}
	if err := os.Rename(tmpName, m.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("state rename: %w", err)
	}
	return nil
}

// IsDue returns true if it is time to rotate based on the last rotation
// timestamp and the configured interval in days. In dev mode it always returns
// true. Returns false (with a non-nil error) when the state is out of sync —
// the caller must surface the error and halt until an operator intervenes.
func (m *Manager) IsDue(s *State, intervalDays int, devMode bool) (bool, error) {
	if s.OutOfSync {
		return false, fmt.Errorf(
			"state is OUT OF SYNC: LSA and AD passwords do not match – " +
				"resolve the mismatch manually then set out_of_sync=false in %s " +
				"(or delete the file) before rotations will resume",
			m.path,
		)
	}
	if devMode {
		return true, nil
	}
	if s.LastRotation.IsZero() {
		return true, nil // never rotated
	}
	next := s.LastRotation.AddDate(0, 0, intervalDays)
	return time.Now().UTC().After(next), nil
}

// MarkSuccess records a successful rotation and clears any out-of-sync flag.
func (m *Manager) MarkSuccess(s *State) {
	s.LastRotation = time.Now().UTC()
	s.RotationCount++
	s.OutOfSync = false
}

// MarkOutOfSync records that LSA was updated but AD could not be updated.
// The service will refuse further rotations until this is manually cleared.
func (m *Manager) MarkOutOfSync(s *State) {
	s.OutOfSync = true
}