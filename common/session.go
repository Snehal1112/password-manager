package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// SessionBaseDir is the directory holding per-user CLI session cache files.
// Overridable in tests.
var SessionBaseDir = defaultSessionBaseDir()

func defaultSessionBaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".rocketvault", "sessions")
	}
	return filepath.Join(home, ".rocketvault", "sessions")
}

// SessionCache is the on-disk representation of a CLI-authenticated session.
type SessionCache struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       uuid.UUID `json:"user_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	ExpiresAt    time.Time `json:"expires_at"`
}

var usernameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// sanitizeUsername converts an arbitrary username into a safe filename
// component. Usernames in this codebase are typically emails
// (user14@exchange4all.local) or simple local names (admin) — both pass
// through unchanged; anything else is replaced with "_".
func sanitizeUsername(username string) string {
	return usernameSanitizer.ReplaceAllString(username, "_")
}

func sessionFilePath(username string) string {
	return filepath.Join(SessionBaseDir, sanitizeUsername(username)+".json")
}

func currentPointerPath() string {
	return filepath.Join(SessionBaseDir, "current")
}

// SaveSession writes session to disk and marks it as the current user —
// the one commands run without --username fall back to.
func SaveSession(session *SessionCache) error {
	if err := os.MkdirAll(SessionBaseDir, 0700); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if err := os.WriteFile(sessionFilePath(session.Username), data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	if err := os.WriteFile(currentPointerPath(), []byte(session.Username), 0600); err != nil {
		return fmt.Errorf("failed to update current-session pointer: %w", err)
	}

	return nil
}

// LoadSession loads a specific user's cached session. A missing file
// returns (nil, nil) — "no session" is not an error.
func LoadSession(username string) (*SessionCache, error) {
	data, err := os.ReadFile(sessionFilePath(username))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	var session SessionCache
	if err := json.Unmarshal(data, &session); err != nil {
		// A corrupt cache file is treated as "no session", not a hard error.
		return nil, nil
	}

	return &session, nil
}

// LoadCurrentSession loads whichever user's session the pointer file
// currently references. Returns (nil, nil) if there is no pointer or no
// matching session file.
func LoadCurrentSession() (*SessionCache, error) {
	data, err := os.ReadFile(currentPointerPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read current-session pointer: %w", err)
	}

	return LoadSession(string(data))
}

// DeleteSession removes username's cached session file. If username is the
// current pointer's target, the pointer is cleared too. Deleting a
// non-existent session is not an error.
func DeleteSession(username string) error {
	if err := os.Remove(sessionFilePath(username)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete session file: %w", err)
	}

	current, err := os.ReadFile(currentPointerPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read current-session pointer: %w", err)
	}
	if string(current) == username {
		if err := os.Remove(currentPointerPath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to clear current-session pointer: %w", err)
		}
	}

	return nil
}
