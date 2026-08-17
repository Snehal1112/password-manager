package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// LocalServerKey is the reserved server key representing local mode — no
// remote target resolved. Every session cached before remote-server support
// existed is implicitly a local-mode session.
const LocalServerKey = "local"

// SessionCache is the on-disk representation of a CLI-authenticated session.
type SessionCache struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       uuid.UUID `json:"user_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	ExpiresAt    time.Time `json:"expires_at"`
	// ServerKey identifies which server this session belongs to:
	// LocalServerKey for local mode, or SanitizeServerKey(serverURL) for a
	// remote target. Empty is treated as LocalServerKey.
	ServerKey string `json:"server_key,omitempty"`
}

var usernameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]`)
var serverKeySanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// sanitizeUsername converts an arbitrary username into a safe filename
// component. Usernames in this codebase are typically emails
// (user14@exchange4all.local) or simple local names (admin) — both pass
// through unchanged; anything else is replaced with "_".
func sanitizeUsername(username string) string {
	return usernameSanitizer.ReplaceAllString(username, "_")
}

// SanitizeServerKey converts a server URL into a safe filename component:
// the scheme is stripped, the result is lowercased, and anything unsafe in
// a filename becomes "_". LocalServerKey and "" both pass through as
// LocalServerKey.
func SanitizeServerKey(server string) string {
	if server == "" || server == LocalServerKey {
		return LocalServerKey
	}
	s := strings.TrimPrefix(server, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.ToLower(s)
	return serverKeySanitizer.ReplaceAllString(s, "_")
}

func sessionFilePath(serverKey, username string) string {
	return filepath.Join(SessionBaseDir, serverKey+"__"+sanitizeUsername(username)+".json")
}

// legacySessionFilePath is the pre-remote-mode filename format: username
// only, implicitly local mode. Only ever read, never written, going forward.
func legacySessionFilePath(username string) string {
	return filepath.Join(SessionBaseDir, sanitizeUsername(username)+".json")
}

func currentPointerPath() string {
	return filepath.Join(SessionBaseDir, "current")
}

// writeSessionFile writes session's JSON to its (serverKey, username)-derived
// path. Does not touch the current-session pointer — callers that should
// also update "current" (SaveSession) do that themselves; callers that
// shouldn't (the lazy-migration path, which is a read-triggered rewrite, not
// a real session change) must not.
func writeSessionFile(session *SessionCache) error {
	if session.ServerKey == "" {
		session.ServerKey = LocalServerKey
	}

	if err := os.MkdirAll(SessionBaseDir, 0700); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if err := os.WriteFile(sessionFilePath(session.ServerKey, session.Username), data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	return nil
}

// SaveSession writes session to disk and marks it as the current session —
// the one commands run without --username fall back to. A blank
// session.ServerKey is treated as LocalServerKey.
func SaveSession(session *SessionCache) error {
	if err := writeSessionFile(session); err != nil {
		return err
	}

	pointer := session.ServerKey + "|" + session.Username
	if err := os.WriteFile(currentPointerPath(), []byte(pointer), 0600); err != nil {
		return fmt.Errorf("failed to update current-session pointer: %w", err)
	}

	return nil
}

// LoadSession loads username's cached local-mode session — equivalent to
// LoadSessionForServer(LocalServerKey, username). Unaffected by remote-mode
// support.
func LoadSession(username string) (*SessionCache, error) {
	return LoadSessionForServer(LocalServerKey, username)
}

// LoadSessionForServer loads a specific (serverKey, username) session. A
// missing file returns (nil, nil) — "no session" is not an error. For
// serverKey == LocalServerKey, falls back to the pre-remote-mode filename
// format if the new-format file doesn't exist, and lazily rewrites it in the
// new format so the fallback is only ever needed once.
func LoadSessionForServer(serverKey, username string) (*SessionCache, error) {
	if serverKey == "" {
		serverKey = LocalServerKey
	}

	data, err := os.ReadFile(sessionFilePath(serverKey, username))
	if os.IsNotExist(err) && serverKey == LocalServerKey {
		data, err = os.ReadFile(legacySessionFilePath(username))
	}
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
	if session.ServerKey == "" {
		session.ServerKey = LocalServerKey
	}

	// Lazily migrate: rewrite under the new filename so the legacy fallback
	// above is only ever needed once per user. Use writeSessionFile (not SaveSession)
	// because this is a read-triggered rewrite, not a real session change, and must
	// not affect the current-session pointer.
	if session.ServerKey == LocalServerKey {
		if _, newErr := os.Stat(sessionFilePath(LocalServerKey, username)); os.IsNotExist(newErr) {
			_ = writeSessionFile(&session)
		}
	}

	return &session, nil
}

// LoadCurrentSession loads whichever session the pointer file currently
// references. Returns (nil, nil) if there is no pointer or no matching
// session file. Handles both the new "serverKey|username" pointer format and
// the pre-remote-mode bare-username format.
func LoadCurrentSession() (*SessionCache, error) {
	data, err := os.ReadFile(currentPointerPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read current-session pointer: %w", err)
	}

	serverKey, username := LocalServerKey, string(data)
	if parts := strings.SplitN(string(data), "|", 2); len(parts) == 2 {
		serverKey, username = parts[0], parts[1]
	}

	return LoadSessionForServer(serverKey, username)
}

// DeleteSession removes username's cached local-mode session — equivalent
// to DeleteSessionForServer(LocalServerKey, username). Unaffected by
// remote-mode support.
func DeleteSession(username string) error {
	return DeleteSessionForServer(LocalServerKey, username)
}

// DeleteSessionForServer removes the (serverKey, username) session file,
// including the legacy-format file when serverKey is LocalServerKey. If it
// was the current pointer's target, the pointer is cleared too. Deleting a
// non-existent session is not an error.
func DeleteSessionForServer(serverKey, username string) error {
	if serverKey == "" {
		serverKey = LocalServerKey
	}

	if err := os.Remove(sessionFilePath(serverKey, username)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete session file: %w", err)
	}
	if serverKey == LocalServerKey {
		if err := os.Remove(legacySessionFilePath(username)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete legacy session file: %w", err)
		}
	}

	current, err := os.ReadFile(currentPointerPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read current-session pointer: %w", err)
	}

	currentServerKey, currentUsername := LocalServerKey, string(current)
	if parts := strings.SplitN(string(current), "|", 2); len(parts) == 2 {
		currentServerKey, currentUsername = parts[0], parts[1]
	}

	if currentServerKey == serverKey && currentUsername == username {
		if err := os.Remove(currentPointerPath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to clear current-session pointer: %w", err)
		}
	}

	return nil
}
