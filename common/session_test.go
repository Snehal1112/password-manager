package common

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoadSession_RoundTrip(t *testing.T) {
	SessionBaseDir = t.TempDir()

	session := &SessionCache{
		Token:        "access-tok",
		RefreshToken: "refresh-tok",
		UserID:       uuid.New(),
		Username:     "user14@exchange4all.local",
		Role:         "user",
		ExpiresAt:    time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second),
	}

	require.NoError(t, SaveSession(session))

	loaded, err := LoadSession("user14@exchange4all.local")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, session.Token, loaded.Token)
	assert.Equal(t, session.RefreshToken, loaded.RefreshToken)
	assert.Equal(t, session.UserID, loaded.UserID)
	assert.Equal(t, session.Username, loaded.Username)
	assert.Equal(t, session.Role, loaded.Role)
	assert.True(t, session.ExpiresAt.Equal(loaded.ExpiresAt))
}

func TestSaveSession_SanitizesFilename(t *testing.T) {
	SessionBaseDir = t.TempDir()

	require.NoError(t, SaveSession(&SessionCache{Username: "user14@exchange4all.local", Token: "t"}))

	_, err := os.Stat(filepath.Join(SessionBaseDir, LocalServerKey+"__user14_exchange4all.local.json"))
	assert.NoError(t, err)
}

func TestLoadSession_MissingFile_ReturnsNilNoError(t *testing.T) {
	SessionBaseDir = t.TempDir()

	loaded, err := LoadSession("nobody")
	assert.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestLoadSession_CorruptFile_ReturnsNilNoError(t *testing.T) {
	SessionBaseDir = t.TempDir()
	require.NoError(t, os.MkdirAll(SessionBaseDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(SessionBaseDir, "admin.json"), []byte("not json"), 0600))

	loaded, err := LoadSession("admin")
	assert.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestLoadCurrentSession_FollowsPointer(t *testing.T) {
	SessionBaseDir = t.TempDir()

	require.NoError(t, SaveSession(&SessionCache{Username: "admin", Token: "admin-tok"}))

	loaded, err := LoadCurrentSession()
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "admin", loaded.Username)
}

func TestLoadCurrentSession_NoPointer_ReturnsNilNoError(t *testing.T) {
	SessionBaseDir = t.TempDir()

	loaded, err := LoadCurrentSession()
	assert.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestSaveSession_SecondUserDoesNotOverwriteFirst(t *testing.T) {
	SessionBaseDir = t.TempDir()

	require.NoError(t, SaveSession(&SessionCache{Username: "admin", Token: "admin-tok"}))
	require.NoError(t, SaveSession(&SessionCache{Username: "user14@exchange4all.local", Token: "oidc-tok"}))

	adminSession, err := LoadSession("admin")
	require.NoError(t, err)
	require.NotNil(t, adminSession)
	assert.Equal(t, "admin-tok", adminSession.Token)

	oidcSession, err := LoadSession("user14@exchange4all.local")
	require.NoError(t, err)
	require.NotNil(t, oidcSession)
	assert.Equal(t, "oidc-tok", oidcSession.Token)

	current, err := LoadCurrentSession()
	require.NoError(t, err)
	assert.Equal(t, "user14@exchange4all.local", current.Username)
}

func TestDeleteSession_RemovesFileAndClearsPointerIfCurrent(t *testing.T) {
	SessionBaseDir = t.TempDir()
	require.NoError(t, SaveSession(&SessionCache{Username: "admin", Token: "admin-tok"}))

	require.NoError(t, DeleteSession("admin"))

	loaded, err := LoadSession("admin")
	require.NoError(t, err)
	assert.Nil(t, loaded)

	current, err := LoadCurrentSession()
	require.NoError(t, err)
	assert.Nil(t, current)
}

func TestDeleteSession_NonCurrentUser_LeavesPointerAlone(t *testing.T) {
	SessionBaseDir = t.TempDir()
	require.NoError(t, SaveSession(&SessionCache{Username: "admin", Token: "admin-tok"}))
	require.NoError(t, SaveSession(&SessionCache{Username: "user14", Token: "oidc-tok"}))

	require.NoError(t, DeleteSession("admin"))

	current, err := LoadCurrentSession()
	require.NoError(t, err)
	require.NotNil(t, current)
	assert.Equal(t, "user14", current.Username)
}

func TestDeleteSession_NonExistent_NoError(t *testing.T) {
	SessionBaseDir = t.TempDir()
	assert.NoError(t, DeleteSession("nobody"))
}

func TestSanitizeServerKey(t *testing.T) {
	cases := map[string]string{
		"":                                          LocalServerKey,
		LocalServerKey:                               LocalServerKey,
		"https://vault.prod.example.com":             "vault.prod.example.com",
		"https://vault.prod.example.com:8443":        "vault.prod.example.com_8443",
		"http://localhost:8774":                      "localhost_8774",
	}
	for in, want := range cases {
		if got := SanitizeServerKey(in); got != want {
			t.Errorf("SanitizeServerKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadSessionForServer_DifferentServers_DoNotCollide(t *testing.T) {
	SessionBaseDir = t.TempDir()

	prod := &SessionCache{Username: "admin", Token: "prod-token", ServerKey: SanitizeServerKey("https://vault.prod.example.com")}
	staging := &SessionCache{Username: "admin", Token: "staging-token", ServerKey: SanitizeServerKey("https://vault.staging.example.com")}

	if err := SaveSession(prod); err != nil {
		t.Fatalf("SaveSession(prod): %v", err)
	}
	if err := SaveSession(staging); err != nil {
		t.Fatalf("SaveSession(staging): %v", err)
	}

	gotProd, err := LoadSessionForServer(SanitizeServerKey("https://vault.prod.example.com"), "admin")
	if err != nil || gotProd == nil || gotProd.Token != "prod-token" {
		t.Fatalf("LoadSessionForServer(prod) = %+v, %v; want token prod-token", gotProd, err)
	}
	gotStaging, err := LoadSessionForServer(SanitizeServerKey("https://vault.staging.example.com"), "admin")
	if err != nil || gotStaging == nil || gotStaging.Token != "staging-token" {
		t.Fatalf("LoadSessionForServer(staging) = %+v, %v; want token staging-token", gotStaging, err)
	}
}

func TestLoadSession_FallsBackToLegacyFormat_AndMigrates(t *testing.T) {
	SessionBaseDir = t.TempDir()
	os.MkdirAll(SessionBaseDir, 0700)

	// Simulate a pre-remote-mode session file: bare "<username>.json", no
	// server key at all.
	legacy := &SessionCache{Username: "admin", Token: "legacy-token"}
	data, _ := json.Marshal(legacy)
	os.WriteFile(filepath.Join(SessionBaseDir, "admin.json"), data, 0600)

	got, err := LoadSession("admin")
	if err != nil || got == nil || got.Token != "legacy-token" {
		t.Fatalf("LoadSession(admin) = %+v, %v; want fallback to legacy-token", got, err)
	}

	// It should have migrated: the new-format file now exists too.
	if _, err := os.Stat(filepath.Join(SessionBaseDir, LocalServerKey+"__admin.json")); err != nil {
		t.Fatalf("expected new-format file to exist after migration: %v", err)
	}
}

func TestLoadCurrentSession_ParsesLegacyAndNewPointerFormats(t *testing.T) {
	SessionBaseDir = t.TempDir()
	os.MkdirAll(SessionBaseDir, 0700)

	remote := &SessionCache{Username: "admin", Token: "remote-token", ServerKey: "vault.prod.example.com"}
	if err := SaveSession(remote); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	got, err := LoadCurrentSession()
	if err != nil || got == nil || got.Token != "remote-token" {
		t.Fatalf("LoadCurrentSession() = %+v, %v; want remote-token", got, err)
	}

	// Legacy pointer format: bare username, no "|".
	os.WriteFile(filepath.Join(SessionBaseDir, "current"), []byte("admin"), 0600)
	legacySession := &SessionCache{Username: "admin", Token: "legacy-current-token"}
	data, _ := json.Marshal(legacySession)
	os.WriteFile(filepath.Join(SessionBaseDir, "admin.json"), data, 0600)

	got2, err := LoadCurrentSession()
	if err != nil || got2 == nil || got2.Token != "legacy-current-token" {
		t.Fatalf("LoadCurrentSession() legacy pointer = %+v, %v; want legacy-current-token", got2, err)
	}
}

func TestDeleteSessionForServer_ClearsCurrentPointerOnlyForMatchingServer(t *testing.T) {
	SessionBaseDir = t.TempDir()

	prodKey := SanitizeServerKey("https://vault.prod.example.com")
	if err := SaveSession(&SessionCache{Username: "admin", Token: "t", ServerKey: prodKey}); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	if err := DeleteSessionForServer(prodKey, "admin"); err != nil {
		t.Fatalf("DeleteSessionForServer: %v", err)
	}

	if s, err := LoadCurrentSession(); err != nil || s != nil {
		t.Fatalf("LoadCurrentSession() after delete = %+v, %v; want nil, nil", s, err)
	}
}

func TestLoadSession_Migration_DoesNotClobberCurrentPointer(t *testing.T) {
	SessionBaseDir = t.TempDir()
	os.MkdirAll(SessionBaseDir, 0700)

	// Scenario: User A is current (new format), User B has a legacy-format session.
	// When we load B's legacy session for a one-off --username lookup, it should
	// not change who the "current" pointer references.

	// Save user A's session (in new format) and mark as current.
	userA := &SessionCache{Username: "userA", Token: "token-a", ServerKey: LocalServerKey}
	if err := SaveSession(userA); err != nil {
		t.Fatalf("SaveSession(userA): %v", err)
	}

	// Verify userA is current.
	current, err := LoadCurrentSession()
	if err != nil || current == nil || current.Username != "userA" {
		t.Fatalf("LoadCurrentSession() initial = %+v, %v; want userA", current, err)
	}

	// Create user B's legacy-format session (old filename, no server key).
	userB := &SessionCache{Username: "userB", Token: "token-b"}
	data, _ := json.Marshal(userB)
	os.WriteFile(filepath.Join(SessionBaseDir, "userB.json"), data, 0600)

	// Load userB's legacy session (simulates --username userB lookup).
	loaded, err := LoadSession("userB")
	if err != nil || loaded == nil || loaded.Token != "token-b" {
		t.Fatalf("LoadSession(userB) = %+v, %v; want token-b", loaded, err)
	}

	// CRITICAL: Verify the current pointer still points to userA, not userB.
	// (Before the fix, SaveSession's side effect during migration would clobber
	// the pointer, causing this to fail.)
	current2, err := LoadCurrentSession()
	if err != nil || current2 == nil || current2.Username != "userA" || current2.Token != "token-a" {
		t.Fatalf("LoadCurrentSession() after userB migration = %+v, %v; want userA/token-a (pointer must not be clobbered)", current2, err)
	}
}
