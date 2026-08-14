package common

import (
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

	_, err := os.Stat(filepath.Join(SessionBaseDir, "user14_exchange4all.local.json"))
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
