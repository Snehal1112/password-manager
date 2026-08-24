package vaultapi

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

// sessionFixture returns a session whose access token expires at the given
// offset from now.
func sessionFixture(expiresIn time.Duration) *common.SessionCache {
	return &common.SessionCache{
		Token:        "access-original",
		RefreshToken: "refresh-original",
		UserID:       uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Username:     "admin",
		Roles:        []string{"admin"},
		ExpiresAt:    time.Now().Add(expiresIn),
		ServerKey:    "vault.example.com",
	}
}

// stubStore is an in-memory stand-in for the on-disk session cache, so no
// test touches the real ~/.rocketvault directory.
type stubStore struct {
	session *common.SessionCache
	saved   []*common.SessionCache
	loadErr error
}

func (s *stubStore) load() (*common.SessionCache, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return s.session, nil
}

func (s *stubStore) save(sc *common.SessionCache) error {
	copied := *sc
	s.saved = append(s.saved, &copied)
	s.session = &copied
	return nil
}

func newSessionSourceForTest(t *testing.T, store *stubStore, baseURL string, client *http.Client) *SessionSource {
	t.Helper()
	src, err := NewSessionSource(SessionConfig{
		BaseURL:     baseURL,
		HTTPClient:  client,
		LoadSession: store.load,
		SaveSession: store.save,
	})
	require.NoError(t, err)
	return src
}

func TestSessionSource_ServesLiveCachedToken(t *testing.T) {
	store := &stubStore{session: sessionFixture(time.Hour)}
	src := newSessionSourceForTest(t, store, "https://vault.example.com", http.DefaultClient)

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-original", tok)
	require.Empty(t, store.saved, "a live token must not trigger a save")
}

func TestSessionSource_ExposesUsername(t *testing.T) {
	store := &stubStore{session: sessionFixture(time.Hour)}
	src := newSessionSourceForTest(t, store, "https://vault.example.com", http.DefaultClient)
	require.Equal(t, "admin", src.Username())
}

func TestSessionSource_NoCachedSessionIsErrNoSession(t *testing.T) {
	// common.LoadCurrentSession returns (nil, nil) when nothing is cached.
	store := &stubStore{session: nil}
	_, err := NewSessionSource(SessionConfig{
		BaseURL:     "https://vault.example.com",
		HTTPClient:  http.DefaultClient,
		LoadSession: store.load,
		SaveSession: store.save,
	})
	require.ErrorIs(t, err, ErrNoSession)
}

func TestSessionSource_LoaderErrorPropagates(t *testing.T) {
	store := &stubStore{loadErr: errors.New("permission denied reading pointer")}
	_, err := NewSessionSource(SessionConfig{
		BaseURL:     "https://vault.example.com",
		HTTPClient:  http.DefaultClient,
		LoadSession: store.load,
		SaveSession: store.save,
	})
	require.ErrorContains(t, err, "permission denied reading pointer")
	require.NotErrorIs(t, err, ErrNoSession, "a real read failure is not the same as no session")
}

func TestSessionSource_RequiresBaseURLAndHTTPClient(t *testing.T) {
	store := &stubStore{session: sessionFixture(time.Hour)}

	_, err := NewSessionSource(SessionConfig{HTTPClient: http.DefaultClient, LoadSession: store.load, SaveSession: store.save})
	require.ErrorContains(t, err, "BaseURL")

	_, err = NewSessionSource(SessionConfig{BaseURL: "https://v", LoadSession: store.load, SaveSession: store.save})
	require.ErrorContains(t, err, "HTTPClient")
}

func TestSessionSource_SatisfiesTokenSource(t *testing.T) {
	var _ TokenSource = (*SessionSource)(nil)
}
