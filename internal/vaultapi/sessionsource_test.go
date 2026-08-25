package vaultapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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

// refreshServer replies to POST /api/v1/users/refresh with a rotated pair,
// and records the refresh token it was sent.
func refreshServer(t *testing.T, newAccess, newRefresh string, expiresIn time.Duration) (*httptest.Server, *string) {
	t.Helper()
	var gotRefresh string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/users/refresh", r.URL.Path)

		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		gotRefresh = body.RefreshToken

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":%q,"refresh_token":%q,"user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"],"expires_at":%q}`,
			newAccess, newRefresh, time.Now().Add(expiresIn).Format(time.RFC3339Nano))
	}))
	return srv, &gotRefresh
}

func TestSessionSource_RefreshesExpiredToken(t *testing.T) {
	srv, sentRefresh := refreshServer(t, "access-new", "refresh-new", time.Hour)
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)} // already expired
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-new", tok)
	require.Equal(t, "refresh-original", *sentRefresh, "the cached refresh token is what gets sent")
}

func TestSessionSource_PersistsRotatedRefreshToken(t *testing.T) {
	srv, _ := refreshServer(t, "access-new", "refresh-ROTATED", time.Hour)
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	_, err := src.Token(context.Background())
	require.NoError(t, err)

	require.Len(t, store.saved, 1, "a refresh must persist the session")
	saved := store.saved[0]
	require.Equal(t, "access-new", saved.Token)
	require.Equal(t, "refresh-ROTATED", saved.RefreshToken,
		"the rotated refresh token must be persisted, or the next refresh fails with a stale token")
	require.Equal(t, "vault.example.com", saved.ServerKey, "the server key must survive a refresh")
	require.Equal(t, "admin", saved.Username)
}

func TestSessionSource_SecondRefreshUsesTheRotatedToken(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		seen = append(seen, body.RefreshToken)

		w.Header().Set("Content-Type", "application/json")
		// Always hand back an already-expired access token, so the next
		// Token call refreshes again.
		_, _ = fmt.Fprintf(w, `{"token":"access-%d","refresh_token":"refresh-%d","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"],"expires_at":%q}`,
			len(seen), len(seen), time.Now().Add(-time.Minute).Format(time.RFC3339Nano))
	}))
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	_, err := src.Token(context.Background())
	require.NoError(t, err)
	_, err = src.Token(context.Background())
	require.NoError(t, err)

	require.Equal(t, []string{"refresh-original", "refresh-1"}, seen,
		"the second refresh must use the token the first one returned")
}

func TestSessionSource_RefreshRejectionIsActionable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// api/users.go:496 calls SetPermissionError, so this is 403.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"token refresh failed"}`))
	}))
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	_, err := src.Token(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "rocketvault users login")
	require.NotContains(t, err.Error(), "refresh-original", "the refresh token must not appear in the error")
	require.Empty(t, store.saved, "a failed refresh must not persist anything")
}

func TestSessionSource_ConcurrentCallersShareOneRefresh(t *testing.T) {
	var calls int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"access-shared","refresh_token":"refresh-shared","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"],"expires_at":%q}`,
			time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	}))
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	const callers = 15
	results := make(chan string, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := src.Token(context.Background())
			require.NoError(t, err)
			results <- tok
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)

	for tok := range results {
		require.Equal(t, "access-shared", tok)
	}
	require.EqualValues(t, 1, atomic.LoadInt32(&calls),
		"concurrent callers must share one refresh, not stampede the endpoint")
}

func TestSessionSource_StaleRefreshTokenRecoversFromDisk(t *testing.T) {
	var seenTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		seenTokens = append(seenTokens, body.RefreshToken)

		if body.RefreshToken == "refresh-stale" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"access-fresh","refresh_token":"refresh-fresh-2","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"],"expires_at":%q}`,
			time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	}))
	defer srv.Close()

	stale := sessionFixture(-time.Minute)
	stale.RefreshToken = "refresh-stale"
	store := &stubStore{session: stale}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	// Simulate a newer `rocketvault users login` landing on disk, in a
	// different process, after src was constructed.
	fresh := sessionFixture(-time.Minute)
	fresh.RefreshToken = "refresh-fresh"
	store.session = fresh

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-fresh", tok)
	require.Equal(t, []string{"refresh-stale", "refresh-fresh"}, seenTokens,
		"the stale in-memory token is tried first, then the freshly loaded one")
}

func TestSessionSource_UnchangedDiskSessionDoesNotRetry(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	store := &stubStore{session: sessionFixture(-time.Minute)}
	src := newSessionSourceForTest(t, store, srv.URL, srv.Client())

	_, err := src.Token(context.Background())
	require.Error(t, err)
	require.Equal(t, 1, calls, "no newer session on disk means no retry, and no infinite loop")
}

func TestNewSessionSourceFromCache_SkipsDiskLoad(t *testing.T) {
	session := sessionFixture(time.Hour)
	src, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL:    "https://vault.example.com",
		HTTPClient: http.DefaultClient,
	}, session)
	require.NoError(t, err)

	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "access-original", tok)
}

func TestNewSessionSourceFromCache_RequiresSession(t *testing.T) {
	_, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL:    "https://vault.example.com",
		HTTPClient: http.DefaultClient,
	}, nil)
	require.ErrorContains(t, err, "requires a session")
}

func TestNewSessionSourceFromCache_SaveDefaultsToNoOp(t *testing.T) {
	srv, _ := refreshServer(t, "access-new", "refresh-new", time.Hour)
	defer srv.Close()

	src, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
	}, sessionFixture(-time.Minute))
	require.NoError(t, err)

	_, err = src.Token(context.Background())
	require.NoError(t, err, "a refresh must not fail merely because no SaveSession was supplied")
}

func TestNewSessionSourceFromCache_HonorsExplicitSaveSession(t *testing.T) {
	srv, _ := refreshServer(t, "access-new", "refresh-new", time.Hour)
	defer srv.Close()

	var saved *common.SessionCache
	src, err := NewSessionSourceFromCache(SessionConfig{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		SaveSession: func(sc *common.SessionCache) error { saved = sc; return nil },
	}, sessionFixture(-time.Minute))
	require.NoError(t, err)

	_, err = src.Token(context.Background())
	require.NoError(t, err)
	require.NotNil(t, saved, "an explicitly supplied SaveSession must still be honored")
}
