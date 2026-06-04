package bootstrap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/bootstrap"
	"rocketvault/internal/vaultclient"
)

// mockFetcher satisfies vaultclient.Fetcher for testing.
type mockFetcher struct {
	results map[string]string
	err     error
}

func (m *mockFetcher) GetMany(_ context.Context, names []string) (map[string]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		if v, ok := m.results[n]; ok {
			out[n] = v
		}
	}
	return out, nil
}

// ----- NewSecretsInitializer -----

func TestSecretsInitializer_InjectsIntoViper(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
	})

	mock := &mockFetcher{results: map[string]string{
		"JWT_SECRET":  "jwt-value",
		"DB_PASSWORD": "db-value",
	}}

	init := bootstrap.NewSecretsInitializer(mock, map[string]string{
		"JWT_SECRET":  "jwt_secret",
		"DB_PASSWORD": "database.password",
	})
	err := init.Initialize(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "jwt-value", viper.GetString("jwt_secret"))
	assert.Equal(t, "db-value", viper.GetString("database.password"))
}

func TestSecretsInitializer_PropagatesError(t *testing.T) {
	t.Cleanup(func() { viper.Reset() })

	mock := &mockFetcher{err: errors.New("network failure")}
	init := bootstrap.NewSecretsInitializer(mock, map[string]string{"JWT_SECRET": "jwt_secret"})
	err := init.Initialize(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "secrets initializer")
}

func TestSecretsInitializer_ErrAuthFailed_IsUnwrappable(t *testing.T) {
	t.Cleanup(func() { viper.Reset() })

	mock := &mockFetcher{err: vaultclient.ErrAuthFailed}
	init := bootstrap.NewSecretsInitializer(mock, map[string]string{"JWT_SECRET": "jwt_secret"})
	err := init.Initialize(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, vaultclient.ErrAuthFailed)
}

// ----- NewSecretsInitializerFromMappings -----

func TestNewSecretsInitializerFromMappings_Success(t *testing.T) {
	t.Cleanup(func() { viper.Reset() })

	mock := &mockFetcher{results: map[string]string{
		"DB_PASS": "secret-db",
	}}

	mappings := []vaultclient.SecretMapping{
		{Name: "DB_PASS", UUID: "some-uuid", ViperKey: "database.password"},
		// Entry with empty ViperKey should be ignored.
		{Name: "IGNORED", UUID: "another-uuid", ViperKey: ""},
	}

	si := bootstrap.NewSecretsInitializerFromMappings(mock, mappings)
	require.NotNil(t, si)

	err := si.Initialize(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "secret-db", viper.GetString("database.password"))
}

func TestNewSecretsInitializerFromMappings_EmptyMappings(t *testing.T) {
	t.Cleanup(func() { viper.Reset() })

	mock := &mockFetcher{results: map[string]string{}}
	si := bootstrap.NewSecretsInitializerFromMappings(mock, nil)
	require.NotNil(t, si)

	// Initialize with zero mappings is a no-op — no error expected.
	err := si.Initialize(context.Background())
	require.NoError(t, err)
}

func TestNewSecretsInitializerFromMappings_FetcherError(t *testing.T) {
	t.Cleanup(func() { viper.Reset() })

	mock := &mockFetcher{err: errors.New("connection refused")}
	mappings := []vaultclient.SecretMapping{
		{Name: "JWT_SECRET", UUID: "uuid-1", ViperKey: "jwt_secret"},
	}

	si := bootstrap.NewSecretsInitializerFromMappings(mock, mappings)
	err := si.Initialize(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secrets initializer")
}

func TestNewSecretsInitializerFromMappings_IgnoresEntryWithoutViperKey(t *testing.T) {
	t.Cleanup(func() { viper.Reset() })

	// Fetcher returns nothing for empty-ViperKey entries (they're skipped at
	// construction time, so GetMany won't even be called for them).
	mock := &mockFetcher{results: map[string]string{}}

	mappings := []vaultclient.SecretMapping{
		{Name: "NO_KEY", UUID: "uuid-x", ViperKey: ""},
	}

	si := bootstrap.NewSecretsInitializerFromMappings(mock, mappings)
	// All mappings filtered out → GetMany is called with an empty slice → no error.
	err := si.Initialize(context.Background())
	require.NoError(t, err)
}
