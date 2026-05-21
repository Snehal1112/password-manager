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
