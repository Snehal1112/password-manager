package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/retry"
	authServices "rocketvault/internal/services/auth"
)

func newAuthTestCmd(username, password, totpCode string) *cobra.Command {
	c := &cobra.Command{Use: "test"}
	c.Flags().String("username", "", "")
	c.Flags().String("password", "", "")
	c.Flags().String("totp-code", "", "")
	_ = c.Flags().Set("username", username)
	_ = c.Flags().Set("password", password)
	_ = c.Flags().Set("totp-code", totpCode)
	c.SetContext(context.Background())
	return c
}

func TestResolveAuthentication_UsernamePassword_Success(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	// jwt.expiry is a required production config value (see CLAUDE.md); the
	// test binary loads no config file, so set it explicitly to avoid a
	// zero-duration ExpiresAt racing against time.Now() in the assertion below.
	previousExpiry := viper.Get("jwt.expiry")
	viper.Set("jwt.expiry", time.Hour)
	t.Cleanup(func() { viper.Set("jwt.expiry", previousExpiry) })
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "admin123", "123456").
		Return(&authServices.AuthenticationResult{
			Token: "access-tok", RefreshToken: "refresh-tok", UserID: userID, Username: "admin", Role: "admin",
		}, nil)

	c := newAuthTestCmd("admin", "admin123", "123456")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "access-tok", result.Token)

	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, "access-tok", cached.Token)
	assert.True(t, cached.ExpiresAt.After(time.Now()))
}

func TestResolveAuthentication_UsernamePassword_AuthFails_ReturnsError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrong", "123456").
		Return(nil, assert.AnError)

	c := newAuthTestCmd("admin", "wrong", "123456")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	assert.Error(t, err)
	cached, err := common.LoadSession("admin")
	require.NoError(t, err)
	assert.Nil(t, cached, "a failed login must not cache a session")
}

func TestResolveAuthentication_UsernameOnly_LoadsNamedCachedSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "cached-tok", Username: "user14", ExpiresAt: time.Now().Add(time.Hour),
	}))
	tc.MockAuthService.On("ValidateSession", mock.Anything, "cached-tok").
		Return(&authServices.JWTClaims{UserID: userID, Username: "user14", Role: "user"}, nil)

	c := newAuthTestCmd("user14", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "cached-tok", result.Token)
	assert.Equal(t, "user14", result.Username)
	tc.MockAuthService.AssertNotCalled(t, "AuthenticateUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestResolveAuthentication_NoFlags_UsesCurrentPointer(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "cached-tok", Username: "user14", ExpiresAt: time.Now().Add(time.Hour),
	}))
	tc.MockAuthService.On("ValidateSession", mock.Anything, "cached-tok").
		Return(&authServices.JWTClaims{UserID: userID, Username: "user14", Role: "user"}, nil)

	c := newAuthTestCmd("", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "cached-tok", result.Token)
}

// TestResolveAuthentication_CachedSessionRevokedServerSide verifies that a
// cache file whose ExpiresAt hasn't passed yet is NOT trusted blindly — the
// server-side ValidateSession check must run, so an admin revoking the
// session takes effect immediately instead of only once the locally-recorded
// ExpiresAt naturally elapses. A ValidateSession failure here falls through
// to the same transparent-refresh path used for an already-expired cache.
func TestResolveAuthentication_CachedSessionRevokedServerSide(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "revoked-tok", RefreshToken: "old-refresh", Username: "user14",
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	tc.MockAuthService.On("ValidateSession", mock.Anything, "revoked-tok").
		Return(nil, assert.AnError)
	tc.MockAuthService.On("RefreshAccessToken", mock.Anything, "old-refresh").
		Return(&authServices.RefreshTokenResult{
			Token: "new-tok", RefreshToken: "new-refresh", UserID: userID, Username: "user14", Role: "user",
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil)

	c := newAuthTestCmd("", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "new-tok", result.Token, "a revoked cached session must fall through to a fresh refresh")
}

func TestResolveAuthentication_NoFlagsNoCache_ReturnsError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)

	c := newAuthTestCmd("", "", "")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	assert.Error(t, err)
}

func TestResolveAuthentication_ExpiredCache_RefreshesTransparently(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	userID := uuid.New()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "old-tok", RefreshToken: "old-refresh", Username: "user14",
		ExpiresAt: time.Now().Add(-time.Minute),
	}))
	tc.MockAuthService.On("RefreshAccessToken", mock.Anything, "old-refresh").
		Return(&authServices.RefreshTokenResult{
			Token: "new-tok", RefreshToken: "new-refresh", UserID: userID, Username: "user14", Role: "user",
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil)

	c := newAuthTestCmd("", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "new-tok", result.Token)

	cached, err := common.LoadSession("user14")
	require.NoError(t, err)
	require.NotNil(t, cached)
	assert.Equal(t, "new-tok", cached.Token, "the refreshed token must be re-cached")
}

func TestResolveAuthentication_ExpiredCacheRefreshFails_ReturnsError(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "old-tok", RefreshToken: "old-refresh", Username: "user14",
		ExpiresAt: time.Now().Add(-time.Minute),
	}))
	tc.MockAuthService.On("RefreshAccessToken", mock.Anything, "old-refresh").
		Return(nil, assert.AnError)

	c := newAuthTestCmd("", "", "")
	_, err := resolveAuthentication(c, tc.MockAuthService)

	assert.Error(t, err)
}

// TestInitConfig_RetryConfigEnvOverride verifies that SetRetryDefaults and
// BindRetryConfig are called during initConfig so environment variable overrides work.
func TestInitConfig_RetryConfigEnvOverride(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")

	// Set up retry defaults and bind config (this is what initConfig does).
	retry.SetRetryDefaults(v)
	retry.BindRetryConfig(v)

	// Set an environment variable override.
	t.Setenv("RETRY_DATABASE_MAX_ATTEMPTS", "10")

	// Verify the environment variable is reflected in viper.
	maxAttempts := v.GetInt("retry.database.max_attempts")
	require.Equal(t, 10, maxAttempts, "environment variable override RETRY_DATABASE_MAX_ATTEMPTS should be reflected in retry config")
}

// useTempConfigFile points the package-level cfgFile at a minimal, valid
// config so initConfig (registered globally via cobra.OnInitialize in
// init(), and therefore run for ANY cobra.Command's Execute/ExecuteContext
// call in this test binary, not just rootCmd's) doesn't panic when it can't
// find ".rocketvault.yaml" relative to the test's working directory
// (cmd/). Restores the previous value on cleanup.
func useTempConfigFile(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test-config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("jwt:\n  expiry: 1h\n"), 0o600))

	previous := cfgFile
	cfgFile = path
	t.Cleanup(func() { cfgFile = previous })
}

// TestRun_ReturnsNonZeroOnError is the regression test for the bug where
// Execute() called os.Exit(0) even when rootCmd.ExecuteContext returned a
// non-nil error, making every CLI failure indistinguishable from success
// at the shell level ("&&"/"set -e" never caught it).
func TestRun_ReturnsNonZeroOnError(t *testing.T) {
	useTempConfigFile(t)
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("boom")
		},
	}
	cmd.SetArgs([]string{})

	exitCode := run(cmd)

	assert.NotEqual(t, 0, exitCode, "run() must return a non-zero exit code when the command errors")
}

// TestRun_ReturnsZeroOnSuccess pins the success path so a future change to
// run() can't flip both cases to the same wrong value.
func TestRun_ReturnsZeroOnSuccess(t *testing.T) {
	useTempConfigFile(t)
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	cmd.SetArgs([]string{})

	exitCode := run(cmd)

	assert.Equal(t, 0, exitCode, "run() must return 0 when the command succeeds")
}

// TestInitConfig_RemoteMode_DoesNotPanicWithoutConfigFile verifies that
// initConfig() no longer panics unconditionally when .rocketvault.yaml is
// missing — remote mode (resolved here via ROCKETVAULT_ADDR) needs no local
// config file at all, only a target server.
func TestInitConfig_RemoteMode_DoesNotPanicWithoutConfigFile(t *testing.T) {
	dir := t.TempDir() // no .rocketvault.yaml here
	origWd, _ := os.Getwd()
	defer os.Chdir(origWd)
	os.Chdir(dir)

	t.Setenv("ROCKETVAULT_ADDR", "https://vault.prod.example.com")
	viper.Reset()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("initConfig() panicked in remote mode without a config file: %v", r)
		}
	}()
	initConfig()
}
