package cmd

import (
	"context"
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
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "cached-tok", Username: "user14", ExpiresAt: time.Now().Add(time.Hour),
	}))

	c := newAuthTestCmd("user14", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "cached-tok", result.Token)
	tc.MockAuthService.AssertNotCalled(t, "AuthenticateUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestResolveAuthentication_NoFlags_UsesCurrentPointer(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	tc := testutils.NewTestContext(t)
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Token: "cached-tok", Username: "user14", ExpiresAt: time.Now().Add(time.Hour),
	}))

	c := newAuthTestCmd("", "", "")
	result, err := resolveAuthentication(c, tc.MockAuthService)

	require.NoError(t, err)
	assert.Equal(t, "cached-tok", result.Token)
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
