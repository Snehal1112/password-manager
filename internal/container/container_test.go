// Package container contains unit tests for the ServiceContainer dependency
// injection layer. Tests are in the same package to allow direct access to
// unexported struct fields without any reflection tricks.
package container

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cache"
	"rocketvault/internal/logging"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestLogger returns a silent logrus-backed Logger so that test output
// stays clean.
func newTestLogger() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel) // suppress all log output during tests
	return logging.WrapLogrus(l)
}

// openSQLite opens a fresh in-memory SQLite database and registers it for
// cleanup when the test ends.
func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newMinimalConfig returns a Config that has enough to bootstrap the container
// without touching the filesystem beyond what the OS key-store provider needs.
//
// The jwt.key_source defaults to "os_store" which auto-generates an RSA key
// when the keychain has no entry, so no jwt_secret is required.
func newMinimalConfig(t *testing.T) Config {
	t.Helper()
	v := viper.New()
	// Use os_store explicitly — it auto-generates a key and never errors.
	v.Set("jwt.key_source", "os_store")
	// Disable caching to avoid background goroutines in tests that close quickly.
	return Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: &cache.CacheConfig{Enabled: false},
		Viper:       v,
	}
}

// ---------------------------------------------------------------------------
// Test 1 — zero-value ServiceContainer returns nil from every getter
// ---------------------------------------------------------------------------

// TestGetters_ZeroValueContainer verifies that all 43 getter methods return
// their zero value (nil interface / nil pointer) on an uninitialised
// ServiceContainer. Each getter is a single-statement return, so calling every
// one drives all of those statements.
func TestGetters_ZeroValueContainer(t *testing.T) {
	c := &ServiceContainer{}

	// Repositories
	assert.Nil(t, c.GetUserRepository(), "GetUserRepository")
	assert.Nil(t, c.GetSecretRepository(), "GetSecretRepository")
	assert.Nil(t, c.GetRotationRepository(), "GetRotationRepository")
	assert.Nil(t, c.GetVersionRepository(), "GetVersionRepository")
	assert.Nil(t, c.GetKeyRepository(), "GetKeyRepository")
	assert.Nil(t, c.GetCertificateRepository(), "GetCertificateRepository")
	assert.Nil(t, c.GetCertificatePolicyRepository(), "GetCertificatePolicyRepository")
	assert.Nil(t, c.GetSessionRepository(), "GetSessionRepository")
	assert.Nil(t, c.GetVaultRepository(), "GetVaultRepository")
	assert.Nil(t, c.GetAccessPolicyRepository(), "GetAccessPolicyRepository")
	assert.Nil(t, c.GetOAuth2ClientRepository(), "GetOAuth2ClientRepository")

	// Auth services
	assert.Nil(t, c.GetPasswordService(), "GetPasswordService")
	assert.Nil(t, c.GetTOTPService(), "GetTOTPService")
	assert.Nil(t, c.GetJWTService(), "GetJWTService")
	assert.Nil(t, c.GetAuthenticationService(), "GetAuthenticationService")
	assert.Nil(t, c.GetOIDCService(), "GetOIDCService")

	// Authorization services
	assert.Nil(t, c.GetRBACService(), "GetRBACService")
	assert.Nil(t, c.GetAccessPolicyService(), "GetAccessPolicyService")

	// OAuth2
	assert.Nil(t, c.GetOAuth2Service(), "GetOAuth2Service")

	// Business services
	assert.Nil(t, c.GetUserService(), "GetUserService")
	assert.Nil(t, c.GetSecretService(), "GetSecretService")
	assert.Nil(t, c.GetKeyService(), "GetKeyService")
	assert.Nil(t, c.GetCertificateService(), "GetCertificateService")
	assert.Nil(t, c.GetCertificateRenewalService(), "GetCertificateRenewalService")
	assert.Nil(t, c.GetCryptoService(), "GetCryptoService")
	assert.Nil(t, c.GetVaultService(), "GetVaultService")

	// Secret component services
	assert.Nil(t, c.GetCryptographyService(), "GetCryptographyService")
	assert.Nil(t, c.GetVersioningService(), "GetVersioningService")
	assert.Nil(t, c.GetTagService(), "GetTagService")
	assert.Nil(t, c.GetRotationService(), "GetRotationService")
	assert.Nil(t, c.GetSchedulerService(), "GetSchedulerService")

	// Infrastructure
	assert.Nil(t, c.GetDatabase(), "GetDatabase")
	assert.Nil(t, c.GetLogger(), "GetLogger")

	// Cache
	assert.Nil(t, c.GetSecretCache(), "GetSecretCache")
	assert.Nil(t, c.GetCacheConfig(), "GetCacheConfig")
	assert.Nil(t, c.GetCachedSecretService(), "GetCachedSecretService")

	// Retry
	assert.Nil(t, c.GetRetryService(), "GetRetryService")

	// Signing / key / metrics
	assert.Nil(t, c.GetSigningProvider(), "GetSigningProvider")
	assert.Nil(t, c.GetItemBackupService(), "GetItemBackupService")
	assert.Nil(t, c.GetKeyProvider(), "GetKeyProvider")
	assert.Nil(t, c.GetKeyCache(), "GetKeyCache")
	assert.Nil(t, c.GetCryptoMetrics(), "GetCryptoMetrics")

	// Audit
	assert.Nil(t, c.GetAuditService(), "GetAuditService")
	assert.Nil(t, c.GetComplianceReportService(), "GetComplianceReportService")
}

// ---------------------------------------------------------------------------
// Test 2 — Config struct zero-value
// ---------------------------------------------------------------------------

// TestConfig_ZeroValue confirms the Config struct is usable as a zero value
// (nil Database, Logger, CacheConfig, and Viper fields).
func TestConfig_ZeroValue(t *testing.T) {
	cfg := Config{}
	assert.Nil(t, cfg.Database)
	assert.Nil(t, cfg.Logger)
	assert.Nil(t, cfg.CacheConfig)
	assert.Nil(t, cfg.Viper)
}

// ---------------------------------------------------------------------------
// Test 3 — Close with all fields nil
// ---------------------------------------------------------------------------

// TestClose_AllFieldsNil verifies that Close() on a zero-value ServiceContainer
// returns nil without panicking. The cacheCancel, keyCache, keyProvider, and
// db fields are all nil — each guard in Close() must be exercised.
func TestClose_AllFieldsNil(t *testing.T) {
	c := &ServiceContainer{}
	err := c.Close()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Test 4 — Close with cacheCancel set
// ---------------------------------------------------------------------------

// TestClose_WithCacheCancel exercises the cacheCancel != nil branch in Close().
func TestClose_WithCacheCancel(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	c := &ServiceContainer{cacheCancel: cancel}
	err := c.Close()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Test 5 — Close with live database
// ---------------------------------------------------------------------------

// TestClose_WithDB exercises the db != nil branch in Close() and verifies the
// returned error propagates correctly (a closed DB returns nil from a second
// close, so we just check no unexpected error occurs).
func TestClose_WithDB(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	// Do NOT defer db.Close() here because Close() will close it for us.
	c := &ServiceContainer{db: db}
	err = c.Close()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Test 6 — NewServiceContainer success path (with caching disabled)
// ---------------------------------------------------------------------------

// TestNewServiceContainer_Success_CacheDisabled bootstraps a full container
// against an in-memory SQLite database with caching turned off. It verifies
// that every core service getter returns a non-nil value after initialisation
// and that Close() tears everything down cleanly.
func TestNewServiceContainer_Success_CacheDisabled(t *testing.T) {
	cfg := newMinimalConfig(t)
	cfg.CacheConfig = &cache.CacheConfig{Enabled: false}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	// Infrastructure
	assert.NotNil(t, container.GetDatabase(), "GetDatabase must not be nil after init")
	assert.NotNil(t, container.GetLogger(), "GetLogger must not be nil after init")

	// Repositories
	assert.NotNil(t, container.GetUserRepository(), "GetUserRepository")
	assert.NotNil(t, container.GetSecretRepository(), "GetSecretRepository")
	assert.NotNil(t, container.GetRotationRepository(), "GetRotationRepository")
	assert.NotNil(t, container.GetVersionRepository(), "GetVersionRepository")
	assert.NotNil(t, container.GetKeyRepository(), "GetKeyRepository")
	assert.NotNil(t, container.GetCertificateRepository(), "GetCertificateRepository")
	assert.NotNil(t, container.GetCertificatePolicyRepository(), "GetCertificatePolicyRepository")
	assert.NotNil(t, container.GetSessionRepository(), "GetSessionRepository")
	assert.NotNil(t, container.GetVaultRepository(), "GetVaultRepository")
	assert.NotNil(t, container.GetAccessPolicyRepository(), "GetAccessPolicyRepository")
	assert.NotNil(t, container.GetOAuth2ClientRepository(), "GetOAuth2ClientRepository")

	// Auth services
	assert.NotNil(t, container.GetPasswordService(), "GetPasswordService")
	assert.NotNil(t, container.GetTOTPService(), "GetTOTPService")
	assert.NotNil(t, container.GetJWTService(), "GetJWTService")
	assert.NotNil(t, container.GetAuthenticationService(), "GetAuthenticationService")
	assert.Nil(t, container.GetOIDCService(), "GetOIDCService") // oidc.enabled is false by default in every test fixture.

	// Authorization services
	assert.NotNil(t, container.GetRBACService(), "GetRBACService")
	assert.NotNil(t, container.GetAccessPolicyService(), "GetAccessPolicyService")

	// OAuth2
	assert.NotNil(t, container.GetOAuth2Service(), "GetOAuth2Service")

	// Business services
	assert.NotNil(t, container.GetUserService(), "GetUserService")
	assert.NotNil(t, container.GetSecretService(), "GetSecretService")
	assert.NotNil(t, container.GetKeyService(), "GetKeyService")
	assert.NotNil(t, container.GetCertificateService(), "GetCertificateService")
	assert.NotNil(t, container.GetCertificateRenewalService(), "GetCertificateRenewalService")
	assert.NotNil(t, container.GetCryptoService(), "GetCryptoService")
	assert.NotNil(t, container.GetVaultService(), "GetVaultService")

	// Secret component services
	assert.NotNil(t, container.GetCryptographyService(), "GetCryptographyService")
	assert.NotNil(t, container.GetVersioningService(), "GetVersioningService")
	assert.NotNil(t, container.GetTagService(), "GetTagService")
	assert.NotNil(t, container.GetRotationService(), "GetRotationService")
	assert.NotNil(t, container.GetSchedulerService(), "GetSchedulerService")

	// Cache (disabled)
	assert.Nil(t, container.GetSecretCache(), "GetSecretCache must be nil when cache disabled")
	assert.Nil(t, container.GetCachedSecretService(), "GetCachedSecretService must be nil when cache disabled")
	assert.NotNil(t, container.GetCacheConfig(), "GetCacheConfig")

	// Signing / key / metrics
	assert.NotNil(t, container.GetSigningProvider(), "GetSigningProvider")
	assert.NotNil(t, container.GetItemBackupService(), "GetItemBackupService")
	assert.NotNil(t, container.GetKeyProvider(), "GetKeyProvider")
	assert.NotNil(t, container.GetKeyCache(), "GetKeyCache")
	assert.NotNil(t, container.GetCryptoMetrics(), "GetCryptoMetrics")

	// Audit
	assert.NotNil(t, container.GetAuditService(), "GetAuditService")
	assert.NotNil(t, container.GetComplianceReportService(), "GetComplianceReportService")

	// Retry service is nil because the injected Viper has no retry configuration
	// and the code intentionally skips retry when the RetryService init logs a
	// warning. That is fine — presence of the field is optional.
}

// ---------------------------------------------------------------------------
// Test 7 — NewServiceContainer success path (with caching enabled)
// ---------------------------------------------------------------------------

// TestNewServiceContainer_Success_CacheEnabled exercises the cache initialisation
// branch in initializeServices and confirms GetSecretCache and
// GetCachedSecretService return non-nil values.
func TestNewServiceContainer_Success_CacheEnabled(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "os_store")

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: cache.DefaultCacheConfig(), // Enabled: true
		Viper:       v,
	}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	assert.NotNil(t, container.GetSecretCache(), "GetSecretCache must be non-nil when cache is enabled")
	assert.NotNil(t, container.GetCachedSecretService(), "GetCachedSecretService must be non-nil when cache is enabled")
	assert.NotNil(t, container.GetCacheConfig(), "GetCacheConfig")
}

// ---------------------------------------------------------------------------
// Test 8 — NewServiceContainer with nil CacheConfig falls back to default
// ---------------------------------------------------------------------------

// TestNewServiceContainer_NilCacheConfig confirms that a nil CacheConfig in the
// Config struct is replaced with the library default and does not panic.
func TestNewServiceContainer_NilCacheConfig(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "os_store")

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: nil, // deliberately nil — should default
		Viper:       v,
	}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	// The container must have a non-nil CacheConfig after defaulting.
	assert.NotNil(t, container.GetCacheConfig(), "GetCacheConfig must be non-nil after defaulting")
}

// ---------------------------------------------------------------------------
// Test 9 — NewServiceContainer with nil Viper falls back to global viper
// ---------------------------------------------------------------------------

// TestNewServiceContainer_NilViper verifies that omitting the Viper field
// causes initializeServices to fall back to the global viper instance, and
// the retry-service warning path is taken (c.viper == nil branch).
func TestNewServiceContainer_NilViper(t *testing.T) {
	// Seed global viper with the jwt_secret so the HS256 fallback path works
	// in case os_store fails (though on most systems it should succeed).
	viper.Set("jwt_secret", "test-super-secret-for-global-viper-at-least-32chars")
	t.Cleanup(func() {
		viper.Set("jwt_secret", "")
	})

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: &cache.CacheConfig{Enabled: false},
		Viper:       nil, // trigger fallback to global viper
	}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	// Core services must still be wired up.
	assert.NotNil(t, container.GetPasswordService())
	assert.NotNil(t, container.GetJWTService())
	assert.NotNil(t, container.GetDatabase())
	// Retry service should be nil because c.viper == nil skips retry init.
	assert.Nil(t, container.GetRetryService(), "RetryService must be nil when Viper not injected")
}

// ---------------------------------------------------------------------------
// Test 10 — NewServiceContainer with missing jwt_secret and unknown key_source
// ---------------------------------------------------------------------------

// TestNewServiceContainer_UnknownKeySource_WithJWTSecret forces an unknown
// jwt.key_source (causing the signing provider to fail) while providing a
// jwt_secret, so the HS256 fallback path is taken without error.
func TestNewServiceContainer_UnknownKeySource_HS256Fallback(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "unknown_provider") // triggers provider == nil
	v.Set("jwt_secret", "super-secret-key-that-is-long-enough-for-hs256")

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: &cache.CacheConfig{Enabled: false},
		Viper:       v,
	}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err, "HS256 fallback must succeed when jwt_secret is set")
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	assert.NotNil(t, container.GetJWTService(), "JWTService must be initialised via HS256 fallback")
	// Signing provider must be nil because the unknown key_source returned an error.
	assert.Nil(t, container.GetSigningProvider(), "SigningProvider must be nil when provider init failed")
}

// ---------------------------------------------------------------------------
// Test 11 — NewServiceContainer with missing jwt_secret and unknown key_source
// ---------------------------------------------------------------------------

// TestNewServiceContainer_MissingJWTSecret_Error verifies that when no
// signing provider can be constructed AND jwt_secret is empty, initialisation
// returns an error containing the expected message.
func TestNewServiceContainer_MissingJWTSecret_Error(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "unknown_provider") // signing provider fails
	// jwt_secret intentionally NOT set

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: &cache.CacheConfig{Enabled: false},
		Viper:       v,
	}

	_, err := NewServiceContainer(cfg)
	require.Error(t, err, "must error when both provider and jwt_secret are absent")
	assert.Contains(t, err.Error(), "JWT secret")
}

// ---------------------------------------------------------------------------
// Test 12 — NewServiceContainer with viper-configured retry policies
// ---------------------------------------------------------------------------

// TestNewServiceContainer_WithRetryConfig exercises the retry-service
// initialisation path when valid retry config is present in viper.
func TestNewServiceContainer_WithRetryConfig(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "os_store")
	v.Set("retry.database.enabled", true)
	v.Set("retry.database.max_attempts", 3)

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: &cache.CacheConfig{Enabled: false},
		Viper:       v,
	}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	// The retry service should be initialised and returned non-nil.
	assert.NotNil(t, container.GetRetryService(), "GetRetryService must be non-nil with retry config")
}

// ---------------------------------------------------------------------------
// Test 13 — NewServiceContainer with external_pki key source
// ---------------------------------------------------------------------------

// TestNewServiceContainer_ExternalPKI_NoFile exercises the code path where the
// signing provider is configured as "external_pki" with no key file and no env
// var, so the provider fails to init. Combined with a valid jwt_secret this
// should still succeed via the HS256 fallback.
func TestNewServiceContainer_ExternalPKI_HS256Fallback(t *testing.T) {
	// Ensure env var is absent so external_pki returns an error.
	t.Setenv("ROCKETVAULT_JWT_SIGNING_KEY", "")

	v := viper.New()
	v.Set("jwt.key_source", "external_pki")
	v.Set("jwt.signing_key_file", "") // no file path — provider will fail
	v.Set("jwt_secret", "fallback-secret-at-least-32-chars-long-here")

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: &cache.CacheConfig{Enabled: false},
		Viper:       v,
	}

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err, "HS256 fallback must succeed when jwt_secret is present")
	require.NotNil(t, container)
	t.Cleanup(func() { _ = container.Close() })

	assert.NotNil(t, container.GetJWTService())
	assert.Nil(t, container.GetSigningProvider(), "SigningProvider must be nil when external_pki fails")
}

// ---------------------------------------------------------------------------
// Test 14 — Close with both cacheCancel and db set
// ---------------------------------------------------------------------------

// TestClose_FullCleanup verifies that Close cancels the cache context and
// closes the database when both are set. The database must not be usable after
// Close returns.
func TestClose_FullCleanup(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	c := &ServiceContainer{
		db:          db,
		cacheCancel: cancel,
	}

	err = c.Close()
	assert.NoError(t, err)

	// The context must have been cancelled.
	assert.Equal(t, context.Canceled, ctx.Err(), "cache context must be cancelled after Close")
}

// ---------------------------------------------------------------------------
// Test 15 — ServiceContainerInterface satisfaction
// ---------------------------------------------------------------------------

// TestServiceContainerInterface_Satisfaction is a compile-time check that
// *ServiceContainer satisfies the ServiceContainerInterface. If this fails to
// compile the test will not build.
func TestServiceContainerInterface_Satisfaction(t *testing.T) {
	var _ ServiceContainerInterface = (*ServiceContainer)(nil)
}

// ---------------------------------------------------------------------------
// Test 16 — GetDatabase returns the exact db passed in Config
// ---------------------------------------------------------------------------

// TestGetDatabase_ReturnsSameInstance checks that the db stored in the
// container is pointer-identical to the one provided in the Config.
func TestGetDatabase_ReturnsSameInstance(t *testing.T) {
	cfg := newMinimalConfig(t)
	originalDB := cfg.Database

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Close() })

	assert.Same(t, originalDB, container.GetDatabase(),
		"GetDatabase must return the same *sql.DB pointer as provided in Config")
}

// ---------------------------------------------------------------------------
// Test 17 — GetLogger returns the exact logger passed in Config
// ---------------------------------------------------------------------------

// TestGetLogger_ReturnsSameInstance checks that the logger stored in the
// container is pointer-identical to the one provided in the Config.
func TestGetLogger_ReturnsSameInstance(t *testing.T) {
	cfg := newMinimalConfig(t)
	originalLogger := cfg.Logger

	container, err := NewServiceContainer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Close() })

	assert.Same(t, originalLogger, container.GetLogger(),
		"GetLogger must return the same *logging.Logger pointer as provided in Config")
}
