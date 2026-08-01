// Package container provides dependency injection for the password manager.
// It manages service creation and lifecycle, ensuring proper dependency
// resolution and eliminating global state dependencies.
package container

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/spf13/viper"

	"rocketvault/internal/backup"
	"rocketvault/internal/cache"
	"rocketvault/internal/crypto"
	"rocketvault/internal/db"
	"rocketvault/internal/keycache"
	"rocketvault/internal/logging"
	"rocketvault/internal/metrics"
	"rocketvault/internal/repositories"
	auditServices "rocketvault/internal/services/audit"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	oauth2Services "rocketvault/internal/services/oauth2"
	retryServices "rocketvault/internal/services/retry"
	secretServices "rocketvault/internal/services/secrets"
	secrets "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/internal/signing"
)

// ServiceContainerInterface defines the interface for the service container.
// This interface enables testability by allowing mock implementations
// to be used in place of the concrete ServiceContainer.
//
// The interface provides access to all application services, repositories,
// and infrastructure components through well-defined getter methods.
type ServiceContainerInterface interface {
	// Repository getters
	GetUserRepository() repositories.UserRepositoryInterface
	GetSecretRepository() repositories.SecretRepositoryInterface
	GetRotationRepository() repositories.RotationPolicyRepositoryInterface
	GetVersionRepository() repositories.SecretVersionRepositoryInterface
	GetKeyRepository() repositories.KeyRepositoryInterface
	GetCertificateRepository() repositories.CertificateRepositoryInterface
	GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface
	GetSessionRepository() repositories.SessionRepositoryInterface
	GetVaultRepository() repositories.VaultRepositoryInterface

	// Authentication service getters
	GetPasswordService() authServices.PasswordService
	GetTOTPService() authServices.TOTPService
	GetJWTService() authServices.JWTService
	GetAuthenticationService() authServices.AuthenticationService

	// Authorization service getters
	GetRBACService() authzServices.RBACService
	GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface
	GetAccessPolicyService() authzServices.AccessPolicyService
	GetRoleAssignmentService() authzServices.RoleAssignmentService

	// OAuth2 / service account getters
	GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface
	GetOAuth2Service() oauth2Services.OAuth2Service

	// Business service getters
	GetUserService() userServices.UserService
	GetSecretService() secretServices.SecretService
	GetKeyService() keyServices.KeyService
	GetCertificateService() certServices.CertificateService
	GetCertificateRenewalService() certServices.CertificateRenewalService
	GetCryptoService() keyServices.CryptoService
	GetVaultService() vaultServices.VaultService

	// Secret component service getters
	GetCryptographyService() secretServices.CryptographyService
	GetVersioningService() secretServices.VersioningServiceInterface
	GetTagService() secretServices.TagService
	GetRotationService() secretServices.RotationServiceInterface
	GetSchedulerService() secretServices.SchedulerServiceInterface

	// Infrastructure getters
	GetDatabase() *sql.DB
	GetLogger() *logging.Logger

	// Cache getters
	GetSecretCache() *cache.SecretCache
	GetCacheConfig() *cache.CacheConfig
	GetCachedSecretService() secrets.SecretService

	// Retry service getters
	GetRetryService() retryServices.RetryService

	// Signing provider getter
	GetSigningProvider() signing.SigningKeyProvider

	// Backup service getter
	GetItemBackupService() *backup.ItemBackupService

	// Key provider getter
	GetKeyProvider() crypto.KeyProvider

	// Key cache and metrics getters
	GetKeyCache() keycache.Cache
	GetCryptoMetrics() metrics.CryptoMetrics

	// Audit service getters
	GetAuditService() auditServices.AuditServiceInterface
	GetComplianceReportService() auditServices.ComplianceReportServiceInterface

	// Lifecycle management
	Close() error
}

// ServiceContainer manages all application services and their dependencies.
// It provides a centralized way to create and inject dependencies,
// replacing global variables with proper dependency injection.
//
// ServiceContainer implements ServiceContainerInterface.
type ServiceContainer struct {
	// Core infrastructure
	db     *sql.DB  // raw handle for health checks, transactions, and Close
	conn   *db.Conn // dialect-aware wrapper repositories use for all queries
	logger *logging.Logger
	viper  *viper.Viper // Configuration manager

	// Cache infrastructure
	secretCache         *cache.SecretCache
	cachedSecretService secrets.SecretService
	cacheConfig         *cache.CacheConfig
	cacheContext        context.Context
	cacheCancel         context.CancelFunc

	// Repositories
	userRepository        repositories.UserRepositoryInterface
	secretRepository      repositories.SecretRepositoryInterface
	rotationRepository    repositories.RotationPolicyRepositoryInterface
	versionRepository     repositories.SecretVersionRepositoryInterface
	keyRepository         repositories.KeyRepositoryInterface
	certificateRepository repositories.CertificateRepositoryInterface
	certPolicyRepository  repositories.CertificatePolicyRepositoryInterface
	sessionRepository     repositories.SessionRepositoryInterface
	vaultRepository       repositories.VaultRepositoryInterface
	auditRepository       repositories.AuditRepositoryExtended

	// Audit services
	auditService            auditServices.AuditServiceInterface
	complianceReportService auditServices.ComplianceReportServiceInterface

	// Authentication services
	passwordService       authServices.PasswordService
	totpService           authServices.TOTPService
	jwtService            authServices.JWTService
	authenticationService authServices.AuthenticationService

	// Authorization services
	rbacService              authzServices.RBACService
	accessPolicyRepository   repositories.AccessPolicyRepositoryInterface
	accessPolicyService      authzServices.AccessPolicyService
	roleAssignmentRepository repositories.RoleAssignmentRepositoryInterface
	roleAssignmentService    authzServices.RoleAssignmentService

	// OAuth2 service account services
	oauth2ClientRepository repositories.OAuth2ClientRepositoryInterface
	oauth2Service          oauth2Services.OAuth2Service

	// Business services
	userService        userServices.UserService
	secretService      secrets.SecretService
	keyService         keyServices.KeyService
	certificateService certServices.CertificateService
	certRenewalService certServices.CertificateRenewalService
	keyCryptoService   keyServices.CryptoService
	vaultService       vaultServices.VaultService

	// Secret component services
	cryptoService     secretServices.CryptographyService
	versioningService secretServices.VersioningServiceInterface
	tagService        secretServices.TagService
	rotationService   secretServices.RotationServiceInterface
	schedulerService  secretServices.SchedulerServiceInterface

	// Retry services
	retryService retryServices.RetryService

	// JWT signing provider
	signingProvider signing.SigningKeyProvider

	// Per-item backup service
	itemBackupService *backup.ItemBackupService

	// Key provider (software or PKCS#11 HSM).
	keyProvider crypto.KeyProvider

	// Key cache for decrypted key material.
	keyCache keycache.Cache
	// Prometheus metrics for crypto operations.
	cryptoMetrics metrics.CryptoMetrics
}

// Config holds configuration for the service container.
type Config struct {
	Database    *sql.DB
	Logger      *logging.Logger
	CacheConfig *cache.CacheConfig
	Viper       *viper.Viper // Configuration manager for retry policies and other settings
}

// NewServiceContainer creates a new service container with the provided configuration.
// It initializes all services and their dependencies in the correct order.
//
// Parameters:
//
//	config: Configuration containing database, logger, and cache settings.
//
// Returns:
//
//	A ServiceContainer with all services properly initialized.
func NewServiceContainer(config Config) (*ServiceContainer, error) {
	// Create cache context for background operations
	cacheCtx, cacheCancel := context.WithCancel(context.Background())

	// Resolve the SQL dialect from configuration so repositories rebind "?"
	// placeholders correctly for the active engine. Defaults to SQLite.
	dialect := db.DialectFromDriver(viper.GetString("database.driver"))

	// Wrap the raw handle so every repository query routes through the dialect.
	// config.Database may be nil on the unit-test path; conn stays nil then.
	var conn *db.Conn
	if config.Database != nil {
		conn = db.NewConn(config.Database, dialect)
	}

	container := &ServiceContainer{
		db:           config.Database,
		conn:         conn,
		logger:       config.Logger,
		viper:        config.Viper,
		cacheContext: cacheCtx,
		cacheCancel:  cacheCancel,
	}

	// Set default cache config if not provided
	if config.CacheConfig == nil {
		config.CacheConfig = cache.DefaultCacheConfig()
	}
	container.cacheConfig = config.CacheConfig

	if err := container.initializeServices(); err != nil {
		cacheCancel() // Clean up cache context on error
		return nil, fmt.Errorf("failed to initialize services: %w", err)
	}

	return container, nil
}

// initializeServices creates and wires all services in dependency order.
func (c *ServiceContainer) initializeServices() error {
	// Resolve the viper instance to use for config reads.
	// Falls back to the global viper populated by initConfig() when none was injected.
	viperCfg := c.viper
	if viperCfg == nil {
		viperCfg = viper.GetViper()
	}

	// Initialize repositories (data layer). They receive the dialect-aware conn
	// so every query is rebound for the active engine.
	c.userRepository = repositories.NewUserRepository(c.conn, c.logger)
	c.secretRepository = repositories.NewSecretRepository(c.conn, c.logger)
	c.rotationRepository = repositories.NewRotationPolicyRepository(c.conn, c.logger)
	c.versionRepository = repositories.NewSecretVersionRepository(c.conn, c.logger)
	c.keyRepository = repositories.NewKeyRepository(c.conn, c.logger)
	c.certificateRepository = repositories.NewCertificateRepository(c.conn, c.logger)
	c.vaultRepository = repositories.NewVaultRepository(c.conn, c.logger)
	vaultCascade := vaultServices.NewCascadeAdapter(c.secretRepository, c.keyRepository, c.certificateRepository)
	c.vaultService = vaultServices.NewVaultService(c.vaultRepository, vaultCascade, c.logger)
	c.vaultService.SetTxBeginner(c.conn)
	c.certPolicyRepository = repositories.NewCertificatePolicyRepository(c.conn, c.logger)
	c.sessionRepository = repositories.NewSessionRepository(repositories.SessionRepositoryConfig{
		DB:     c.conn,
		Logger: c.logger,
	})
	c.auditRepository = repositories.NewAuditRepository(c.conn)
	c.auditService = auditServices.NewAuditService(c.auditRepository)
	c.complianceReportService = auditServices.NewComplianceReportService(c.auditRepository)
	c.logger.SetAuditPersister(c.auditService)

	// Start daily audit log retention purge in the background.
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := c.complianceReportService.PurgeExpiredLogs(context.Background()); err != nil {
				c.logger.WithError(err).Warn("audit retention purge failed")
			}
		}
	}()

	// Initialize cache if enabled
	if c.cacheConfig.Enabled {
		// Create secret cache
		c.secretCache = cache.NewSecretCache(c.cacheConfig.TTL, c.logger.Logger)

		// Start background cleanup if configured
		if c.cacheConfig.CleanupInterval > 0 {
			c.secretCache.StartCleanup(c.cacheContext, c.cacheConfig.CleanupInterval)
		}

		// The vault delete/recover cascade writes the secrets table directly,
		// so it needs its own invalidation hook. Set only when the cache
		// exists: a typed-nil *SecretCache in the interface would panic.
		c.vaultService.SetSecretCacheFlusher(c.secretCache)
	}

	// Initialize retry service before any service that wraps with retry logic.
	if c.viper != nil {
		retrySvc, err := retryServices.NewRetryService(viperCfg)
		if err != nil {
			c.logger.WithError(err).Warn("Failed to initialize retry service, continuing without retry functionality")
			// Continue without retry service - operations will not have retry.
		} else {
			c.retryService = retrySvc
			c.logger.Info("Retry service initialized successfully")
		}
	} else {
		c.logger.Warn("Viper configuration not provided, retry service will not be available")
	}

	// Initialize authentication services
	c.passwordService = authServices.NewPasswordService()
	c.totpService = authServices.NewTOTPService()

	// Initialize cryptography service early — needed by SelfPKIProvider.
	c.cryptoService = secretServices.NewCryptographyService()

	// Initialize JWT signing provider.
	signingDeps := signing.ProviderDeps{
		CryptoService: c.cryptoService,
		KeyRepository: c.keyRepository,
	}
	provider, err := signing.NewProvider(viperCfg, signingDeps)
	if err != nil {
		c.logger.WithError(err).Warn("Failed to initialise asymmetric JWT signing provider, falling back to HS256")
		provider = nil
	}
	c.signingProvider = provider

	// Initialize JWT service with configuration.
	jwtExpiry := viperCfg.GetDuration("jwt.expiry")
	if jwtExpiry == 0 {
		jwtExpiry = time.Hour // Default to 1 hour.
	}
	jwtConfig := authServices.JWTConfig{
		SecretKey:       viperCfg.GetString("jwt_secret"),
		Issuer:          viperCfg.GetString("oauth2.issuer"),
		Audience:        "PASSWORD_MANAGER",
		Expiry:          jwtExpiry,
		MigrationWindow: viperCfg.GetDuration("jwt.migration_window"),
		Logger:          c.logger.Logger,
	}

	if provider != nil {
		c.jwtService = authServices.NewJWTServiceWithProvider(jwtConfig, provider)
	} else {
		// Asymmetric provider unavailable — fall back to legacy HS256.
		if jwtConfig.SecretKey == "" {
			return fmt.Errorf("JWT secret not configured and asymmetric provider unavailable")
		}
		c.jwtService = authServices.NewJWTService(jwtConfig)
	}

	// Initialize OAuth2 client repository first — the auth service needs it to
	// validate service-account tokens against the live client record.
	c.oauth2ClientRepository = repositories.NewOAuth2ClientRepository(c.conn)

	// Initialize authentication service
	baseAuthService := authServices.NewAuthenticationService(authServices.AuthenticationConfig{
		UserRepository:         c.userRepository,
		SessionRepository:      c.sessionRepository,
		PasswordService:        c.passwordService,
		TOTPService:            c.totpService,
		JWTService:             c.jwtService,
		OAuth2ClientRepository: c.oauth2ClientRepository,
		Logger:                 c.logger,
	})

	// Wrap with retry logic if retry service is available.
	if c.retryService != nil {
		c.authenticationService = retryServices.NewRetryAuthenticationService(baseAuthService, c.retryService)
		c.logger.Info("Retry logic enabled for authentication service")
	} else {
		c.authenticationService = baseAuthService
	}

	// Initialize authorization services
	c.rbacService = authzServices.NewRBACService(c.logger)
	c.accessPolicyRepository = repositories.NewAccessPolicyRepository(c.conn)
	c.accessPolicyService = authzServices.NewAccessPolicyService(c.accessPolicyRepository)
	// Wire the policy cleaner now that the access-policy repository exists; the vault
	// service deletes vault-scoped policies on purge since access_policies has no FK to vaults.
	c.vaultService.SetPolicyCleaner(c.accessPolicyRepository)
	c.roleAssignmentRepository = repositories.NewRoleAssignmentRepository(c.conn)
	c.roleAssignmentService = authzServices.NewRoleAssignmentService(
		c.roleAssignmentRepository,
		c.accessPolicyRepository,
		c.userRepository,
		c.logger,
	)

	// Initialize remaining OAuth2 services (client repo already set above).
	oauth2TokenExpiry := viperCfg.GetDuration("oauth2.token_expiry")
	if oauth2TokenExpiry == 0 {
		oauth2TokenExpiry = 30 * time.Minute
	}
	c.oauth2Service = oauth2Services.NewOAuth2Service(oauth2Services.OAuth2Config{
		ClientRepo:      c.oauth2ClientRepository,
		PasswordService: c.passwordService,
		JWTService:      c.jwtService,
		TokenExpiry:     oauth2TokenExpiry,
	})

	// Initialize user service
	baseUserService := userServices.NewUserService(userServices.UserServiceConfig{
		UserRepository:  c.userRepository,
		PasswordService: c.passwordService,
		TOTPService:     c.totpService,
		Logger:          c.logger,
	})

	// Wrap with retry logic if retry service is available
	if c.retryService != nil {
		c.userService = retryServices.NewRetryUserService(baseUserService, c.retryService)
		c.logger.Info("Retry logic enabled for user service")
	} else {
		c.userService = baseUserService
	}

	// Rollback and rotation update the secrets table directly instead of going
	// through CachedSecretService, so they take their own invalidator. It
	// stays a nil interface when caching is disabled — assigning a typed-nil
	// *cache.SecretCache would make the nil check inside the services useless.
	var secretCacheInvalidator secretServices.SecretCacheInvalidator
	if c.secretCache != nil {
		secretCacheInvalidator = c.secretCache
	}

	// Initialize secret component services (cryptoService already initialised above).
	c.versioningService = secretServices.NewVersioningService(
		c.versionRepository,
		c.secretRepository,
		c.userRepository,
		c.cryptoService,
		c.logger,
		secretCacheInvalidator,
	)
	c.tagService = secretServices.NewTagService(repositories.NewSecretTagRepository(c.conn), c.logger)
	c.rotationService = secretServices.NewRotationService(
		c.rotationRepository,
		c.secretRepository,
		c.userRepository,
		c.cryptoService,
		c.logger,
		secretCacheInvalidator,
	)
	c.schedulerService = secretServices.NewSchedulerService(
		c.rotationService,
		c.versioningService,
		c.userRepository,
		c.secretRepository,
		c.rotationRepository,
		c.logger,
	)

	// Initialize secret service
	baseSecretService := secretServices.NewSecretService(secretServices.SecretServiceConfig{
		SecretRepository: c.secretRepository,
		CryptoService:    c.cryptoService,
		VersionService:   c.versioningService,
		TagService:       c.tagService,
		Logger:           c.logger,
	})

	// Wrap with retry logic if retry service is available
	var retryEnabledSecretService secrets.SecretService
	if c.retryService != nil {
		// Create retry-aware secret service
		retryEnabledSecretService = retryServices.NewRetrySecretService(baseSecretService, c.retryService)
		c.logger.Info("Retry logic enabled for secret service")
	} else {
		retryEnabledSecretService = baseSecretService
	}

	// Wrap with cache if enabled
	if c.cacheConfig.Enabled {
		c.cachedSecretService = cache.NewCachedSecretService(retryEnabledSecretService, c.secretCache, c.logger.Logger)
		c.secretService = c.cachedSecretService
	} else {
		c.secretService = retryEnabledSecretService
	}

	// Initialize key cache from configuration.
	keyCacheConfig := keycache.DefaultKeyCacheConfig()
	if viperCfg.IsSet("key_cache.enabled") {
		keyCacheConfig.Enabled = viperCfg.GetBool("key_cache.enabled")
	}
	if viperCfg.IsSet("key_cache.ttl") {
		keyCacheConfig.TTL = viperCfg.GetDuration("key_cache.ttl")
	}
	if viperCfg.IsSet("key_cache.max_entries") {
		keyCacheConfig.MaxEntries = viperCfg.GetInt("key_cache.max_entries")
	}
	if viperCfg.IsSet("key_cache.cleanup_interval") {
		keyCacheConfig.CleanupInterval = viperCfg.GetDuration("key_cache.cleanup_interval")
	}

	if keyCacheConfig.Enabled {
		c.keyCache = keycache.NewMemoryCache(keyCacheConfig)
	} else {
		c.keyCache = keycache.NewNopCache()
	}

	// Initialize Prometheus metrics for crypto operations.
	c.cryptoMetrics = metrics.NewDefaultPrometheusCryptoMetrics()

	// Select key provider based on hsm.enabled config.
	if viperCfg.GetBool("hsm.enabled") {
		hsmCfg := crypto.PKCS11Config{
			LibPath:    viperCfg.GetString("hsm.lib_path"),
			TokenLabel: viperCfg.GetString("hsm.token_label"),
			PIN:        viperCfg.GetString("hsm.pin"),
			SlotID:     uint(viperCfg.GetUint("hsm.slot_id")),
		}
		p11Provider, p11Err := crypto.NewPKCS11KeyProvider(hsmCfg)
		if p11Err != nil {
			return fmt.Errorf("failed to initialise PKCS#11 key provider: %w", p11Err)
		}
		c.keyProvider = p11Provider
		c.logger.Info("PKCS#11 HSM key provider initialised")
	} else {
		c.keyProvider = crypto.NewSoftwareKeyProvider()
		c.logger.Info("Software key provider initialised (HSM disabled)")
	}

	// Initialize key service with cache for invalidation on mutations.
	c.keyService = keyServices.NewKeyService(keyServices.KeyServiceConfig{
		KeyRepository: c.keyRepository,
		KeyProvider:   c.keyProvider,
		KeyCache:      c.keyCache,
		Logger:        c.logger,
	})

	// Initialize crypto service with cache and Prometheus metrics.
	c.keyCryptoService = keyServices.NewCryptoService(keyServices.CryptoServiceConfig{
		KeyRepository: c.keyRepository,
		KeyProvider:   c.keyProvider,
		KeyCache:      c.keyCache,
		CryptoMetrics: c.cryptoMetrics,
		Logger:        c.logger,
	})

	// Initialize certificate service
	c.certificateService = certServices.NewCertificateService(certServices.CertificateServiceConfig{
		CertificateRepository: c.certificateRepository,
		KeyRepository:         c.keyRepository,
		Logger:                c.logger,
	})

	// Initialize certificate renewal service.
	c.certRenewalService = certServices.NewCertificateRenewalService(certServices.RenewalServiceConfig{
		CertRepository:     c.certificateRepository,
		CertificateService: c.certificateService,
		Logger:             c.logger,
	})

	// Initialize per-item backup service.
	c.itemBackupService = backup.NewItemBackupService(
		c.secretRepository,
		c.keyRepository,
		c.certificateRepository,
	)

	return nil
}

// GetUserRepository returns the user repository.
func (c *ServiceContainer) GetUserRepository() repositories.UserRepositoryInterface {
	return c.userRepository
}

// GetSecretRepository returns the secret repository.
func (c *ServiceContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	return c.secretRepository
}

// GetPasswordService returns the password service.
func (c *ServiceContainer) GetPasswordService() authServices.PasswordService {
	return c.passwordService
}

// GetTOTPService returns the TOTP service.
func (c *ServiceContainer) GetTOTPService() authServices.TOTPService {
	return c.totpService
}

// GetJWTService returns the JWT service.
func (c *ServiceContainer) GetJWTService() authServices.JWTService {
	return c.jwtService
}

// GetAuthenticationService returns the authentication service.
func (c *ServiceContainer) GetAuthenticationService() authServices.AuthenticationService {
	return c.authenticationService
}

// GetRBACService returns the RBAC service.
func (c *ServiceContainer) GetRBACService() authzServices.RBACService {
	return c.rbacService
}

// GetAccessPolicyRepository returns the access policy repository.
func (c *ServiceContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	return c.accessPolicyRepository
}

// GetAccessPolicyService returns the access policy service.
func (c *ServiceContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	return c.accessPolicyService
}

// GetRoleAssignmentService returns the role assignment service.
func (c *ServiceContainer) GetRoleAssignmentService() authzServices.RoleAssignmentService {
	return c.roleAssignmentService
}

// GetOAuth2ClientRepository returns the OAuth2 client repository.
func (c *ServiceContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	return c.oauth2ClientRepository
}

// GetOAuth2Service returns the OAuth2 service for token issuance and service account management.
func (c *ServiceContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	return c.oauth2Service
}

// GetUserService returns the user service.
func (c *ServiceContainer) GetUserService() userServices.UserService {
	return c.userService
}

// GetSecretService returns the secret service.
func (c *ServiceContainer) GetSecretService() secretServices.SecretService {
	return c.secretService
}

// GetCryptographyService returns the cryptography service.
func (c *ServiceContainer) GetCryptographyService() secretServices.CryptographyService {
	return c.cryptoService
}

// GetVersioningService returns the versioning service.
func (c *ServiceContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	return c.versioningService
}

// GetTagService returns the tag service.
func (c *ServiceContainer) GetTagService() secretServices.TagService {
	return c.tagService
}

// GetRotationRepository returns the rotation policy repository.
func (c *ServiceContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	return c.rotationRepository
}

// GetVersionRepository returns the secret version repository.
func (c *ServiceContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	return c.versionRepository
}

// GetRotationService returns the rotation service.
func (c *ServiceContainer) GetRotationService() secretServices.RotationServiceInterface {
	return c.rotationService
}

// GetSchedulerService returns the scheduler service.
func (c *ServiceContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	return c.schedulerService
}

// GetDatabase returns the database connection.
func (c *ServiceContainer) GetDatabase() *sql.DB {
	return c.db
}

// GetLogger returns the logger.
func (c *ServiceContainer) GetLogger() *logging.Logger {
	return c.logger
}

// GetKeyRepository returns the key repository.
func (c *ServiceContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	return c.keyRepository
}

// GetCertificateRepository returns the certificate repository.
func (c *ServiceContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	return c.certificateRepository
}

// GetCertificatePolicyRepository returns the certificate policy repository.
func (c *ServiceContainer) GetCertificatePolicyRepository() repositories.CertificatePolicyRepositoryInterface {
	return c.certPolicyRepository
}

// GetVaultRepository returns the vault repository.
func (c *ServiceContainer) GetVaultRepository() repositories.VaultRepositoryInterface {
	return c.vaultRepository
}

// GetVaultService returns the vault lifecycle service.
func (c *ServiceContainer) GetVaultService() vaultServices.VaultService {
	return c.vaultService
}

// GetSessionRepository returns the session repository.
func (c *ServiceContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	return c.sessionRepository
}

// GetKeyService returns the key service.
func (c *ServiceContainer) GetKeyService() keyServices.KeyService {
	return c.keyService
}

// GetCertificateService returns the certificate service.
func (c *ServiceContainer) GetCertificateService() certServices.CertificateService {
	return c.certificateService
}

// GetCertificateRenewalService returns the certificate renewal service.
func (c *ServiceContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	return c.certRenewalService
}

// GetCryptoService returns the key crypto service for wrap/unwrap operations.
func (c *ServiceContainer) GetCryptoService() keyServices.CryptoService {
	return c.keyCryptoService
}

// GetSecretCache returns the secret cache (if enabled).
func (c *ServiceContainer) GetSecretCache() *cache.SecretCache {
	return c.secretCache
}

// GetCacheConfig returns the cache configuration.
func (c *ServiceContainer) GetCacheConfig() *cache.CacheConfig {
	return c.cacheConfig
}

// GetCachedSecretService returns the cached secret service (if caching is enabled).
func (c *ServiceContainer) GetCachedSecretService() secrets.SecretService {
	return c.cachedSecretService
}

// GetRetryService returns the retry service for handling retry logic.
func (c *ServiceContainer) GetRetryService() retryServices.RetryService {
	return c.retryService
}

// GetSigningProvider returns the JWT signing key provider.
func (c *ServiceContainer) GetSigningProvider() signing.SigningKeyProvider {
	return c.signingProvider
}

// GetItemBackupService returns the per-item backup service.
func (c *ServiceContainer) GetItemBackupService() *backup.ItemBackupService {
	return c.itemBackupService
}

// Close closes the service container and cleans up resources.
func (c *ServiceContainer) Close() error {
	// Cancel cache context to stop background operations.
	if c.cacheCancel != nil {
		c.cacheCancel()
	}

	// Stop the key cache background sweeper.
	if c.keyCache != nil {
		c.keyCache.Stop()
	}

	if c.keyProvider != nil {
		if err := c.keyProvider.Close(); err != nil {
			c.logger.WithError(err).Warn("Failed to close key provider")
		}
	}

	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// GetKeyProvider returns the active key provider (software or PKCS#11).
func (c *ServiceContainer) GetKeyProvider() crypto.KeyProvider {
	return c.keyProvider
}

// GetKeyCache returns the in-process key cache.
func (c *ServiceContainer) GetKeyCache() keycache.Cache {
	return c.keyCache
}

// GetCryptoMetrics returns the Prometheus crypto metrics recorder.
func (c *ServiceContainer) GetCryptoMetrics() metrics.CryptoMetrics {
	return c.cryptoMetrics
}

// GetAuditService returns the audit event write-path service.
func (c *ServiceContainer) GetAuditService() auditServices.AuditServiceInterface {
	return c.auditService
}

// GetComplianceReportService returns the compliance report read-path service.
func (c *ServiceContainer) GetComplianceReportService() auditServices.ComplianceReportServiceInterface {
	return c.complianceReportService
}
