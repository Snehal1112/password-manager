// Package container provides dependency injection for the password manager.
// It manages service creation and lifecycle, ensuring proper dependency
// resolution and eliminating global state dependencies.
package container

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/spf13/viper"

	"password-manager/internal/certificates"
	"password-manager/internal/keys"
	"password-manager/internal/logging"
	"password-manager/internal/repositories"
	authServices "password-manager/internal/services/auth"
	authzServices "password-manager/internal/services/authorization"
	certServices "password-manager/internal/services/certificates"
	keyServices "password-manager/internal/services/keys"
	secretServices "password-manager/internal/services/secrets"
	userServices "password-manager/internal/services/users"
)

// ServiceContainer manages all application services and their dependencies.
// It provides a centralized way to create and inject dependencies,
// replacing global variables with proper dependency injection.
type ServiceContainer struct {
	// Core infrastructure
	db     *sql.DB
	logger *logging.Logger

	// Repositories
	userRepository         repositories.UserRepositoryInterface
	secretRepository       repositories.SecretRepositoryInterface
	rotationRepository     repositories.RotationPolicyRepositoryInterface
	versionRepository      repositories.SecretVersionRepositoryInterface
	keyRepository          keys.KeyRepository
	certificateRepository  certificates.CertificateRepository

	// Authentication services
	passwordService      authServices.PasswordService
	totpService          authServices.TOTPService
	jwtService           authServices.JWTService
	authenticationService authServices.AuthenticationService

	// Authorization services
	rbacService authzServices.RBACService

	// Business services
	userService         userServices.UserService
	secretService       secretServices.SecretService
	keyService          keyServices.KeyService
	certificateService  certServices.CertificateService

	// Secret component services
	cryptoService         secretServices.CryptographyService
	versioningService     secretServices.VersioningServiceInterface
	tagService            secretServices.TagService
	rotationService       secretServices.RotationServiceInterface
	schedulerService      secretServices.SchedulerServiceInterface
}

// Config holds configuration for the service container.
type Config struct {
	Database *sql.DB
	Logger   *logging.Logger
}

// NewServiceContainer creates a new service container with the provided configuration.
// It initializes all services and their dependencies in the correct order.
//
// Parameters:
//   config: Configuration containing database and logger.
//
// Returns:
//   A ServiceContainer with all services properly initialized.
func NewServiceContainer(config Config) (*ServiceContainer, error) {
	container := &ServiceContainer{
		db:     config.Database,
		logger: config.Logger,
	}

	if err := container.initializeServices(); err != nil {
		return nil, fmt.Errorf("failed to initialize services: %w", err)
	}

	return container, nil
}

// initializeServices creates and wires all services in dependency order.
func (c *ServiceContainer) initializeServices() error {
	// Initialize repositories (data layer)
	c.userRepository = repositories.NewUserRepository(c.db, c.logger)
	c.secretRepository = repositories.NewSecretRepository(c.db, c.logger)
	c.rotationRepository = repositories.NewRotationPolicyRepository(c.db, c.logger)
	c.versionRepository = repositories.NewSecretVersionRepository(c.db, c.logger)
	c.keyRepository = keys.NewKeyRepository(c.db, c.logger)
	c.certificateRepository = certificates.NewCertificateRepository(c.db, c.logger)

	// Initialize authentication services
	c.passwordService = authServices.NewPasswordService()
	c.totpService = authServices.NewTOTPService()

	// Initialize JWT service with configuration
	jwtConfig := authServices.JWTConfig{
		SecretKey: viper.GetString("jwt_secret"),
		Issuer:    "PasswordManager",
		Audience:  "PASSWORD_MANAGER",
		Expiry:    time.Hour, // 1 hour expiration
	}
	if jwtConfig.SecretKey == "" {
		return fmt.Errorf("JWT secret not configured")
	}
	c.jwtService = authServices.NewJWTService(jwtConfig)

	// Initialize authentication service
	c.authenticationService = authServices.NewAuthenticationService(authServices.AuthenticationConfig{
		UserRepository:  c.userRepository,
		PasswordService: c.passwordService,
		TOTPService:     c.totpService,
		JWTService:      c.jwtService,
		Logger:          c.logger,
	})

	// Initialize authorization services
	c.rbacService = authzServices.NewRBACService(c.logger)

	// Initialize user service
	c.userService = userServices.NewUserService(userServices.UserServiceConfig{
		UserRepository:  c.userRepository,
		PasswordService: c.passwordService,
		TOTPService:     c.totpService,
		Logger:          c.logger,
	})

	// Initialize secret component services
	c.cryptoService = secretServices.NewCryptographyService()
	c.versioningService = secretServices.NewVersioningService(
		c.versionRepository,
		c.secretRepository,
		c.userRepository,
		c.cryptoService,
		c.logger,
	)
	c.tagService = secretServices.NewTagService(c.db, c.logger)
	c.rotationService = secretServices.NewRotationService(
		c.rotationRepository,
		c.secretRepository,
		c.userRepository,
		c.cryptoService,
		c.logger,
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
	c.secretService = secretServices.NewSecretService(secretServices.SecretServiceConfig{
		SecretRepository: c.secretRepository,
		CryptoService:    c.cryptoService,
		VersionService:   c.versioningService,
		TagService:       c.tagService,
		Logger:           c.logger,
	})

	// Initialize key service
	c.keyService = keyServices.NewKeyService(keyServices.KeyServiceConfig{
		KeyRepository: c.keyRepository,
		Logger:        c.logger,
	})

	// Initialize certificate service
	c.certificateService = certServices.NewCertificateService(certServices.CertificateServiceConfig{
		CertificateRepository: c.certificateRepository,
		KeyRepository:         c.keyRepository,
		Logger:                c.logger,
	})

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
func (c *ServiceContainer) GetKeyRepository() keys.KeyRepository {
	return c.keyRepository
}

// GetCertificateRepository returns the certificate repository.
func (c *ServiceContainer) GetCertificateRepository() certificates.CertificateRepository {
	return c.certificateRepository
}

// GetKeyService returns the key service.
func (c *ServiceContainer) GetKeyService() keyServices.KeyService {
	return c.keyService
}

// GetCertificateService returns the certificate service.
func (c *ServiceContainer) GetCertificateService() certServices.CertificateService {
	return c.certificateService
}

// Close closes the service container and cleans up resources.
func (c *ServiceContainer) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}