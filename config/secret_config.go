// Package config provides configuration management with secret reference resolution.
package config

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"password-manager/internal/config"
	"password-manager/internal/services/secrets"
)

// SecretConfigResolver provides configuration resolution with secret reference support.
// It integrates with the secret resolver to automatically resolve vault:// references
// in configuration files and environment variables.
type SecretConfigResolver struct {
	secretResolver *config.SecretResolver
	viper          *viper.Viper
	logger         *logrus.Logger
}

// SecretConfigResolverConfig contains configuration for the secret config resolver.
type SecretConfigResolverConfig struct {
	SecretService secrets.SecretService
	UserID        string // User ID for secret resolution
	Logger        *logrus.Logger
	Viper         *viper.Viper
}

// NewSecretConfigResolver creates a new secret configuration resolver.
func NewSecretConfigResolver(cfg SecretConfigResolverConfig) (*SecretConfigResolver, error) {
	if cfg.SecretService == nil {
		return nil, fmt.Errorf("secret service is required")
	}
	if cfg.Viper == nil {
		return nil, fmt.Errorf("viper instance is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Parse user ID
	userID, err := parseUserID(cfg.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Create secret resolver
	secretResolver := config.NewSecretResolver(cfg.SecretService, uuid.MustParse(userID.(string)), cfg.Logger)

	return &SecretConfigResolver{
		secretResolver: secretResolver,
		viper:          cfg.Viper,
		logger:         cfg.Logger,
	}, nil
}

// ResolveConfig resolves all vault:// references in the current configuration.
func (r *SecretConfigResolver) ResolveConfig(ctx context.Context) error {
	r.logger.Debug("Resolving secret references in configuration")

	// Get all configuration keys
	allKeys := r.viper.AllKeys()

	for _, key := range allKeys {
		value := r.viper.GetString(key)
		if value == "" {
			continue
		}

		// Check if this is a vault reference
		if !strings.HasPrefix(value, "vault://") {
			continue
		}

		// Resolve the secret reference
		resolvedValue, err := r.secretResolver.ResolveSecretReference(ctx, value)
		if err != nil {
			r.logger.WithError(err).WithField("key", key).Warn("Failed to resolve secret reference")
			// Continue with other keys, don't fail the entire operation
			continue
		}

		// Update the configuration with the resolved value
		r.viper.Set(key, resolvedValue)
		r.logger.WithField("key", key).Debug("Resolved secret reference")
	}

	return nil
}

// ResolveEnvironmentVariables resolves vault:// references in environment variables.
func (r *SecretConfigResolver) ResolveEnvironmentVariables(ctx context.Context) error {
	r.logger.Debug("Resolving secret references in environment variables")

	envVars := os.Environ()
	for _, envVar := range envVars {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		// Check if this is a vault reference
		if !strings.HasPrefix(value, "vault://") {
			continue
		}

		// Resolve the secret reference
		resolvedValue, err := r.secretResolver.ResolveSecretReference(ctx, value)
		if err != nil {
			r.logger.WithError(err).WithField("env_var", key).Warn("Failed to resolve environment variable secret reference")
			// Continue with other variables, don't fail the entire operation
			continue
		}

		// Update the environment variable
		if err := os.Setenv(key, resolvedValue); err != nil {
			r.logger.WithError(err).WithField("env_var", key).Warn("Failed to set resolved environment variable")
			continue
		}

		r.logger.WithField("env_var", key).Debug("Resolved environment variable secret reference")
	}

	return nil
}

// GetSecretResolver returns the underlying secret resolver.
func (r *SecretConfigResolver) GetSecretResolver() *config.SecretResolver {
	return r.secretResolver
}

// GetSupportedFormats returns the supported secret reference formats.
func (r *SecretConfigResolver) GetSupportedFormats() []string {
	return r.secretResolver.GetSupportedFormats()
}

// ValidateSecretReference validates a secret reference.
func (r *SecretConfigResolver) ValidateSecretReference(reference string) error {
	return r.secretResolver.ValidateSecretReference(reference)
}

// parseUserID parses a user ID string into a UUID.
func parseUserID(userID string) (interface{}, error) {
	// This is a simplified version - in a real implementation,
	// you would parse this into the actual UUID type used by your application
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}
	return userID, nil
}

// Example usage:
//
// // In your application initialization:
// resolver, err := NewSecretConfigResolver(SecretConfigResolverConfig{
//     SecretService: container.GetSecretService(),
//     UserID:        "current-user-id",
//     Logger:        logger,
//     Viper:         viper.GetViper(),
// })
// if err != nil {
//     return err
// }
//
// // Resolve configuration secrets
// if err := resolver.ResolveConfig(ctx); err != nil {
//     return err
// }
//
// // Resolve environment variable secrets
// if err := resolver.ResolveEnvironmentVariables(ctx); err != nil {
//     return err
// }
