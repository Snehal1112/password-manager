// Package config provides secret reference resolution for configuration files.
// It enables referencing secrets from the password manager using vault:// URLs.
package config

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"password-manager/internal/domain"
	"password-manager/internal/services/secrets"
)

// SecretResolver resolves secret references in configuration files.
// It supports vault:// URLs and provides secure secret injection.
type SecretResolver struct {
	secretService secrets.SecretService
	userID        uuid.UUID
	logger        *logrus.Logger
}

// NewSecretResolver creates a new secret resolver with the specified service and user.
func NewSecretResolver(secretService secrets.SecretService, userID uuid.UUID, logger *logrus.Logger) *SecretResolver {
	return &SecretResolver{
		secretService: secretService,
		userID:        userID,
		logger:        logger,
	}
}

// ResolveSecretReference resolves a secret reference and returns the actual secret value.
// Supports formats:
// - vault://secret-name - References a secret by name
// - vault://secret-id - References a secret by ID
// - plain-text - Returns the value as-is (not a reference)
func (r *SecretResolver) ResolveSecretReference(ctx context.Context, reference string) (string, error) {
	// Check if this is a vault reference
	if !strings.HasPrefix(reference, "vault://") {
		// Not a vault reference, return as-is
		return reference, nil
	}

	// Extract the secret identifier
	secretRef := strings.TrimPrefix(reference, "vault://")
	secretRef = strings.TrimSpace(secretRef)

	if secretRef == "" {
		return "", fmt.Errorf("empty vault reference")
	}

	r.logger.WithFields(logrus.Fields{
		"reference": reference,
		"user_id":   r.userID,
	}).Debug("Resolving vault secret reference")

	// Try to resolve by name first, then by ID
	secret, err := r.resolveByName(ctx, secretRef)
	if err != nil {
		// Try to resolve by ID
		secret, err = r.resolveByID(ctx, secretRef)
		if err != nil {
			return "", fmt.Errorf("failed to resolve vault reference %s: %w", reference, err)
		}
	}

	// Check if secret is deleted
	if secret.DeletedAt != nil {
		return "", fmt.Errorf("cannot reference deleted secret: %s", secretRef)
	}

	r.logger.WithFields(logrus.Fields{
		"secret_id": secret.ID,
		"secret_name": secret.Name,
	}).Debug("Secret reference resolved successfully")

	return secret.Value, nil
}

// resolveByName attempts to resolve a secret by its name.
func (r *SecretResolver) resolveByName(ctx context.Context, name string) (*domain.Secret, error) {
	// List all secrets for the user and find by name
	secretList, err := r.secretService.ListSecrets(ctx, r.userID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secretList {
		if secret.Name == name {
			return &secret, nil
		}
	}

	return nil, fmt.Errorf("secret not found by name: %s", name)
}

// resolveByID attempts to resolve a secret by its ID.
func (r *SecretResolver) resolveByID(ctx context.Context, idStr string) (*domain.Secret, error) {
	secretID, err := uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("invalid secret ID format: %w", err)
	}

	secret, err := r.secretService.GetSecret(ctx, secretID, r.userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret by ID: %w", err)
	}

	return secret, nil
}

// ResolveConfigMap resolves all vault references in a configuration map.
func (r *SecretResolver) ResolveConfigMap(ctx context.Context, config map[string]string) (map[string]string, error) {
	resolved := make(map[string]string)

	for key, value := range config {
		resolvedValue, err := r.ResolveSecretReference(ctx, value)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve config key %s: %w", key, err)
		}
		resolved[key] = resolvedValue
	}

	return resolved, nil
}

// ValidateSecretReference validates that a secret reference is well-formed.
func (r *SecretResolver) ValidateSecretReference(reference string) error {
	if !strings.HasPrefix(reference, "vault://") {
		return nil // Not a vault reference, valid
	}

	secretRef := strings.TrimPrefix(reference, "vault://")
	secretRef = strings.TrimSpace(secretRef)

	if secretRef == "" {
		return fmt.Errorf("empty vault reference")
	}

	return nil
}

// GetSupportedFormats returns the supported secret reference formats.
func (r *SecretResolver) GetSupportedFormats() []string {
	return []string{
		"vault://secret-name",
		"vault://secret-id",
		"plain-text (not a reference)",
	}
}

// Example usage in configuration:
// database:
//   password: vault://database-password
//   api_key: vault://external-api-key
//   host: db.example.com (plain text, not a reference)

// Environment variable support:
// DATABASE_PASSWORD=vault://database-password
// API_KEY=vault://external-api-key
// HOST=db.example.com (plain text, not a reference)

// Configuration file support:
// {
//   "database": {
//     "password": "vault://database-password",
//     "host": "db.example.com"
//   }
// }