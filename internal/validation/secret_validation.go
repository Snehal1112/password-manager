// Package validation provides input validation framework using ozzo-validation.
// It implements comprehensive validators for all domain entities with Azure Key Vault compatibility.
package validation

import (
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"

	"password-manager/internal/domain"
)

// SecretCreateRequest represents the input for creating a secret.
type SecretCreateRequest struct {
	Name      string
	Value     string
	Tags      []string
	ExpiresAt *time.Time
	NotBefore *time.Time
	Enabled   bool
}

// SecretUpdateRequest represents the input for updating a secret.
type SecretUpdateRequest struct {
	Name      *string
	Value     *string
	Tags      []string
	ExpiresAt *time.Time
	NotBefore *time.Time
	Enabled   *bool
}

// ValidateSecretCreate validates secret creation request.
func ValidateSecretCreate(req SecretCreateRequest) error {
	return validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.Required,
			validation.Length(1, 127),
			SecretNameRule(),
		),
		validation.Field(&req.Value,
			validation.Required,
			validation.Length(1, 25600), // 25KB max (Azure Key Vault limit)
		),
		validation.Field(&req.Tags,
			validation.Length(0, 15), // Max 15 tags (Azure Key Vault limit)
			validation.Each(validation.Length(1, 256)),
		),
		validation.Field(&req.ExpiresAt,
			validation.By(validateLifecycleTimestamps(req.NotBefore, req.ExpiresAt)),
		),
	)
}

// ValidateSecretUpdate validates secret update request.
func ValidateSecretUpdate(req SecretUpdateRequest) error {
	return validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.When(req.Name != nil,
				validation.Length(1, 127),
				SecretNameRule(),
			),
		),
		validation.Field(&req.Value,
			validation.When(req.Value != nil,
				validation.Required,
				validation.Length(1, 25600),
			),
		),
		validation.Field(&req.Tags,
			validation.Length(0, 15),
			validation.Each(validation.Length(1, 256)),
		),
		validation.Field(&req.ExpiresAt,
			validation.When(req.NotBefore != nil || req.ExpiresAt != nil,
				validation.By(validateLifecycleTimestamps(req.NotBefore, req.ExpiresAt)),
			),
		),
	)
}

// ValidateSecret validates a domain secret entity.
func ValidateSecret(secret *domain.Secret) error {
	return validation.ValidateStruct(secret,
		validation.Field(&secret.ID,
			validation.Required,
			validation.By(validateUUID(secret.ID)),
		),
		validation.Field(&secret.UserID,
			validation.Required,
			validation.By(validateUUID(secret.UserID)),
		),
		validation.Field(&secret.Name,
			validation.Required,
			validation.Length(1, 127),
			SecretNameRule(),
		),
		validation.Field(&secret.Value,
			validation.Required,
			validation.Length(1, 25600),
		),
		validation.Field(&secret.Tags,
			validation.Length(0, 15),
			validation.Each(validation.Length(1, 256)),
		),
		validation.Field(&secret.ExpiresAt,
			validation.By(validateLifecycleTimestamps(secret.NotBefore, secret.ExpiresAt)),
		),
	)
}

// SecretNameRule validates secret names according to Azure Key Vault pattern.
// Names must be alphanumeric with hyphens, starting with letter.
func SecretNameRule() validation.Rule {
	return validation.Match(SecretNamePattern).Error("must contain only alphanumeric characters and hyphens, and start with a letter")
}

// validateLifecycleTimestamps validates secret lifecycle timestamps.
func validateLifecycleTimestamps(notBefore, expiresAt *time.Time) validation.RuleFunc {
	return func(value interface{}) error {
		if notBefore == nil || expiresAt == nil {
			return nil
		}

		if notBefore.After(*expiresAt) {
			return validation.NewError("validation_lifecycle", "not_before must be before expires_at")
		}

		return nil
	}
}

// validateUUID validates that a UUID is not nil/zero.
func validateUUID(id uuid.UUID) validation.RuleFunc {
	return func(value interface{}) error {
		if id == uuid.Nil {
			return validation.NewError("validation_uuid", "ID cannot be nil or zero")
		}
		return nil
	}
}
