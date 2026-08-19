package validation

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"rocketvault/model"
)

// KeyCreateRequest represents the input for creating a cryptographic key.
type KeyCreateRequest struct {
	Name  string
	Type  string // "RSA" or "ECDSA"
	Bits  int    // For RSA: 2048, 3072, or 4096
	Curve string // For ECDSA: P-256, P-384, P-521, P-256K
	Tags  []string
}

// KeyUpdateRequest represents the input for updating a key.
type KeyUpdateRequest struct {
	Name *string
	Tags []string
}

// ValidateKeyCreate validates key creation request.
func ValidateKeyCreate(req KeyCreateRequest) error {
	return validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.Required,
			validation.Length(1, 127),
			KeyNameRule(),
		),
		validation.Field(&req.Type,
			validation.Required,
			validation.In(model.KeyTypeRSA, model.KeyTypeECDSA, "OCT"),
		),
		validation.Field(&req.Bits,
			validation.When(req.Type == model.KeyTypeRSA,
				validation.Required,
				validation.In(2048, 3072, 4096),
			),
			validation.When(req.Type == "OCT",
				validation.Required,
				validation.In(128, 192, 256),
			),
		),
		validation.Field(&req.Curve,
			validation.When(req.Type == model.KeyTypeECDSA,
				validation.Required,
				validation.In("P-256", "P-384", "P-521", "P-256K"),
			),
		),
		validation.Field(&req.Tags,
			validation.Length(0, 15),
			validation.Each(validation.Length(1, 256)),
		),
	)
}

// ValidateKeyUpdate validates key update request.
func ValidateKeyUpdate(req KeyUpdateRequest) error {
	return validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.When(req.Name != nil,
				validation.Length(1, 127),
				KeyNameRule(),
			),
		),
		validation.Field(&req.Tags,
			validation.Length(0, 15),
			validation.Each(validation.Length(1, 256)),
		),
	)
}

// KeyRotationPolicyRequest represents the input for creating or updating a
// key's rotation policy.
type KeyRotationPolicyRequest struct {
	RotateAfterDays int
	Enabled         bool
}

// ValidateKeyRotationPolicy validates a rotation-policy upsert request. Azure
// enforces a 7-day minimum rotation interval; RocketVault mirrors it only
// when the policy is enabled, since a disabled policy never schedules a
// rotation and RotateAfterDays is inert -- 0/negative disabled values are
// how a policy is parked without deleting it.
//
// Uses validation.By rather than validation.Min: ozzo-validation's built-in
// threshold rules (Min/Max) skip validation entirely when the field holds
// its zero value, which would silently let RotateAfterDays: 0 -- the exact
// continuous-re-rotation case this validation exists to catch -- through.
func ValidateKeyRotationPolicy(req KeyRotationPolicyRequest) error {
	return validation.ValidateStruct(&req,
		validation.Field(&req.RotateAfterDays, validation.By(func(value any) error {
			days := value.(int)
			if req.Enabled && days < 7 {
				return fmt.Errorf("must be at least 7 when the policy is enabled")
			}
			return nil
		})),
	)
}

// ValidateKey validates a domain key entity.
func ValidateKey(key *model.Key) error {
	return validation.ValidateStruct(key,
		validation.Field(&key.ID,
			validation.Required,
			validation.By(validateUUID(key.ID)),
		),
		validation.Field(&key.UserID,
			validation.Required,
			validation.By(validateUUID(key.UserID)),
		),
		validation.Field(&key.Name,
			validation.Required,
			validation.Length(1, 127),
			KeyNameRule(),
		),
		validation.Field(&key.Type,
			validation.Required,
			validation.In(model.KeyTypeRSA, model.KeyTypeECDSA),
		),
		validation.Field(&key.Value,
			validation.Required,
		),
		validation.Field(&key.Tags,
			validation.Length(0, 15),
			validation.Each(validation.Length(1, 256)),
		),
	)
}

// KeyNameRule validates key names according to Azure Key Vault pattern.
func KeyNameRule() validation.Rule {
	return validation.Match(KeyNamePattern).Error("must contain only alphanumeric characters and hyphens, and start with a letter")
}
