package validation

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"

	"password-manager/internal/domain"
)

// KeyCreateRequest represents the input for creating a cryptographic key.
type KeyCreateRequest struct {
	Name  string
	Type  string // "RSA" or "ECDSA"
	Bits  int    // For RSA: 2048 or 4096
	Curve string // For ECDSA: P-256, P-384, P-521
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
			validation.In(domain.KeyTypeRSA, domain.KeyTypeECDSA),
		),
		validation.Field(&req.Bits,
			validation.When(req.Type == domain.KeyTypeRSA,
				validation.Required,
				validation.In(2048, 4096),
			),
		),
		validation.Field(&req.Curve,
			validation.When(req.Type == domain.KeyTypeECDSA,
				validation.Required,
				validation.In("P-256", "P-384", "P-521"),
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

// ValidateKey validates a domain key entity.
func ValidateKey(key *domain.Key) error {
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
			validation.In(domain.KeyTypeRSA, domain.KeyTypeECDSA),
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
