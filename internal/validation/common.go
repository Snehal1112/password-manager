package validation

import (
	"regexp"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

var (
	// SecretNamePattern is the Azure Key Vault compatible pattern for secret names.
	// Must be 1-127 characters, alphanumeric and hyphens only, start with letter.
	SecretNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,126}$`)

	// KeyNamePattern is the Azure Key Vault compatible pattern for key names.
	KeyNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,126}$`)

	// CertificateNamePattern is the Azure Key Vault compatible pattern for certificate names.
	CertificateNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,126}$`)

	// UsernamePattern for user validation.
	UsernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,32}$`)
)

// CommonValidationRules provides reusable validation rules.
type CommonValidationRules struct{}

// ValidateEmail validates email addresses.
func (c *CommonValidationRules) ValidateEmail(email string) error {
	return validation.Validate(email,
		validation.Required,
		is.Email,
		validation.Length(5, 254),
	)
}

// ValidateUsername validates usernames.
func (c *CommonValidationRules) ValidateUsername(username string) error {
	return validation.Validate(username,
		validation.Required,
		validation.Length(3, 32),
		validation.Match(UsernamePattern),
	)
}

// ValidatePassword validates password strength.
func (c *CommonValidationRules) ValidatePassword(password string) error {
	return validation.Validate(password,
		validation.Required,
		validation.Length(8, 128),
		validation.By(passwordStrengthRule),
	)
}

// ValidateTag validates individual tag values.
func (c *CommonValidationRules) ValidateTag(tag string) error {
	return validation.Validate(tag,
		validation.Required,
		validation.Length(1, 256),
	)
}

// ValidateTags validates a slice of tags.
func (c *CommonValidationRules) ValidateTags(tags []string) error {
	return validation.Validate(tags,
		validation.Length(0, 15),
		validation.Each(validation.Length(1, 256)),
	)
}

// passwordStrengthRule validates password complexity.
func passwordStrengthRule(value interface{}) error {
	password, ok := value.(string)
	if !ok {
		return validation.NewError("validation_password", "invalid password type")
	}

	var (
		hasUpper   = regexp.MustCompile(`[A-Z]`)
		hasLower   = regexp.MustCompile(`[a-z]`)
		hasNumber  = regexp.MustCompile(`[0-9]`)
		hasSpecial = regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`)
	)

	checks := 0
	if hasUpper.MatchString(password) {
		checks++
	}
	if hasLower.MatchString(password) {
		checks++
	}
	if hasNumber.MatchString(password) {
		checks++
	}
	if hasSpecial.MatchString(password) {
		checks++
	}

	if checks < 3 {
		return validation.NewError("validation_password", "password must contain at least 3 of: uppercase, lowercase, number, special character")
	}

	return nil
}
