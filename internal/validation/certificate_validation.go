package validation

import validation "github.com/go-ozzo/ozzo-validation/v4"

// CertificateCreateRequest is the input for creating a certificate.
type CertificateCreateRequest struct {
	Name string
	Tags []string
}

// ValidateCertificateCreate validates certificate creation input.
func ValidateCertificateCreate(req CertificateCreateRequest) error {
	return validation.ValidateStruct(&req,
		validation.Field(&req.Name,
			validation.Required,
			validation.Length(1, 127),
			CertificateNameRule(),
		),
		validation.Field(&req.Tags,
			validation.Length(0, 15),
			validation.Each(validation.Length(1, 256)),
		),
	)
}

// CertificateNameRule validates certificate names.
func CertificateNameRule() validation.Rule {
	return validation.Match(CertificateNamePattern).Error("must contain only alphanumeric characters and hyphens, and start with a letter")
}
