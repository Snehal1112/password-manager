package api

import (
	"errors"

	"rocketvault/internal/repositories"
	certServices "rocketvault/internal/services/certificates"
)

// writeCertificateError maps a certificate-service error onto an HTTP response.
//
// It mirrors writeSecretError and writeKeyError so every certificate handler
// agrees on the mapping. A lifecycle denial is a 403, not a 500:
// updateCertificate reads the certificate back after a successful update, and
// that read-back legitimately hits ErrCertLifecycleDenied when the update
// disabled the certificate or the certificate has expired. That is a state
// condition, not a server fault.
func writeCertificateError(c *Context, err error) {
	switch {
	case errors.Is(err, certServices.ErrCertLifecycleDenied):
		c.SetPermissionError("certificate is disabled or outside its valid time window")
	case errors.Is(err, certServices.ErrCertNotFound):
		c.SetNotFound("certificate")
	case errors.Is(err, repositories.ErrCertPurgeProtected):
		c.SetPermissionError("certificate has purge protection enabled")
	default:
		c.SetInternalError(err)
	}
}
