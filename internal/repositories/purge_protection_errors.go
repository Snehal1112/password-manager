package repositories

import "errors"

// ErrSecretPurgeProtected is returned when PurgeSecret refuses to act because
// the secret itself, or the vault containing it, has purge protection
// enabled.
var ErrSecretPurgeProtected = errors.New("secret has purge protection enabled")

// ErrKeyPurgeProtected is returned when PurgeKey refuses to act because the
// key itself, or the vault containing it, has purge protection enabled.
var ErrKeyPurgeProtected = errors.New("key has purge protection enabled")

// ErrCertPurgeProtected is returned when PurgeCertificate refuses to act
// because the certificate itself, or the vault containing it, has purge
// protection enabled.
var ErrCertPurgeProtected = errors.New("certificate has purge protection enabled")
