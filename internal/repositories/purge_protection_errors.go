package repositories

import "rocketvault/model"

// ErrSecretPurgeProtected is returned when PurgeSecret refuses to act because
// the secret itself, or the vault containing it, has purge protection
// enabled. Aliases model.ErrSecretPurgeProtected: the canonical value lives
// in model/ so api/ and cmd/ can check it without importing this package.
var ErrSecretPurgeProtected = model.ErrSecretPurgeProtected

// ErrKeyPurgeProtected is returned when PurgeKey refuses to act because the
// key itself, or the vault containing it, has purge protection enabled.
// Aliases model.ErrKeyPurgeProtected.
var ErrKeyPurgeProtected = model.ErrKeyPurgeProtected

// ErrCertPurgeProtected is returned when PurgeCertificate refuses to act
// because the certificate itself, or the vault containing it, has purge
// protection enabled. Aliases model.ErrCertPurgeProtected.
var ErrCertPurgeProtected = model.ErrCertPurgeProtected

// ErrGlobalPurgeProtectionEnabled is returned when a purge operation refuses
// to act because the instance-wide soft_delete.purge_protection switch is
// enabled. Aliases model.ErrGlobalPurgeProtectionEnabled.
var ErrGlobalPurgeProtectionEnabled = model.ErrGlobalPurgeProtectionEnabled
