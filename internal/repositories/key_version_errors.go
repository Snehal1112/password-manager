package repositories

import "rocketvault/model"

// ErrKeyVersionNotFound is returned when a requested key version does not
// exist (or is not visible to the requesting owner). Propagates unwrapped to
// callers — same pattern as ErrKeyPurgeProtected in
// purge_protection_errors.go. Aliases model.ErrKeyVersionNotFound: the
// canonical value lives in model/ so api/ and cmd/ can check it without
// importing this package.
var ErrKeyVersionNotFound = model.ErrKeyVersionNotFound
