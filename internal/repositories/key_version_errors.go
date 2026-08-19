package repositories

import "errors"

// ErrKeyVersionNotFound is returned when a requested key version does not
// exist (or is not visible to the requesting owner). Propagates unwrapped to
// callers — same pattern as ErrKeyPurgeProtected in
// purge_protection_errors.go.
var ErrKeyVersionNotFound = errors.New("key version not found")
