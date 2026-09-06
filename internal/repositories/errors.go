package repositories

import "errors"

// ErrNotFound is returned (wrapped with %w) by repository Read/ReadBy*
// methods when no row matches the lookup. Callers must use errors.Is against
// this sentinel rather than comparing error strings — see
// role_assignment_repository.go's FindByTuple, which used to identify a miss
// by comparing err.Error() to a literal string and now wraps this sentinel
// instead (commit 5b1f54a); the surrounding package was swept for the same
// fragile pattern in commits 3107a85 and c574c42.
var ErrNotFound = errors.New("repository: not found")
