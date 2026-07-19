package repositories

import "errors"

// ErrNotFound is returned (wrapped with %w) by repository Read/ReadBy*
// methods when no row matches the lookup. Callers must use errors.Is against
// this sentinel rather than comparing error strings — see
// role_assignment_repository.go's FindByTuple for the fragile pattern this
// sentinel replaces (not fixed by this change; kept as a documented example).
var ErrNotFound = errors.New("repository: not found")
