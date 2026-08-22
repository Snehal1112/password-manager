package repositories

import "errors"

// ErrNameTaken is returned when creating a resource whose name collides
// with an active resource of the same type in the same vault. It wraps the
// underlying driver's unique-constraint error (see db.Dialect.IsConstraintErr)
// so callers get a clear, dialect-agnostic reason instead of a raw SQL error.
var ErrNameTaken = errors.New("a resource with this name already exists in this vault")
