package repositories

import (
	"errors"
	"fmt"

	"rocketvault/model"
)

// ErrInvalidScope is returned when a repository receives a scope it cannot
// turn into a SQL predicate. It is a programming error, never reachable from a
// well-formed request, and surfaces to clients as a 500.
var ErrInvalidScope = errors.New("invalid authorization scope")

// scopePredicate turns an authorization scope into a SQL fragment plus its bind
// arguments. Each fragment is a compile-time constant; every caller-supplied
// value travels as a "?" placeholder, so nothing is ever interpolated.
//
// ScopeOwner deliberately does not constrain vault_id: the legacy owner-keyed
// read and user-keyed list methods never filtered by vault, and tightening
// that here would be a behavioral change smuggled into a refactor. P2 retires
// ScopeOwner entirely.
func scopePredicate(scope model.Scope) (string, []any, error) {
	if err := scope.Validate(); err != nil {
		return "", nil, fmt.Errorf("%w: %s", ErrInvalidScope, err.Error())
	}

	switch scope.Kind() {
	case model.ScopeVault:
		return "vault_id = ?", []any{scope.VaultID().String()}, nil
	case model.ScopeOwner:
		ownerID, ok := scope.OwnerID()
		if !ok {
			return "", nil, fmt.Errorf("%w: owner scope without an owner", ErrInvalidScope)
		}
		return "user_id = ?", []any{ownerID.String()}, nil
	case model.ScopeAdmin:
		return "1 = 1", nil, nil
	default:
		return "", nil, fmt.Errorf("%w: unknown scope kind %d", ErrInvalidScope, scope.Kind())
	}
}
