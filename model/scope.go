package model

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ScopeKind identifies how a resource operation is authorized. Its zero value
// is deliberately invalid so an uninitialised Scope fails closed.
type ScopeKind uint8

const (
	ScopeInvalid ScopeKind = iota // Zero value. Repositories reject it.
	ScopeVault                    // Any member of the vault may act.
	ScopeOwner                    // Restricted to the owner. P1 only; retired in P2.
	ScopeAdmin                    // No predicate. Trusted internal callers only.
)

// ErrScopeInvalid is returned by Validate when a scope cannot authorize an
// operation. Reaching it from a request path is a programming error.
var ErrScopeInvalid = errors.New("model: invalid authorization scope")

// Scope is the authorization scope of a single resource operation. It replaces
// the *InVault and *ByOwner method pairs: the scope travels as a value instead
// of being encoded in the method name. Every field is unexported so the only
// way to build one is through a constructor that sets a valid kind.
type Scope struct {
	kind    ScopeKind
	vaultID uuid.UUID // Set for ScopeVault; advisory for ScopeOwner.
	ownerID uuid.UUID // Set for ScopeOwner only.
	actorID uuid.UUID // The acting principal, for audit. Never an access predicate.
}

// NewVaultScope authorizes an operation for any member of vaultID, acted on by
// actorID. The actor is recorded for audit and is never an access predicate.
func NewVaultScope(vaultID, actorID uuid.UUID) Scope {
	return Scope{kind: ScopeVault, vaultID: vaultID, actorID: actorID}
}

// NewOwnerScope restricts an operation to the resource owner. vaultID is
// advisory: owner-scoped queries never constrain vault_id, matching the
// pre-refactor behaviour of ReadByOwner and ListByUser.
func NewOwnerScope(vaultID, ownerID uuid.UUID) Scope {
	return Scope{kind: ScopeOwner, vaultID: vaultID, ownerID: ownerID, actorID: ownerID}
}

// NewAdminScope authorizes an operation with no access predicate. It is for
// trusted internal callers only: the vault cascade, backup/restore, and the
// rotation scheduler.
func NewAdminScope(actorID uuid.UUID) Scope {
	return Scope{kind: ScopeAdmin, actorID: actorID}
}

// Kind returns the scope kind.
func (s Scope) Kind() ScopeKind { return s.kind }

// VaultID returns the vault the scope refers to, or uuid.Nil when it has none.
func (s Scope) VaultID() uuid.UUID { return s.vaultID }

// ActorID returns the acting principal, for audit attribution.
func (s Scope) ActorID() uuid.UUID { return s.actorID }

// OwnerID returns the owner and true only when the scope is owner-scoped.
// It never overloads uuid.Nil as "no check".
func (s Scope) OwnerID() (uuid.UUID, bool) {
	if s.kind != ScopeOwner {
		return uuid.Nil, false
	}
	return s.ownerID, true
}

// ResolvedVaultID returns the scope's vault, falling back to the well-known
// default vault so legacy flat routes keep targeting it.
func (s Scope) ResolvedVaultID() uuid.UUID {
	if s.vaultID == uuid.Nil {
		return uuid.MustParse(DefaultVaultID)
	}
	return s.vaultID
}

// Validate reports whether the scope can authorize an operation. Every
// repository entry point calls it before building a query.
func (s Scope) Validate() error {
	switch s.kind {
	case ScopeVault:
		if s.vaultID == uuid.Nil {
			return fmt.Errorf("%w: vault scope requires a vault id", ErrScopeInvalid)
		}
		return nil
	case ScopeOwner:
		if s.ownerID == uuid.Nil {
			return fmt.Errorf("%w: owner scope requires an owner id", ErrScopeInvalid)
		}
		return nil
	case ScopeAdmin:
		return nil
	default:
		return fmt.Errorf("%w: uninitialised scope", ErrScopeInvalid)
	}
}

// String renders the scope for logs. It never contains secret material.
func (s Scope) String() string {
	switch s.kind {
	case ScopeVault:
		return "vault(" + s.vaultID.String() + ")"
	case ScopeOwner:
		return "owner(" + s.ownerID.String() + ")"
	case ScopeAdmin:
		return "admin(" + s.actorID.String() + ")"
	default:
		return "invalid"
	}
}
