package model

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrInvalidQuota is returned when a grant's quota is not a positive count.
var ErrInvalidQuota = errors.New("quota must be greater than zero")

// ErrInvalidPrincipal is returned when a grant names no principal.
var ErrInvalidPrincipal = errors.New("principal_id is required")

// VaultProvisioningGrant is a bounded right to create vaults. It is the
// delegated alternative to a global vaults:manage grant, which additionally
// confers authority over every vault that already exists.
//
// PrincipalID is deliberately not constrained to a users row: a grantee may
// be an OAuth2 service account, which is how an MSP's automation
// authenticates.
type VaultProvisioningGrant struct {
	ID          uuid.UUID `json:"id"`
	PrincipalID uuid.UUID `json:"principal_id"`
	// Quota is the maximum number of vaults this principal may have created
	// and not yet purged. Soft-deleted vaults still count -- see the design
	// doc's §5 for why.
	Quota     int       `json:"quota"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy uuid.UUID `json:"created_by"`
}

// Validate reports whether the grant is well formed.
func (g *VaultProvisioningGrant) Validate() error {
	if g.PrincipalID == uuid.Nil {
		return ErrInvalidPrincipal
	}
	if g.Quota <= 0 {
		return ErrInvalidQuota
	}
	return nil
}
