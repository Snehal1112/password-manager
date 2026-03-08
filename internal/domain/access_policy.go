package domain

import (
	"time"

	"github.com/google/uuid"
)

// PrincipalType identifies the kind of principal a policy applies to.
type PrincipalType string

const (
	PrincipalTypeUser           PrincipalType = "user"
	PrincipalTypeServiceAccount PrincipalType = "service_account"
)

// PolicyEffect is the result of a policy evaluation.
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

// PolicyResourceType is the resource category a policy covers.
type PolicyResourceType string

const (
	PolicyResourceSecrets      PolicyResourceType = "secrets"
	PolicyResourceKeys         PolicyResourceType = "keys"
	PolicyResourceCertificates PolicyResourceType = "certificates"
)

// PolicyOperation is the exact operation a policy grants or denies.
// The same operation name is shared across resource types; the resource type
// provides the disambiguation (e.g. "get" on "secrets" vs "get" on "keys").
type PolicyOperation string

const (
	OpGet     PolicyOperation = "get"
	OpList    PolicyOperation = "list"
	OpSet     PolicyOperation = "set"     // create / update a secret value
	OpCreate  PolicyOperation = "create"  // create a key or certificate
	OpDelete  PolicyOperation = "delete"
	OpBackup  PolicyOperation = "backup"
	OpRestore PolicyOperation = "restore"
	OpPurge   PolicyOperation = "purge"
	OpRecover PolicyOperation = "recover"
	OpRotate  PolicyOperation = "rotate"
	OpSign    PolicyOperation = "sign"
	OpVerify  PolicyOperation = "verify"
	OpEncrypt PolicyOperation = "encrypt"
	OpDecrypt PolicyOperation = "decrypt"
	OpImport  PolicyOperation = "import"
	OpRenew   PolicyOperation = "renew"
)

// AccessPolicy maps a principal to an allow/deny effect for one operation on one resource type.
type AccessPolicy struct {
	ID            uuid.UUID          `json:"id"`
	PrincipalID   uuid.UUID          `json:"principal_id"`
	PrincipalType PrincipalType      `json:"principal_type"`
	ResourceType  PolicyResourceType `json:"resource_type"`
	Operation     PolicyOperation    `json:"operation"`
	Effect        PolicyEffect       `json:"effect"`
	CreatedAt     time.Time          `json:"created_at"`
}
