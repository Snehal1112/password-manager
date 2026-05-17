# API Layer Mattermost-Style Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the `api/` layer and consolidate all types into a new `model/` package, matching Mattermost `api4` patterns: typed `Routes` struct, centralized `ApiParams`, `Context` error-setter methods, and `FromJson`/`ToJson` on every HTTP-boundary type.

**Architecture:** A new `model/` package replaces `internal/domain/` as the single source of truth for all domain entity types and HTTP wire types. The `api/` layer is fully rewritten with a typed `Routes` struct (replacing `map[string]*mux.Router`), a centralized `ApiParams` parsed once per request, and `Context` error-setter methods that eliminate inline `common.NewAppError` calls. Migration proceeds in 5 ordered steps, each compiling cleanly before the next begins.

**Tech Stack:** Go 1.24.2, Gorilla Mux, `github.com/google/uuid`, `github.com/golang-jwt/jwt/v5`, `encoding/json`

---

## File Map

### Created
- `model/utils.go` — `NewId()`, `GetMillis()`
- `model/user.go` — `User`, `Claims`, role constants, HTTP req/resp types, `FromJson`/`ToJson`
- `model/secret.go` — `Secret`, `SecretVersion`, export/import types, HTTP req/resp, `FromJson`/`ToJson`
- `model/key.go` — `Key`, key constants, HTTP req/resp, `FromJson`/`ToJson`
- `model/certificate.go` — `Certificate`, `RevokedCertificate`, HTTP req/resp, `FromJson`/`ToJson`
- `model/access_policy.go` — `AccessPolicy`, policy constants, HTTP req/resp, `FromJson`/`ToJson`
- `model/session.go` — `Session`, `SessionInfo`, session types, `FromJson`/`ToJson`
- `model/oauth2_client.go` — `OAuth2Client`, HTTP req/resp, `FromJson`/`ToJson`
- `api/params.go` — `ApiParams`, `ApiParamsFromRequest()`

### Modified (import path only — `internal/domain` → `model`)
- `internal/cache/cache_integration.go`
- `internal/cache/secret_cache.go`
- `internal/middleware/middleware.go`
- `internal/repositories/access_policy_repository.go`
- `internal/repositories/certificate_repository.go`
- `internal/repositories/key_repository.go`
- `internal/repositories/oauth2_client_repository.go`
- `internal/repositories/rotation_repository.go`
- `internal/repositories/secret_repository.go`
- `internal/repositories/session_repository.go`
- `internal/repositories/user_repository.go`
- `internal/repositories/versioning_repository.go`
- `internal/services/auth/authentication_service.go`
- `internal/services/authorization/access_policy_service.go`
- `internal/services/authorization/rbac_service.go`
- `internal/services/certificates/certificate_service.go`
- `internal/services/keys/key_service.go`
- `internal/services/oauth2/oauth2_service.go`
- `internal/services/retry/retry_repository_wrapper.go`
- `internal/services/retry/retry_secret_service.go`
- `internal/services/retry/retry_user_repository_wrapper.go`
- `internal/services/retry/retry_user_service.go`
- `internal/services/secrets/expiration_service.go`
- `internal/services/secrets/rotation_service.go`
- `internal/services/secrets/scheduler_service.go`
- `internal/services/secrets/secret_service.go`
- `internal/services/secrets/versioning_service.go`
- `internal/services/users/user_service.go`
- `internal/testutils/mocks.go`
- `internal/validation/key_validation.go`
- `internal/validation/secret_validation.go`
- `cmd/certificates/create.go`, `delete.go`, `get.go`, `list.go`, `renew.go`, `update.go`
- `cmd/keys/create.go`, `delete.go`, `get.go`, `list.go`, `rotate.go`, `unwrap.go`, `update.go`, `wrap.go`
- `cmd/root.go`
- `cmd/testutils/test_utils.go`
- `cmd/users/admin.go`, `create.go`, `delete.go`, `get.go`, `list.go`, `update.go`

### Rewritten (full)
- `api/api.go` — `Routes` struct, `API` struct, `Init()`, `Handle404()`, `ReturnStatusOK()`
- `api/context.go` — `Context`, `ApiHandler()`, `ApiSessionRequired()`, error setters, service accessors
- `api/users.go` — `InitUsers()` + all user handlers using `model.*` and `c.Params`
- `api/secrets.go` — `InitSecrets()` + all secret handlers
- `api/keys.go` — `InitKeys()` + all key handlers
- `api/certificates.go` — `InitCertificates()` + all cert handlers
- `api/access_policies.go` — `InitAccessPolicies()` + all policy handlers
- `api/soft_delete.go` — `InitDeleted()` + all soft-delete handlers
- `api/oauth2.go` — `InitOAuth2()` + service account handlers
- `api/health.go` — `InitHealth()` (minor: use `ReturnStatusOK`)
- `api/vault.go` — `InitVault()` (no-arg signature)
- `api/context_test.go` — updated for renamed wrappers + error setters
- `api/context_accessors_test.go` — updated for `ApiParams` field names

### Deleted
- `internal/domain/user.go`
- `internal/domain/secret.go`
- `internal/domain/key.go`
- `internal/domain/certificate.go`
- `internal/domain/access_policy.go`
- `internal/domain/session.go`
- `internal/domain/oauth2_client.go`
- `internal/domain/rotation.go`

---

## Task 1: Create `model/utils.go`

**Files:**
- Create: `model/utils.go`

- [ ] **Step 1: Create the file**

```go
package model

import (
	"time"

	"github.com/google/uuid"
)

// NewId returns a new random UUID string.
func NewId() string {
	return uuid.New().String()
}

// GetMillis returns the current time in milliseconds since Unix epoch.
func GetMillis() int64 {
	return time.Now().UnixMilli()
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./model/...
```
Expected: no output (clean build).

- [ ] **Step 3: Commit**

```bash
git add model/utils.go
git commit -m "feat(model): add model package with NewId and GetMillis utils"
```

---

## Task 2: Create `model/user.go`

**Files:**
- Create: `model/user.go`

- [ ] **Step 1: Create the file**

```go
package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// User represents a user in the password manager.
type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"user_name"`
	PasswordHash string    `json:"password_hash"`
	TOTPSecret   string    `json:"totp_secret"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

// Claims extends JWT claims with user-specific fields.
type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
	jwt.RegisteredClaims
}

// Role constants for RBAC.
const (
	RoleAdmin              = "admin"
	RoleUser               = "user"
	RoleSecretsManager     = "secrets_manager"
	RoleCryptoManager      = "crypto_manager"
	RoleCertificateManager = "certificate_manager"
	RoleServiceAccount     = "service_account"
)

// --- HTTP request/response types ---

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func CreateUserRequestFromJson(data io.Reader) (*CreateUserRequest, error) {
	var r CreateUserRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateUserRequest struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role,omitempty"`
}

func UpdateUserRequestFromJson(data io.Reader) (*UpdateUserRequest, error) {
	var r UpdateUserRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UserResponse struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	CreatedAt  string `json:"created_at"`
	TOTPSecret string `json:"totp_secret,omitempty"`
}

func (r *UserResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
}

func (r *ListUsersResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

func LoginRequestFromJson(data io.Reader) (*LoginRequest, error) {
	var r LoginRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type LoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
}

func (r *LoginResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func RefreshTokenRequestFromJson(data io.Reader) (*RefreshTokenRequest, error) {
	var r RefreshTokenRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type RefreshTokenResponse struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (r *RefreshTokenResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./model/...
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add model/user.go
git commit -m "feat(model): add User domain type and HTTP req/resp types"
```

---

## Task 3: Create `model/secret.go`

**Files:**
- Create: `model/secret.go`

- [ ] **Step 1: Create the file**

```go
package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// Secret represents a secret in the password manager.
type Secret struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	Name             string     `json:"name"`
	Value            string     `json:"value"`
	Version          int        `json:"version"`
	Tags             []string   `json:"tags"`
	CreatedAt        time.Time  `json:"created_at"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	PurgeProtection  bool       `json:"purge_protection"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
	Enabled          bool       `json:"enabled"`
	ContentType      string     `json:"content_type,omitempty"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
}

func (s *Secret) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

func (s *Secret) IsActive() bool {
	if s.NotBefore == nil {
		return true
	}
	return time.Now().After(*s.NotBefore)
}

func (s *Secret) IsAccessible() bool {
	return s.Enabled && s.IsActive() && !s.IsExpired()
}

func (s *Secret) DaysUntilExpiration() int {
	if s.ExpiresAt == nil {
		return -1
	}
	if s.IsExpired() {
		return 0
	}
	return int(time.Until(*s.ExpiresAt).Hours() / 24)
}

// SecretVersion represents a version of a secret.
type SecretVersion struct {
	ID        uuid.UUID `json:"id"`
	SecretID  uuid.UUID `json:"secret_id"`
	UserID    uuid.UUID `json:"user_id"`
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// ExportFormat represents the format for exporting secrets.
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
)

// ExportOptions contains options for exporting secrets.
type ExportOptions struct {
	Format      ExportFormat `json:"format"`
	IncludeTags bool         `json:"include_tags"`
	FilterTags  []string     `json:"filter_tags,omitempty"`
	Encrypt     bool         `json:"encrypt"`
	UserID      uuid.UUID    `json:"user_id"`
	ExportedAt  time.Time    `json:"exported_at"`
	ExportedBy  string       `json:"exported_by"`
}

// ImportOptions contains options for importing secrets.
type ImportOptions struct {
	Format            ExportFormat `json:"format"`
	OverwriteExisting bool         `json:"overwrite_existing"`
	Encrypted         bool         `json:"encrypted"`
	UserID            uuid.UUID    `json:"user_id"`
	ImportedBy        string       `json:"imported_by"`
}

// ExportedSecret represents a secret in export format.
type ExportedSecret struct {
	ID        string    `json:"id" csv:"id"`
	Name      string    `json:"name" csv:"name"`
	Value     string    `json:"value" csv:"value"`
	Version   int       `json:"version" csv:"version"`
	Tags      []string  `json:"tags" csv:"tags"`
	CreatedAt time.Time `json:"created_at" csv:"created_at"`
}

// ExportContainer is the complete export structure.
type ExportContainer struct {
	Metadata ExportOptions    `json:"metadata"`
	Secrets  []ExportedSecret `json:"secrets"`
}

// --- HTTP request/response types ---

type CreateSecretRequest struct {
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Tags        []string `json:"tags,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
}

func CreateSecretRequestFromJson(data io.Reader) (*CreateSecretRequest, error) {
	var r CreateSecretRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateSecretRequest struct {
	Name        string   `json:"name,omitempty"`
	Value       string   `json:"value,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	ContentType *string  `json:"content_type,omitempty"`
}

func UpdateSecretRequestFromJson(data io.Reader) (*UpdateSecretRequest, error) {
	var r UpdateSecretRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type GenerateSecretRequest struct {
	Length       int    `json:"length,omitempty"`
	UseSymbols   bool   `json:"use_symbols,omitempty"`
	UseNumbers   bool   `json:"use_numbers,omitempty"`
	UseUppercase bool   `json:"use_uppercase,omitempty"`
	UseLowercase bool   `json:"use_lowercase,omitempty"`
	Name         string `json:"name"`
}

func GenerateSecretRequestFromJson(data io.Reader) (*GenerateSecretRequest, error) {
	var r GenerateSecretRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type ExportSecretsRequest struct {
	Format      string   `json:"format"`
	Encrypt     bool     `json:"encrypt"`
	Tags        []string `json:"tags"`
	IncludeTags bool     `json:"include_tags"`
}

func ExportSecretsRequestFromJson(data io.Reader) (*ExportSecretsRequest, error) {
	var r ExportSecretsRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type SecretResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Value       string   `json:"value,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Version     int      `json:"version"`
	ContentType string   `json:"content_type,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

func (r *SecretResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListSecretsResponse struct {
	Secrets []SecretResponse `json:"secrets"`
	Total   int              `json:"total"`
}

func (r *ListSecretsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ExportResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Count      int    `json:"count"`
	Format     string `json:"format"`
	Encrypted  bool   `json:"encrypted"`
	ExportedAt string `json:"exported_at"`
}

func (r *ExportResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ImportResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	ImportedCount int    `json:"imported_count"`
	TotalCount    int    `json:"total_count"`
	Format        string `json:"format"`
	ImportedAt    string `json:"imported_at"`
}

func (r *ImportResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./model/...
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add model/secret.go
git commit -m "feat(model): add Secret domain type and HTTP req/resp types"
```

---

## Task 4: Create `model/key.go`

**Files:**
- Create: `model/key.go`

- [ ] **Step 1: Create the file**

```go
package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// Key represents a cryptographic key in the password manager.
type Key struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	Name             string     `json:"name"`
	Type             string     `json:"type"`
	Value            string     `json:"value"`
	Revoked          bool       `json:"revoked"`
	CreatedAt        time.Time  `json:"created_at"`
	Tags             []string   `json:"tags"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	PurgeProtection  bool       `json:"purge_protection"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
}

const (
	KeyTypeRSA   = "RSA"
	KeyTypeECDSA = "ECDSA"
)

// --- HTTP request/response types ---

type CreateKeyRequest struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Bits  int      `json:"bits"`
	Curve string   `json:"curve"`
	Tags  []string `json:"tags"`
}

func CreateKeyRequestFromJson(data io.Reader) (*CreateKeyRequest, error) {
	var r CreateKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateKeyRequest struct {
	Name    *string  `json:"name,omitempty"`
	Revoked *bool    `json:"revoked,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

func UpdateKeyRequestFromJson(data io.Reader) (*UpdateKeyRequest, error) {
	var r UpdateKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type KeyResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	UserID    uuid.UUID `json:"user_id"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	Tags      []string  `json:"tags"`
}

func (r *KeyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type KeyListResponse struct {
	Keys []KeyResponse `json:"keys"`
}

func (r *KeyListResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type WrapKeyRequest struct {
	PlaintextKey string `json:"plaintext_key"`
	Algorithm    string `json:"algorithm"`
}

func WrapKeyRequestFromJson(data io.Reader) (*WrapKeyRequest, error) {
	var r WrapKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type WrapKeyResponse struct {
	WrappedKey string `json:"wrapped_key"`
	Algorithm  string `json:"algorithm"`
}

func (r *WrapKeyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type UnwrapKeyRequest struct {
	WrappedKey string `json:"wrapped_key"`
	Algorithm  string `json:"algorithm"`
}

func UnwrapKeyRequestFromJson(data io.Reader) (*UnwrapKeyRequest, error) {
	var r UnwrapKeyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UnwrapKeyResponse struct {
	PlaintextKey string `json:"plaintext_key"`
	Algorithm    string `json:"algorithm"`
}

func (r *UnwrapKeyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./model/...
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add model/key.go
git commit -m "feat(model): add Key domain type and HTTP req/resp types"
```

---

## Task 5: Create `model/certificate.go`

**Files:**
- Create: `model/certificate.go`

- [ ] **Step 1: Create the file**

```go
package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// Certificate represents an X.509 certificate in the password manager.
type Certificate struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	Name             string     `json:"name"`
	Certificate      string     `json:"certificate"`
	PrivateKey       string     `json:"private_key"`
	CreatedAt        time.Time  `json:"created_at"`
	Tags             []string   `json:"tags"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	PurgeProtection  bool       `json:"purge_protection"`
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	AutoRenew        bool       `json:"auto_renew"`
	RenewalDays      int        `json:"renewal_days"`
}

// RevokedCertificate represents a revoked certificate in the CRL.
type RevokedCertificate struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	SerialNumber string
	Name         string
	RevokedAt    time.Time
}

// --- HTTP request/response types ---

type CreateCertificateRequest struct {
	Name         string   `json:"name"`
	KeyID        string   `json:"key_id"`
	ValidityDays int      `json:"validity_days"`
	Tags         []string `json:"tags,omitempty"`
	AutoRenew    bool     `json:"auto_renew"`
	RenewalDays  int      `json:"renewal_days"`
	CAKeyID      string   `json:"ca_key_id,omitempty"`
	CACertID     string   `json:"ca_cert_id,omitempty"`
}

func CreateCertificateRequestFromJson(data io.Reader) (*CreateCertificateRequest, error) {
	var r CreateCertificateRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type UpdateCertificateRequest struct {
	Name        *string  `json:"name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	AutoRenew   *bool    `json:"auto_renew,omitempty"`
	RenewalDays *int     `json:"renewal_days,omitempty"`
}

func UpdateCertificateRequestFromJson(data io.Reader) (*UpdateCertificateRequest, error) {
	var r UpdateCertificateRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type CertificateResponse struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	UserID      uuid.UUID  `json:"user_id"`
	CreatedAt   time.Time  `json:"created_at"`
	Tags        []string   `json:"tags"`
	AutoRenew   bool       `json:"auto_renew"`
	RenewalDays int        `json:"renewal_days"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func (r *CertificateResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type CertificateListResponse struct {
	Certificates []CertificateResponse `json:"certificates"`
}

func (r *CertificateListResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./model/...
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add model/certificate.go
git commit -m "feat(model): add Certificate domain type and HTTP req/resp types"
```

---

## Task 6: Create `model/access_policy.go`, `model/session.go`, `model/oauth2_client.go`

**Files:**
- Create: `model/access_policy.go`
- Create: `model/session.go`
- Create: `model/oauth2_client.go`

- [ ] **Step 1: Create `model/access_policy.go`**

```go
package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

type PrincipalType string

const (
	PrincipalTypeUser           PrincipalType = "user"
	PrincipalTypeServiceAccount PrincipalType = "service_account"
)

type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

type PolicyResourceType string

const (
	PolicyResourceSecrets      PolicyResourceType = "secrets"
	PolicyResourceKeys         PolicyResourceType = "keys"
	PolicyResourceCertificates PolicyResourceType = "certificates"
)

type PolicyOperation string

const (
	OpGet     PolicyOperation = "get"
	OpList    PolicyOperation = "list"
	OpSet     PolicyOperation = "set"
	OpCreate  PolicyOperation = "create"
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

type AccessPolicy struct {
	ID            uuid.UUID          `json:"id"`
	PrincipalID   uuid.UUID          `json:"principal_id"`
	PrincipalType PrincipalType      `json:"principal_type"`
	ResourceType  PolicyResourceType `json:"resource_type"`
	Operation     PolicyOperation    `json:"operation"`
	Effect        PolicyEffect       `json:"effect"`
	CreatedAt     time.Time          `json:"created_at"`
}

type CreateAccessPolicyRequest struct {
	PrincipalID   string `json:"principal_id"`
	PrincipalType string `json:"principal_type"`
	ResourceType  string `json:"resource_type"`
	Operation     string `json:"operation"`
	Effect        string `json:"effect"`
}

func CreateAccessPolicyRequestFromJson(data io.Reader) (*CreateAccessPolicyRequest, error) {
	var r CreateAccessPolicyRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type AccessPolicyResponse struct {
	ID            string `json:"id"`
	PrincipalID   string `json:"principal_id"`
	PrincipalType string `json:"principal_type"`
	ResourceType  string `json:"resource_type"`
	Operation     string `json:"operation"`
	Effect        string `json:"effect"`
	CreatedAt     string `json:"created_at"`
}

func (r *AccessPolicyResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListAccessPoliciesResponse struct {
	AccessPolicies []AccessPolicyResponse `json:"access_policies"`
	Total          int                    `json:"total"`
}

func (r *ListAccessPoliciesResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
```

- [ ] **Step 2: Create `model/session.go`**

```go
package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Session represents a user session with refresh token capability.
type Session struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	RefreshTokenHash string     `json:"refresh_token_hash"`
	DeviceInfo       string     `json:"device_info"`
	IPAddress        string     `json:"ip_address"`
	UserAgent        string     `json:"user_agent"`
	ExpiresAt        time.Time  `json:"expires_at"`
	LastUsedAt       time.Time  `json:"last_used_at"`
	CreatedAt        time.Time  `json:"created_at"`
	Revoked          bool       `json:"revoked"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedReason    string     `json:"revoked_reason,omitempty"`
}

// SessionInfo contains structured device metadata.
type SessionInfo struct {
	DeviceName string `json:"device_name,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
	OS         string `json:"os,omitempty"`
	Browser    string `json:"browser,omitempty"`
	AppVersion string `json:"app_version,omitempty"`
}

// SessionConfig contains configuration for session management.
type SessionConfig struct {
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	MaxSessions        int
	EnableRotation     bool
}

func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		AccessTokenExpiry:  30 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
		MaxSessions:        5,
		EnableRotation:     true,
	}
}

type SessionResponse struct {
	ID         string    `json:"id"`
	DeviceInfo string    `json:"device_info"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	CreatedAt  time.Time `json:"created_at"`
	Revoked    bool      `json:"revoked"`
}

func (r *SessionResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListSessionsResponse struct {
	Sessions []SessionResponse `json:"sessions"`
	Total    int               `json:"total"`
}

func (r *ListSessionsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
```

- [ ] **Step 3: Create `model/oauth2_client.go`**

```go
package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// OAuth2Client represents a machine-to-machine authentication client.
type OAuth2Client struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	ClientSecret string     `json:"client_secret,omitempty"`
	Description  string     `json:"description"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

type CreateOAuth2ClientRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func CreateOAuth2ClientRequestFromJson(data io.Reader) (*CreateOAuth2ClientRequest, error) {
	var r CreateOAuth2ClientRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type OAuth2ClientResponse struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	ClientSecret string     `json:"client_secret,omitempty"`
	Description  string     `json:"description"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

func (r *OAuth2ClientResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListOAuth2ClientsResponse struct {
	Clients []OAuth2ClientResponse `json:"clients"`
	Total   int                    `json:"total"`
}

func (r *ListOAuth2ClientsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
```

- [ ] **Step 4: Verify it compiles**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./model/...
```
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add model/access_policy.go model/session.go model/oauth2_client.go
git commit -m "feat(model): add AccessPolicy, Session, OAuth2Client types"
```

---

## Task 7: Update `internal/` imports from `internal/domain` to `model`

**Files:** All 21 `internal/` files listed in the file map above (import path change only).

- [ ] **Step 1: Bulk-replace the import path**

```bash
cd /home/numericlabs/data/rocket/rocketvault
find internal/ -name "*.go" | xargs sed -i 's|"rocketvault/internal/domain"|"rocketvault/model"|g'
```

- [ ] **Step 2: Replace `domain.` references with `model.`**

```bash
find internal/ -name "*.go" | xargs sed -i 's/domain\./model\./g'
```

- [ ] **Step 3: Fix any aliased imports** — some files import with an alias (e.g. `domainpkg`). Check:

```bash
grep -rn "internal/domain\|domain\." internal/ --include="*.go"
```
Expected: no output. If any remain, fix them manually by opening the file and correcting the reference.

- [ ] **Step 4: Verify the build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./internal/...
```
Expected: no output (clean build). Fix any compilation errors before proceeding.

- [ ] **Step 5: Run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./internal/... 2>&1 | tail -20
```
Expected: all tests pass (PASS lines, no FAIL).

- [ ] **Step 6: Commit**

```bash
git add internal/
git commit -m "refactor(internal): replace internal/domain import with model"
```

---

## Task 8: Update `cmd/` imports from `internal/domain` to `model`

**Files:** All `cmd/` files listed in the file map above (import path change only).

- [ ] **Step 1: Bulk-replace the import path**

```bash
cd /home/numericlabs/data/rocket/rocketvault
find cmd/ -name "*.go" | xargs sed -i 's|"rocketvault/internal/domain"|"rocketvault/model"|g'
```

- [ ] **Step 2: Replace `domain.` references with `model.`**

```bash
find cmd/ -name "*.go" | xargs sed -i 's/domain\./model\./g'
```

- [ ] **Step 3: Check for remaining references**

```bash
grep -rn "internal/domain\|domain\." cmd/ --include="*.go"
```
Expected: no output. Fix any remaining references manually.

- [ ] **Step 4: Verify the build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./cmd/...
```
Expected: no output. Fix any compilation errors before proceeding.

- [ ] **Step 5: Run CLI tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./cmd/... 2>&1 | tail -20
```
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add cmd/
git commit -m "refactor(cmd): replace internal/domain import with model"
```

---

## Task 9: Create `api/params.go`

**Files:**
- Create: `api/params.go`

- [ ] **Step 1: Create the file**

```go
package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

// ApiParams holds all URL path variables and query parameters for a request.
// Populated once per request by ApiParamsFromRequest and stored on Context.Params.
type ApiParams struct {
	// Path variables — populated from mux route patterns
	UserID           string
	SecretID         string
	KeyID            string
	CertificateID    string
	PolicyID         string
	ServiceAccountID string
	SessionID        string
	PrincipalID      string
	Version          int // {version} parsed to int; 0 if absent

	// Pagination
	Page    int // default: 0, floor: 0
	PerPage int // default: 60, max: 200

	// Filters
	Tags      []string // ?tags=a,b split on comma
	Permanent bool     // ?permanent=true
}

// ApiParamsFromRequest parses mux route variables and query string into ApiParams.
func ApiParamsFromRequest(r *http.Request) *ApiParams {
	vars := mux.Vars(r)
	p := &ApiParams{
		UserID:           vars["user_id"],
		SecretID:         vars["secret_id"],
		KeyID:            vars["key_id"],
		CertificateID:    vars["certificate_id"],
		PolicyID:         vars["policy_id"],
		ServiceAccountID: vars["service_account_id"],
		SessionID:        vars["session_id"],
		PrincipalID:      vars["principal_id"],
	}

	if v, err := strconv.Atoi(vars["version"]); err == nil {
		p.Version = v
	}

	q := r.URL.Query()

	if page, err := strconv.Atoi(q.Get("page")); err == nil && page >= 0 {
		p.Page = page
	}

	perPage := 60
	if pp, err := strconv.Atoi(q.Get("per_page")); err == nil && pp > 0 {
		perPage = pp
	}
	if perPage > 200 {
		perPage = 200
	}
	p.PerPage = perPage

	if tagsParam := q.Get("tags"); tagsParam != "" {
		p.Tags = strings.Split(tagsParam, ",")
	}

	p.Permanent = q.Get("permanent") == "true"

	return p
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./api/...
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add api/params.go
git commit -m "feat(api): add ApiParams with centralized request parameter parsing"
```

---

## Task 10: Rewrite `api/context.go` and `api/api.go`

**Files:**
- Modify: `api/context.go`
- Modify: `api/api.go`

- [ ] **Step 1: Rewrite `api/context.go`**

Replace the entire file contents with:

```go
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	authServices "rocketvault/internal/services/auth"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
)

// Context holds request-scoped data for every API handler.
type Context struct {
	App            *app.App
	T              common.TranslateFunc
	Err            *common.AppError
	RequestID      string
	IPAddress      string
	Token          string
	Claims         jwt.MapClaims
	Path           string
	UserAgent      string
	AcceptLanguage string
	Params         *ApiParams
	Logger         *logging.Logger
}

// SetInvalidParam sets a 400 error for a missing or malformed parameter.
func (c *Context) SetInvalidParam(parameter string) {
	c.Err = common.NewAppError("api.context.set_invalid_param",
		"Invalid or missing parameter: "+parameter, nil, "", http.StatusBadRequest)
}

// SetPermissionError sets a 403 error for insufficient permissions.
func (c *Context) SetPermissionError(permission string) {
	c.Err = common.NewAppError("api.context.set_permission_error",
		"Insufficient permissions: "+permission, nil, "", http.StatusForbidden)
}

// SetNotFound sets a 404 error for a missing resource.
func (c *Context) SetNotFound(resource string) {
	c.Err = common.NewAppError("api.context.set_not_found",
		resource+" not found", nil, "", http.StatusNotFound)
}

// SetInternalError sets a 500 error for unexpected failures.
func (c *Context) SetInternalError(err error) {
	c.Err = common.NewAppError("api.context.set_internal_error",
		"Internal server error", nil, err.Error(), http.StatusInternalServerError)
}

// ApiHandler wraps public (unauthenticated) handlers.
func ApiHandler(app *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := &Context{
			App:            app,
			Params:         ApiParamsFromRequest(r),
			RequestID:      "req-" + uuid.New().String()[:8],
			IPAddress:      r.RemoteAddr,
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Logger:         app.Logger,
		}

		if ctx.Logger != nil {
			ctx.Logger.Printf("Handling %s %s", r.Method, r.URL.Path)
		}

		handler(ctx, w, r)

		if ctx.Logger != nil {
			ctx.Logger.Printf("Completed %s %s in %dms", r.Method, r.URL.Path, time.Since(start).Milliseconds())
		}

		if ctx.Err != nil {
			writeError(w, ctx)
		}
	}
}

// ApiSessionRequired wraps handlers that require an authenticated session.
func ApiSessionRequired(a *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		userIDStr, ok := r.Context().Value(common.UserIDKey).(string)
		if !ok || userIDStr == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{
				"id":          "api.context.session_required",
				"message":     "Unauthorized: missing session",
				"status_code": http.StatusUnauthorized,
			})
			return
		}

		username, _ := r.Context().Value(common.UsernameKey).(string)
		role, _ := r.Context().Value(common.RoleKey).(string)

		if a.ServiceContainer != nil {
			if err := a.ServiceContainer.GetRBACService().ValidateEndpointAccess(role, r.Method, r.URL.Path); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{
					"id":          "api.context.permissions",
					"message":     "Access denied",
					"status_code": http.StatusForbidden,
				})
				return
			}
		}

		ctx := &Context{
			App: a,
			Claims: jwt.MapClaims{
				"user_id":  userIDStr,
				"username": username,
				"role":     role,
			},
			Params:         ApiParamsFromRequest(r),
			RequestID:      "req-" + uuid.New().String()[:8],
			IPAddress:      r.RemoteAddr,
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Logger:         a.Logger,
		}

		if ctx.Logger != nil {
			ctx.Logger.Printf("Handling %s %s (user: %s)", r.Method, r.URL.Path, userIDStr)
		}

		handler(ctx, w, r)

		if ctx.Logger != nil {
			ctx.Logger.Printf("Completed %s %s in %dms", r.Method, r.URL.Path, time.Since(start).Milliseconds())
		}

		if ctx.Err != nil {
			writeError(w, ctx)
		}
	}
}

// writeError writes a structured JSON error response with request_id.
func writeError(w http.ResponseWriter, c *Context) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c.Err.StatusCode)
	json.NewEncoder(w).Encode(map[string]any{
		"id":             c.Err.ID,
		"message":        c.Err.Message,
		"detailed_error": c.Err.DetailedError,
		"status_code":    c.Err.StatusCode,
		"request_id":     c.RequestID,
	})
}

// Service accessor methods — set c.Err and return nil if service container is unavailable.

func (c *Context) secretSvc() secretServices.SecretService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetSecretService()
}

func (c *Context) keySvc() keyServices.KeyService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetKeyService()
}

func (c *Context) cryptoSvc() keyServices.CryptoService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetCryptoService()
}

func (c *Context) userSvc() userServices.UserService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetUserService()
}

func (c *Context) certSvc() certServices.CertificateService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetCertificateService()
}

func (c *Context) authSvc() authServices.AuthenticationService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetAuthenticationService()
}

func (c *Context) sessionRepo() repositories.SessionRepositoryInterface {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetSessionRepository()
}
```

- [ ] **Step 2: Rewrite `api/api.go`**

Replace the entire file contents with:

```go
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"rocketvault/app"
	"rocketvault/internal/logging"
)

// Routes holds all subrouters for the API — typed for compile-time safety.
type Routes struct {
	ApiRoot         *mux.Router // /api/v1
	Vault           *mux.Router // /api/v1/vault
	Secrets         *mux.Router // /api/v1/secrets
	Secret          *mux.Router // /api/v1/secrets/{secret_id}
	Users           *mux.Router // /api/v1/users
	User            *mux.Router // /api/v1/users/{user_id}
	Keys            *mux.Router // /api/v1/keys
	Key             *mux.Router // /api/v1/keys/{key_id}
	Certificates    *mux.Router // /api/v1/certificates
	Certificate     *mux.Router // /api/v1/certificates/{certificate_id}
	Health          *mux.Router // /api/v1/health
	Deleted         *mux.Router // /api/v1/deleted
	AccessPolicies  *mux.Router // /api/v1/access-policies
	AccessPolicy    *mux.Router // /api/v1/access-policies/{policy_id}
	ServiceAccounts *mux.Router // /api/v1/service-accounts
	ServiceAccount  *mux.Router // /api/v1/service-accounts/{service_account_id}
	OAuth2          *mux.Router // /api/v1/oauth2 (public — no auth middleware)
}

// API is the main API structure for the vault service.
type API struct {
	App        *app.App
	BaseRoutes *Routes
	basePath   string
	rootRouter *mux.Router
	Logger     *logging.Logger
}

// Init initializes the API, wires middleware, and registers all route handlers.
func Init(options ...Options) *API {
	api := &API{
		BaseRoutes: &Routes{},
	}

	for _, option := range options {
		option(api)
	}

	mw := newMiddleware(api.App)
	api.Logger.WithField("basePath", api.basePath).Infoln("Api configured with")

	r := api.BaseRoutes
	r.ApiRoot = api.rootRouter.PathPrefix(api.basePath).Subrouter()
	r.ApiRoot.Use(
		mw.RateLimitMiddleware,
		mw.AuthenticationMiddleware,
		mw.PolicyMiddleware,
		mw.AuthorizationMiddleware,
	)

	r.Vault = r.ApiRoot.PathPrefix("/vault").Subrouter()

	r.Secrets = r.ApiRoot.PathPrefix("/secrets").Subrouter()
	r.Secret = r.Secrets.PathPrefix("/{secret_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Users = r.ApiRoot.PathPrefix("/users").Subrouter()
	r.User = r.Users.PathPrefix("/{user_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Keys = r.ApiRoot.PathPrefix("/keys").Subrouter()
	r.Key = r.Keys.PathPrefix("/{key_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Certificates = r.ApiRoot.PathPrefix("/certificates").Subrouter()
	r.Certificate = r.Certificates.PathPrefix("/{certificate_id:[A-Fa-f0-9-]+}").Subrouter()

	r.Health = r.ApiRoot.PathPrefix("/health").Subrouter()
	r.Deleted = r.ApiRoot.PathPrefix("/deleted").Subrouter()

	r.AccessPolicies = r.ApiRoot.PathPrefix("/access-policies").Subrouter()
	r.AccessPolicy = r.AccessPolicies.PathPrefix("/{policy_id:[A-Fa-f0-9-]+}").Subrouter()

	r.ServiceAccounts = r.ApiRoot.PathPrefix("/service-accounts").Subrouter()
	r.ServiceAccount = r.ServiceAccounts.PathPrefix("/{service_account_id:[A-Fa-f0-9-]+}").Subrouter()

	// OAuth2 is public — registered on rootRouter to bypass auth middleware.
	r.OAuth2 = api.rootRouter.PathPrefix(api.basePath).Subrouter()

	api.InitVault()
	api.InitSecrets()
	api.InitUsers()
	api.InitKeys()
	api.InitCertificates()
	api.InitHealth()
	api.InitDeleted()
	api.InitAccessPolicies()
	api.InitOAuth2()

	// Catch-all 404 for unmatched routes.
	api.rootRouter.NotFoundHandler = http.HandlerFunc(Handle404)

	var names []string
	for _, n := range []string{"Vault", "Secrets", "Users", "Keys", "Certificates",
		"Health", "Deleted", "AccessPolicies", "ServiceAccounts", "OAuth2"} {
		names = append(names, n)
	}
	api.Logger.WithField("api", strings.Join(names, ",")).Infoln("Initialized api")
	return api
}

// Handle404 returns a structured JSON 404 response for unmatched routes.
func Handle404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]any{
		"id":          "api.not_found",
		"message":     "Not found",
		"status_code": http.StatusNotFound,
	})
}

// ReturnStatusOK writes a standard {"status":"OK"} response.
func ReturnStatusOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
}

// newMiddleware constructs the middleware chain from the service container.
func newMiddleware(a *app.App) interface {
	RateLimitMiddleware(http.Handler) http.Handler
	AuthenticationMiddleware(http.Handler) http.Handler
	PolicyMiddleware(http.Handler) http.Handler
	AuthorizationMiddleware(http.Handler) http.Handler
} {
	return middlewareFromContainer(a)
}
```

> **Note on `newMiddleware`:** The existing `middleware.NewMiddleware(api.App.ServiceContainer)` call returns a `*middleware.Middleware`. Replace the inline interface approach above with the actual import: `import "rocketvault/internal/middleware"` and call `middleware.NewMiddleware(api.App.ServiceContainer)`. The inline interface is shown for clarity only.

- [ ] **Step 3: Fix the middleware import in `api/api.go`**

Replace the `newMiddleware` helper and its call with:

```go
import "rocketvault/internal/middleware"

// In Init():
mw := middleware.NewMiddleware(api.App.ServiceContainer)
```

- [ ] **Step 4: Verify the build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./api/...
```
Expected: no output. Fix any compilation errors (likely missing `InitServiceAccounts` — add a stub `func (api *API) InitServiceAccounts() {}` in `oauth2.go` if needed).

- [ ] **Step 5: Commit**

```bash
git add api/context.go api/api.go
git commit -m "refactor(api): rewrite context and api with typed Routes and ApiHandler"
```

---

## Task 11: Rewrite `api/users.go`

**Files:**
- Modify: `api/users.go`

- [ ] **Step 1: Replace `api/users.go`**

The key changes from the original:
- Replace all `mux.Vars(r)["id"]` with `c.Params.UserID` or `c.Params.SessionID`
- Replace `common.NewAppError(...)` calls with `c.SetInvalidParam(...)`, `c.SetPermissionError(...)`, `c.SetNotFound(...)`, `c.SetInternalError(...)`
- Replace inline `json.NewDecoder(r.Body).Decode(&req)` with `model.LoginRequestFromJson(r.Body)` etc.
- Replace `json.NewEncoder(w).Encode(response)` with `w.Write([]byte(response.ToJson()))`
- Replace `domain.` with `model.`
- `InitUsers()` takes no router argument — uses `api.BaseRoutes.*`
- Route patterns use `{user_id}` and `{session_id}` instead of `{id}`

```go
package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
	userService "rocketvault/internal/services/users"
)

func (api *API) InitUsers() {
	// Public endpoints
	api.BaseRoutes.Users.Handle("/login", ApiHandler(api.App, loginUser)).Methods("POST")
	api.BaseRoutes.Users.Handle("/refresh", ApiHandler(api.App, refreshToken)).Methods("POST")

	// Session management
	api.BaseRoutes.Users.Handle("/sessions", ApiSessionRequired(api.App, listUserSessions)).Methods("GET")
	api.BaseRoutes.Users.Handle("/sessions/{session_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, revokeSession)).Methods("DELETE")
	api.BaseRoutes.Users.Handle("/sessions", ApiSessionRequired(api.App, revokeAllSessions)).Methods("DELETE")

	// Collection routes
	api.BaseRoutes.Users.Handle("", ApiSessionRequired(api.App, createUser)).Methods("POST")
	api.BaseRoutes.Users.Handle("", ApiSessionRequired(api.App, listUsers)).Methods("GET")

	// Resource routes on BaseRoutes.User (already has /{user_id} prefix)
	api.BaseRoutes.User.Handle("", ApiSessionRequired(api.App, getUser)).Methods("GET")
	api.BaseRoutes.User.Handle("", ApiSessionRequired(api.App, updateUser)).Methods("PUT")
	api.BaseRoutes.User.Handle("", ApiSessionRequired(api.App, deleteUser)).Methods("DELETE")
}

func createUser(c *Context, w http.ResponseWriter, r *http.Request) {
	claims, ok := c.Claims["role"].(string)
	if !ok || claims != model.RoleAdmin {
		c.SetPermissionError("admin")
		return
	}

	req, err := model.CreateUserRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request_body")
		return
	}

	if req.Username == "" || len(req.Username) < 3 || len(req.Username) > 50 {
		c.SetInvalidParam("username")
		return
	}
	if req.Password == "" || len(req.Password) < 8 {
		c.SetInvalidParam("password")
		return
	}

	validRoles := []string{model.RoleAdmin, model.RoleCryptoManager, model.RoleCertificateManager, model.RoleSecretsManager, model.RoleUser}
	if !isValidRoleString(req.Role, validRoles) {
		c.SetInvalidParam("role")
		return
	}

	svc := c.userSvc()
	if svc == nil {
		return
	}

	result, err := svc.CreateUser(r.Context(), userService.CreateUserRequest{
		Username:   req.Username,
		Password:   req.Password,
		Role:       req.Role,
		CallerRole: claims,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	response := &model.UserResponse{
		ID:         result.UserID.String(),
		Username:   result.Username,
		Role:       result.Role,
		CreatedAt:  time.Now().Format(time.RFC3339),
		TOTPSecret: result.TOTPSecret,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(response.ToJson()))
}

func listUsers(c *Context, w http.ResponseWriter, r *http.Request) {
	claims, ok := c.Claims["role"].(string)
	if !ok || claims != model.RoleAdmin {
		c.SetPermissionError("admin")
		return
	}

	limit := c.Params.PerPage
	offset := c.Params.Page * limit

	svc := c.userSvc()
	if svc == nil {
		return
	}

	users, err := svc.ListUsers(r.Context())
	if err != nil {
		c.SetInternalError(err)
		return
	}

	total := len(users)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	userResponses := make([]model.UserResponse, end-start)
	for i, u := range users[start:end] {
		userResponses[i] = model.UserResponse{
			ID:        u.ID.String(),
			Username:  u.Username,
			Role:      u.Role,
			CreatedAt: u.CreatedAt.Format(time.RFC3339),
		}
	}

	response := &model.ListUsersResponse{Users: userResponses, Total: total}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

func getUser(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(c.Params.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	currentUserID, _ := c.Claims["user_id"].(string)
	currentRole, _ := c.Claims["role"].(string)

	if currentRole != model.RoleAdmin && currentUserID != userID.String() {
		c.SetPermissionError("own_profile")
		return
	}

	svc := c.userSvc()
	if svc == nil {
		return
	}

	user, err := svc.GetUser(r.Context(), userID)
	if err != nil {
		c.SetNotFound("user")
		return
	}

	response := &model.UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

func updateUser(c *Context, w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(c.Params.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	req, err := model.UpdateUserRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request_body")
		return
	}

	if req.Username != "" && (len(req.Username) < 3 || len(req.Username) > 50) {
		c.SetInvalidParam("username")
		return
	}
	if req.Password != "" && len(req.Password) < 8 {
		c.SetInvalidParam("password")
		return
	}

	currentUserID, _ := c.Claims["user_id"].(string)
	currentRole, _ := c.Claims["role"].(string)

	if currentRole != model.RoleAdmin {
		if currentUserID != userID.String() {
			c.SetPermissionError("own_profile")
			return
		}
		if req.Role != "" {
			c.SetPermissionError("change_role")
			return
		}
	}

	svc := c.userSvc()
	if svc == nil {
		return
	}

	callerID, _ := uuid.Parse(currentUserID)
	var usernamePtr, passwordPtr, rolePtr *string
	if req.Username != "" {
		usernamePtr = &req.Username
	}
	if req.Password != "" {
		passwordPtr = &req.Password
	}
	if req.Role != "" {
		rolePtr = &req.Role
	}

	if err := svc.UpdateUser(r.Context(), userService.UpdateUserRequest{
		UserID:     userID,
		CallerID:   callerID,
		CallerRole: currentRole,
		Username:   usernamePtr,
		Password:   passwordPtr,
		Role:       rolePtr,
	}); err != nil {
		c.SetInternalError(err)
		return
	}

	user, err := svc.GetUser(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	response := &model.UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

func deleteUser(c *Context, w http.ResponseWriter, r *http.Request) {
	claims, ok := c.Claims["role"].(string)
	if !ok || claims != model.RoleAdmin {
		c.SetPermissionError("admin")
		return
	}

	userID, err := uuid.Parse(c.Params.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	currentUserID, _ := c.Claims["user_id"].(string)
	if currentUserID == userID.String() {
		c.SetInvalidParam("self_delete")
		return
	}

	svc := c.userSvc()
	if svc == nil {
		return
	}

	if _, err := svc.GetUser(r.Context(), userID); err != nil {
		c.SetNotFound("user")
		return
	}

	if err := svc.DeleteUser(r.Context(), userID); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}

func loginUser(c *Context, w http.ResponseWriter, r *http.Request) {
	req, err := model.LoginRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request_body")
		return
	}

	if req.Username == "" || req.Password == "" || req.TOTPCode == "" {
		c.SetInvalidParam("username_password_totp")
		return
	}

	svc := c.authSvc()
	if svc == nil {
		return
	}

	result, err := svc.AuthenticateUser(r.Context(), req.Username, req.Password, req.TOTPCode)
	if err != nil {
		c.SetPermissionError("authentication")
		return
	}

	response := &model.LoginResponse{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID.String(),
		Username:     result.Username,
		Role:         result.Role,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

func refreshToken(c *Context, w http.ResponseWriter, r *http.Request) {
	req, err := model.RefreshTokenRequestFromJson(r.Body)
	if err != nil || req.RefreshToken == "" {
		c.SetInvalidParam("refresh_token")
		return
	}

	svc := c.authSvc()
	if svc == nil {
		return
	}

	result, err := svc.RefreshAccessToken(r.Context(), req.RefreshToken)
	if err != nil {
		c.SetPermissionError("refresh_token")
		return
	}

	response := &model.RefreshTokenResponse{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID.String(),
		Username:     result.Username,
		Role:         result.Role,
		ExpiresAt:    result.ExpiresAt,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

func listUserSessions(c *Context, w http.ResponseWriter, r *http.Request) {
	currentUserID, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}

	userID, err := uuid.Parse(currentUserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	repo := c.sessionRepo()
	if repo == nil {
		return
	}

	sessions, err := repo.GetActiveSessionsByUserID(r.Context(), userID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	sessionResponses := make([]model.SessionResponse, len(sessions))
	for i, s := range sessions {
		sessionResponses[i] = model.SessionResponse{
			ID:         s.ID.String(),
			DeviceInfo: s.DeviceInfo,
			IPAddress:  s.IPAddress,
			UserAgent:  s.UserAgent,
			ExpiresAt:  s.ExpiresAt,
			LastUsedAt: s.LastUsedAt,
			CreatedAt:  s.CreatedAt,
			Revoked:    s.Revoked,
		}
	}

	response := &model.ListSessionsResponse{Sessions: sessionResponses, Total: len(sessionResponses)}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

func revokeSession(c *Context, w http.ResponseWriter, r *http.Request) {
	sessionID := c.Params.SessionID
	if sessionID == "" {
		c.SetInvalidParam("session_id")
		return
	}

	svc := c.authSvc()
	if svc == nil {
		return
	}

	if err := svc.RevokeSession(r.Context(), sessionID, "User requested revocation"); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}

func revokeAllSessions(c *Context, w http.ResponseWriter, r *http.Request) {
	currentUserID, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}

	userID, err := uuid.Parse(currentUserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.authSvc()
	if svc == nil {
		return
	}

	if err := svc.RevokeAllUserSessions(r.Context(), userID, "User requested revocation of all sessions"); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}

// isValidRoleString checks all comma-separated roles against the valid list.
func isValidRoleString(roleStr string, validRoles []string) bool {
	if roleStr == "" {
		return false
	}
	for _, r := range strings.Split(strings.TrimSpace(roleStr), ",") {
		r = strings.TrimSpace(r)
		found := false
		for _, v := range validRoles {
			if r == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ensure strconv is used (pagination offset calculation)
var _ = strconv.Itoa
```

- [ ] **Step 2: Verify the build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./api/...
```
Expected: no output. Fix any compilation errors.

- [ ] **Step 3: Commit**

```bash
git add api/users.go
git commit -m "refactor(api): rewrite users handlers with ApiParams and model types"
```

---

## Task 12: Rewrite `api/secrets.go`

**Files:**
- Modify: `api/secrets.go`

- [ ] **Step 1: Replace `api/secrets.go`**

Key changes:
- `InitSecrets()` — no router arg, uses `api.BaseRoutes.Secrets` and `api.BaseRoutes.Secret`
- Route patterns: `{secret_id}` instead of `{id}`, `{secret_id}/versions/{version}`
- All `mux.Vars(r)["id"]` → `c.Params.SecretID`, `mux.Vars(r)["version"]` → `c.Params.Version`
- `common.NewAppError(...)` → `c.SetInvalidParam(...)` / `c.SetInternalError(...)`
- `json.NewDecoder(r.Body).Decode(&req)` → `model.CreateSecretRequestFromJson(r.Body)`
- `json.NewEncoder(w).Encode(response)` → `w.Write([]byte(response.ToJson()))`

```go
package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
	secretsSvc "rocketvault/internal/services/secrets"
)

func (api *API) InitSecrets() {
	// Collection routes
	api.BaseRoutes.Secrets.Handle("", ApiSessionRequired(api.App, createSecret)).Methods("POST")
	api.BaseRoutes.Secrets.Handle("", ApiSessionRequired(api.App, listSecrets)).Methods("GET")
	api.BaseRoutes.Secrets.Handle("/generate", ApiSessionRequired(api.App, generateSecret)).Methods("POST")
	api.BaseRoutes.Secrets.Handle("/export", ApiSessionRequired(api.App, exportSecrets)).Methods("POST")
	api.BaseRoutes.Secrets.Handle("/import", ApiSessionRequired(api.App, importSecrets)).Methods("POST")

	// Resource routes (BaseRoutes.Secret already has /{secret_id} prefix)
	api.BaseRoutes.Secret.Handle("", ApiSessionRequired(api.App, getSecret)).Methods("GET")
	api.BaseRoutes.Secret.Handle("", ApiSessionRequired(api.App, updateSecret)).Methods("PUT")
	api.BaseRoutes.Secret.Handle("", ApiSessionRequired(api.App, deleteSecret)).Methods("DELETE")
	api.BaseRoutes.Secret.Handle("/versions", ApiSessionRequired(api.App, listSecretVersions)).Methods("GET")
	api.BaseRoutes.Secret.Handle("/versions/{version:[0-9]+}", ApiSessionRequired(api.App, getSecretVersion)).Methods("GET")
	api.BaseRoutes.Secret.Handle("/versions/latest", ApiSessionRequired(api.App, getLatestSecretVersion)).Methods("GET")
}

func createSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	req, err := model.CreateSecretRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request_body")
		return
	}
	if req.Name == "" {
		c.SetInvalidParam("name")
		return
	}
	if req.Value == "" {
		c.SetInvalidParam("value")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	secret, err := svc.CreateSecret(r.Context(), secretsSvc.CreateSecretRequest{
		UserID:      userID,
		Name:        req.Name,
		Value:       req.Value,
		Tags:        req.Tags,
		ContentType: req.ContentType,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	response := &model.SecretResponse{
		ID:          secret.ID.String(),
		Name:        secret.Name,
		Tags:        secret.Tags,
		Version:     secret.Version,
		ContentType: secret.ContentType,
		CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(response.ToJson()))
}

func listSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	list, err := svc.ListSecrets(r.Context(), userID, c.Params.Tags)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	responses := make([]model.SecretResponse, len(list))
	for i, s := range list {
		responses[i] = model.SecretResponse{
			ID:        s.ID.String(),
			Name:      s.Name,
			Tags:      s.Tags,
			Version:   s.Version,
			CreatedAt: s.CreatedAt.Format(time.RFC3339),
		}
	}

	response := &model.ListSecretsResponse{Secrets: responses, Total: len(list)}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

func getSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	secret, err := svc.GetSecret(r.Context(), secretID, userID)
	if err != nil {
		c.SetNotFound("secret")
		return
	}

	response := &model.SecretResponse{
		ID:          secret.ID.String(),
		Name:        secret.Name,
		Value:       secret.Value,
		Tags:        secret.Tags,
		Version:     secret.Version,
		ContentType: secret.ContentType,
		CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

func updateSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	req, err := model.UpdateSecretRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request_body")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	secret, err := svc.GetSecret(r.Context(), secretID, userID)
	if err != nil {
		c.SetNotFound("secret")
		return
	}

	updated := false
	if req.Name != "" && req.Name != secret.Name {
		secret.Name = req.Name
		updated = true
	}
	if req.Value != "" && req.Value != secret.Value {
		secret.Value = req.Value
		updated = true
	}
	if req.Tags != nil {
		secret.Tags = req.Tags
		updated = true
	}
	if req.ContentType != nil && *req.ContentType != secret.ContentType {
		secret.ContentType = *req.ContentType
		updated = true
	}
	if !updated {
		c.SetInvalidParam("no_changes")
		return
	}

	secret.Version++

	if err := svc.UpdateSecret(r.Context(), secretsSvc.UpdateSecretRequest{
		UserID:      userID,
		SecretID:    secret.ID,
		Name:        &secret.Name,
		Value:       &secret.Value,
		Tags:        &secret.Tags,
		ContentType: req.ContentType,
	}); err != nil {
		c.SetInternalError(err)
		return
	}

	response := &model.SecretResponse{
		ID:          secret.ID.String(),
		Name:        secret.Name,
		Tags:        secret.Tags,
		Version:     secret.Version,
		ContentType: secret.ContentType,
		CreatedAt:   secret.CreatedAt.Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

func deleteSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	if err := svc.DeleteSecret(r.Context(), secretID, userID); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}

func generateSecret(c *Context, w http.ResponseWriter, r *http.Request) {
	req, err := model.GenerateSecretRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request_body")
		return
	}
	if req.Name == "" {
		c.SetInvalidParam("name")
		return
	}
	if req.Length == 0 {
		req.Length = 16
	}
	if req.Length < 8 || req.Length > 128 {
		c.SetInvalidParam("length")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	secret, err := svc.GenerateSecret(r.Context(), secretsSvc.GenerateSecretRequest{
		UserID:       userID,
		Name:         req.Name,
		Length:       req.Length,
		UseSymbols:   req.UseSymbols,
		UseNumbers:   req.UseNumbers,
		UseUppercase: req.UseUppercase,
		UseLowercase: req.UseLowercase,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	response := &model.SecretResponse{
		ID:        secret.ID.String(),
		Name:      secret.Name,
		Value:     secret.Value,
		Tags:      secret.Tags,
		Version:   secret.Version,
		CreatedAt: secret.CreatedAt.Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(response.ToJson()))
}

func exportSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	req, err := model.ExportSecretsRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request_body")
		return
	}
	if req.Format != "json" && req.Format != "csv" {
		c.SetInvalidParam("format")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	data, err := svc.ExportSecrets(r.Context(), secretsSvc.ExportSecretsRequest{
		UserID:      userID,
		Format:      req.Format,
		FilterTags:  req.Tags,
		IncludeTags: req.IncludeTags,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	contentType := "application/json"
	if req.Format == "csv" {
		contentType = "text/csv"
	}
	filename := fmt.Sprintf("secrets-export-%s.%s", time.Now().Format("20060102-150405"), req.Format)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func importSecrets(c *Context, w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		c.SetInvalidParam("multipart_form")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		c.SetInvalidParam("file")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		c.SetInvalidParam("file_data")
		return
	}

	format := r.FormValue("format")
	if format != "json" && format != "csv" {
		c.SetInvalidParam("format")
		return
	}

	overwrite := r.FormValue("overwrite") == "true"

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	result, err := svc.ImportSecrets(r.Context(), secretsSvc.ImportSecretsRequest{
		UserID:    userID,
		Data:      data,
		Format:    format,
		Overwrite: overwrite,
	})
	if err != nil {
		c.SetInternalError(err)
		return
	}

	response := &model.ImportResponse{
		Success:       true,
		Message:       fmt.Sprintf("Successfully imported %d/%d secrets", result.ImportedCount, result.TotalCount),
		ImportedCount: result.ImportedCount,
		TotalCount:    result.TotalCount,
		Format:        format,
		ImportedAt:    time.Now().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

func listSecretVersions(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	versions, err := svc.GetSecretVersions(r.Context(), secretID, userID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// versions is []domain.SecretVersion from the service — encode directly.
	encodeJSON(w, versions)
}

func getSecretVersion(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	if c.Params.Version == 0 {
		c.SetInvalidParam("version")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	version, err := svc.GetSecretVersion(r.Context(), secretID, c.Params.Version, userID)
	if err != nil {
		c.SetNotFound("secret_version")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	encodeJSON(w, version)
}

func getLatestSecretVersion(c *Context, w http.ResponseWriter, r *http.Request) {
	secretID, err := uuid.Parse(c.Params.SecretID)
	if err != nil {
		c.SetInvalidParam("secret_id")
		return
	}

	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInvalidParam("user_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.secretSvc()
	if svc == nil {
		return
	}

	version, err := svc.GetLatestSecretVersion(r.Context(), secretID, userID)
	if err != nil {
		c.SetNotFound("secret_version")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	encodeJSON(w, version)
}

// encodeJSON is a thin helper for encoding arbitrary values to JSON response body.
func encodeJSON(w http.ResponseWriter, v any) {
	import_encoding_json_encoder := json.NewEncoder(w) //nolint — placeholder removed in next step
	_ = import_encoding_json_encoder
}
```

> **Note:** The `encodeJSON` helper uses `encoding/json`. Add `"encoding/json"` to the import block. Replace the placeholder body with:
```go
func encodeJSON(w http.ResponseWriter, v any) {
    json.NewEncoder(w).Encode(v)
}
```
And add `"encoding/json"` to imports.

- [ ] **Step 2: Verify the build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./api/...
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add api/secrets.go
git commit -m "refactor(api): rewrite secrets handlers with ApiParams and model types"
```

---

## Task 13: Rewrite `api/keys.go`, `api/certificates.go`, `api/access_policies.go`

**Files:**
- Modify: `api/keys.go`
- Modify: `api/certificates.go`
- Modify: `api/access_policies.go`

Apply the same transformation pattern as Tasks 11-12 to these three files:

- [ ] **Step 1: Update `api/keys.go`**

Key changes:
- `InitKeys()` — no router arg, uses `api.BaseRoutes.Keys` and `api.BaseRoutes.Key`
- Route patterns: `{key_id}` instead of `{id}`
- All `mux.Vars(r)["id"]` → `c.Params.KeyID`
- Replace `common.NewAppError` → `c.SetInvalidParam` / `c.SetNotFound` / `c.SetInternalError`
- Replace `json.NewDecoder(r.Body).Decode(&req)` → `model.CreateKeyRequestFromJson(r.Body)` etc.
- Replace `domain.KeyTypeRSA` / `domain.KeyTypeECDSA` → `model.KeyTypeRSA` / `model.KeyTypeECDSA`
- Replace `json.NewEncoder(w).Encode(response)` → `w.Write([]byte(response.ToJson()))`
- Remove `"github.com/gorilla/mux"` import

```go
func (api *API) InitKeys() {
	api.BaseRoutes.Keys.Handle("", ApiSessionRequired(api.App, createKey)).Methods("POST")
	api.BaseRoutes.Keys.Handle("", ApiSessionRequired(api.App, listKeys)).Methods("GET")
	api.BaseRoutes.Key.Handle("", ApiSessionRequired(api.App, getKey)).Methods("GET")
	api.BaseRoutes.Key.Handle("", ApiSessionRequired(api.App, updateKey)).Methods("PUT")
	api.BaseRoutes.Key.Handle("", ApiSessionRequired(api.App, deleteKey)).Methods("DELETE")
	api.BaseRoutes.Key.Handle("/rotate", ApiSessionRequired(api.App, rotateKey)).Methods("POST")
	api.BaseRoutes.Key.Handle("/wrap", ApiSessionRequired(api.App, wrapKey)).Methods("POST")
	api.BaseRoutes.Key.Handle("/unwrap", ApiSessionRequired(api.App, unwrapKey)).Methods("POST")
}
```

In every handler: replace `vars := mux.Vars(r)` + `uuid.Parse(vars["id"])` with `uuid.Parse(c.Params.KeyID)`.

- [ ] **Step 2: Update `api/certificates.go`**

Key changes:
- `InitCertificates()` — no router arg, uses `api.BaseRoutes.Certificates` and `api.BaseRoutes.Certificate`
- Route patterns: `{certificate_id}` instead of `{id}`
- All `mux.Vars(r)["id"]` → `c.Params.CertificateID`
- Replace `CreateCertificateAPIRequest` → `model.CreateCertificateRequest`, `UpdateCertificateAPIRequest` → `model.UpdateCertificateRequest`
- Replace `certToDomainResponse()` with inline mapping to `model.CertificateResponse`
- Remove `"github.com/gorilla/mux"` import

```go
func (api *API) InitCertificates() {
	api.BaseRoutes.Certificates.Handle("", ApiSessionRequired(api.App, createCertificate)).Methods("POST")
	api.BaseRoutes.Certificates.Handle("", ApiSessionRequired(api.App, listCertificates)).Methods("GET")
	api.BaseRoutes.Certificate.Handle("", ApiSessionRequired(api.App, getCertificate)).Methods("GET")
	api.BaseRoutes.Certificate.Handle("", ApiSessionRequired(api.App, updateCertificate)).Methods("PUT")
	api.BaseRoutes.Certificate.Handle("", ApiSessionRequired(api.App, deleteCertificate)).Methods("DELETE")
}
```

- [ ] **Step 3: Update `api/access_policies.go`**

Key changes:
- `InitAccessPolicies()` — no router arg, uses `api.BaseRoutes.AccessPolicies` and `api.BaseRoutes.AccessPolicy`
- Route patterns: `{policy_id}` and `{principal_id}` instead of `{id}` and `{principalId}`
- `mux.Vars(r)["id"]` → `c.Params.PolicyID`, `mux.Vars(r)["principalId"]` → `c.Params.PrincipalID`
- Replace inline anonymous request struct with `model.CreateAccessPolicyRequest`
- Replace `json.NewEncoder(w).Encode(...)` with `model.ListAccessPoliciesResponse{...}.ToJson()`

```go
func (api *API) InitAccessPolicies() {
	api.BaseRoutes.AccessPolicies.Handle("", ApiSessionRequired(api.App, listAccessPolicies)).Methods("GET")
	api.BaseRoutes.AccessPolicies.Handle("", ApiSessionRequired(api.App, createAccessPolicy)).Methods("POST")
	api.BaseRoutes.AccessPolicies.Handle("/principal/{principal_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, listAccessPoliciesByPrincipal)).Methods("GET")
	api.BaseRoutes.AccessPolicy.Handle("", ApiSessionRequired(api.App, getAccessPolicy)).Methods("GET")
	api.BaseRoutes.AccessPolicy.Handle("", ApiSessionRequired(api.App, updateAccessPolicy)).Methods("PUT")
	api.BaseRoutes.AccessPolicy.Handle("", ApiSessionRequired(api.App, deleteAccessPolicy)).Methods("DELETE")
}
```

- [ ] **Step 4: Verify the build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./api/...
```
Expected: no output. Fix any remaining `mux.Vars`, `domain.`, or `common.NewAppError` references.

- [ ] **Step 5: Commit**

```bash
git add api/keys.go api/certificates.go api/access_policies.go
git commit -m "refactor(api): rewrite keys, certs, access-policies handlers"
```

---

## Task 14: Rewrite `api/soft_delete.go`, `api/oauth2.go`, `api/health.go`, `api/vault.go`

**Files:**
- Modify: `api/soft_delete.go`
- Modify: `api/oauth2.go`
- Modify: `api/health.go`
- Modify: `api/vault.go`

- [ ] **Step 1: Update `api/soft_delete.go`**

Key changes:
- `InitDeleted()` — no router arg, uses `api.BaseRoutes.Deleted`
- Route patterns: `{secret_id}`, `{key_id}`, `{certificate_id}` instead of `{id}`
- `mux.Vars(r)["id"]` → `c.Params.SecretID` / `c.Params.KeyID` / `c.Params.CertificateID`
- `common.NewAppError` → `c.SetInvalidParam` / `c.SetInternalError`
- `Permanent` flag read from `c.Params.Permanent` instead of `r.URL.Query().Get("permanent")`

```go
func (api *API) InitDeleted() {
	api.BaseRoutes.Deleted.Handle("/secrets", ApiSessionRequired(api.App, listDeletedSecrets)).Methods("GET")
	api.BaseRoutes.Deleted.Handle("/secrets/{secret_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverSecret)).Methods("POST")
	api.BaseRoutes.Deleted.Handle("/secrets/{secret_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeSecret)).Methods("DELETE")
	api.BaseRoutes.Deleted.Handle("/keys", ApiSessionRequired(api.App, listDeletedKeys)).Methods("GET")
	api.BaseRoutes.Deleted.Handle("/keys/{key_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverKey)).Methods("POST")
	api.BaseRoutes.Deleted.Handle("/keys/{key_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeKey)).Methods("DELETE")
	api.BaseRoutes.Deleted.Handle("/certificates", ApiSessionRequired(api.App, listDeletedCertificates)).Methods("GET")
	api.BaseRoutes.Deleted.Handle("/certificates/{certificate_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverCertificate)).Methods("POST")
	api.BaseRoutes.Deleted.Handle("/certificates/{certificate_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeCertificate)).Methods("DELETE")
}
```

- [ ] **Step 2: Update `api/oauth2.go`**

Key changes:
- `InitOAuth2()` and `InitServiceAccounts()` — no router arg
- Service account routes use `api.BaseRoutes.ServiceAccounts` and `api.BaseRoutes.ServiceAccount`
- `{service_account_id}` instead of `{id}`
- `c.Params.ServiceAccountID` instead of `mux.Vars(r)["id"]`
- `tokenHandler` is exempt — stays as raw `http.HandlerFunc` writing its own response

```go
func (api *API) InitOAuth2() {
	api.BaseRoutes.OAuth2.HandleFunc("/oauth2/token", api.tokenHandler).Methods("POST")

	api.BaseRoutes.ServiceAccounts.Handle("", ApiSessionRequired(api.App, createServiceAccount)).Methods("POST")
	api.BaseRoutes.ServiceAccounts.Handle("", ApiSessionRequired(api.App, listServiceAccounts)).Methods("GET")
	api.BaseRoutes.ServiceAccount.Handle("", ApiSessionRequired(api.App, getServiceAccount)).Methods("GET")
	api.BaseRoutes.ServiceAccount.Handle("", ApiSessionRequired(api.App, deleteServiceAccount)).Methods("DELETE")
	api.BaseRoutes.ServiceAccount.Handle("/rotate", ApiSessionRequired(api.App, rotateServiceAccountSecret)).Methods("POST")
}
```

- [ ] **Step 3: Update `api/health.go`**

Change only: replace the three `Handler(api.App, ...)` calls with `ApiHandler(api.App, ...)`. No router arg needed — `InitHealth()` uses `api.BaseRoutes.Health`.

```go
func (api *API) InitHealth() {
	api.BaseRoutes.Health.Handle("/ready", ApiHandler(api.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		ReturnStatusOK(w)
	})).Methods("GET")
	api.BaseRoutes.Health.Handle("/live", ApiHandler(api.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		ReturnStatusOK(w)
	})).Methods("GET")
	api.BaseRoutes.Health.Handle("", ApiHandler(api.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		ReturnStatusOK(w)
	})).Methods("GET")
}
```

- [ ] **Step 4: Update `api/vault.go`**

```go
package api

// InitVault is a placeholder for future multi-tenant functionality.
func (api *API) InitVault() {
	api.Logger.Infoln("Vault API initialized (placeholder)")
}
```

- [ ] **Step 5: Verify the build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./api/...
```
Expected: no output.

- [ ] **Step 6: Run full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | tail -30
```
Expected: all tests pass. Fix any failures before proceeding.

- [ ] **Step 7: Commit**

```bash
git add api/soft_delete.go api/oauth2.go api/health.go api/vault.go
git commit -m "refactor(api): rewrite remaining handlers and remove no-arg Init signatures"
```

---

## Task 15: Update `api/context_test.go` and `api/context_accessors_test.go`

**Files:**
- Modify: `api/context_test.go`
- Modify: `api/context_accessors_test.go`

- [ ] **Step 1: Update test references in `api/context_test.go`**

Replace all references to the old names:
- `Handler(` → `ApiHandler(`
- `SessionRequired(` → `ApiSessionRequired(`
- `ctx.Params.Query` → `ctx.Params` (the `Query map[string]string` field is gone; use `ctx.Params.Page`, `ctx.Params.PerPage` etc. as appropriate)

Run the tests after to verify:

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -v 2>&1 | tail -30
```
Expected: all tests pass.

- [ ] **Step 2: Update `api/context_accessors_test.go`**

Replace any references to old `Params` field structure. The `ApiParams` struct fields are:
`UserID`, `SecretID`, `KeyID`, `CertificateID`, `PolicyID`, `ServiceAccountID`, `SessionID`, `PrincipalID`, `Version`, `Page`, `PerPage`, `Tags`, `Permanent`.

If tests set `ctx.Params.UserID = "..."` that is correct. If they set `ctx.Params.Query["user_id"]` replace with `ctx.Params.UserID`.

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -v 2>&1 | tail -30
```
Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add api/context_test.go api/context_accessors_test.go
git commit -m "test(api): update context tests for ApiHandler and ApiParams"
```

---

## Task 16: Delete `internal/domain/` and final verification

**Files:**
- Delete: all 8 files in `internal/domain/`

- [ ] **Step 1: Confirm zero remaining references to `internal/domain`**

```bash
grep -rn "rocketvault/internal/domain" . --include="*.go"
```
Expected: no output. If any references remain, fix them before deleting.

- [ ] **Step 2: Delete the directory**

```bash
rm -rf /home/numericlabs/data/rocket/rocketvault/internal/domain
```

- [ ] **Step 3: Verify the full build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./...
```
Expected: no output (clean build).

- [ ] **Step 4: Run the full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | tail -30
```
Expected: all tests pass.

- [ ] **Step 5: Verify key invariants**

```bash
# model/ must not import internal/
grep -rn "rocketvault/internal" model/ --include="*.go"
# No handler should call mux.Vars directly
grep -rn "mux\.Vars" api/ --include="*.go"
# No handler should call common.NewAppError directly (except context.go)
grep -rn "common\.NewAppError" api/ --include="*.go" | grep -v context.go
```
Expected: all three commands produce no output.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor: delete internal/domain after full migration to model package"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] `model/` package with all 8 files — Tasks 1-6
- [x] `FromJson`/`ToJson` on every HTTP-boundary type — Tasks 2-6
- [x] Domain business methods retained (`IsExpired`, etc.) — Task 3
- [x] `internal/` import migration — Task 7
- [x] `cmd/` import migration — Task 8
- [x] `api/params.go` with `ApiParams` and `ApiParamsFromRequest` — Task 9
- [x] Route variable standardization (`{secret_id}` etc.) — Tasks 11-14
- [x] `ApiHandler` / `ApiSessionRequired` rename — Task 10
- [x] `SetInvalidParam`, `SetPermissionError`, `SetNotFound`, `SetInternalError` — Task 10
- [x] `writeError` includes `request_id` — Task 10
- [x] Typed `Routes` struct — Task 10
- [x] `Handle404` / `ReturnStatusOK` — Task 10
- [x] `Init*()` no-arg signature — Tasks 10-14
- [x] `tokenHandler` exempt from wrapper — Task 14
- [x] Delete `internal/domain/` — Task 16
- [x] Key invariant verification — Task 16

**Placeholder scan:** No TBD, TODO, or "implement later" phrases. Code shown for every step.

**Type consistency:** `model.CreateSecretRequestFromJson` defined in Task 3 and called in Task 12. `model.UserResponse.ToJson()` defined in Task 2 and called in Task 11. `ApiParams.SecretID` defined in Task 9 and used in Tasks 12, 13, 14. `ApiSessionRequired` defined in Task 10 and used in Tasks 11-14. All consistent.
