# Certificate Policy Resource Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Certificate Policy as a separate, updatable resource associated with each certificate, matching Azure Key Vault's `GET /certificates/{name}/policy` and `PUT /certificates/{name}/policy`. The policy stores: lifetime actions (auto-renew or email trigger at N days before expiry), key properties (exportable, key type, key size, reuse key, curve name), X.509 properties (SAN, EKU, key usage, validity months), and issuer information. The renewal scheduler reads the policy's lifetime action instead of the certificate's flat `auto_renew`/`renewal_days` fields.

**Architecture:** New `certificate_policies` DB table. `CertificatePolicyRepository` + `CertificatePolicyService` follow the established DDD pattern. Two HTTP endpoints `GET /certificates/{cert_id}/policy` and `PUT /certificates/{cert_id}/policy` are added. The existing `RenewalService` is updated to read from the policy if one exists, falling back to the old `auto_renew`/`renewal_days` fields for backward compatibility.

**Tech Stack:** Go 1.24.2, SQLite/PostgreSQL, `encoding/json`, testify.

**Spec:** `docs/plans/2026-05-23-azure-keyvault-parity-audit.md` §Certificates — "Certificate Policy (separate resource)" row.

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `model/certificate_policy.go` | Create | Domain types: `CertificatePolicy`, `LifetimeAction`, `KeyProperties`, `X509Properties`, `IssuerParameters`, request/response types |
| `internal/db/db.go` | Modify | Add `certificate_policies` table to `createOptimizedSchema` |
| `internal/repositories/certificate_policy_repository.go` | Create | `CertificatePolicyRepository` interface + implementation |
| `internal/repositories/certificate_policy_repository_test.go` | Create | Repository tests |
| `internal/services/certificates/certificate_policy_service.go` | Create | `CertificatePolicyService` — `GetPolicy`, `SetPolicy` |
| `internal/services/certificates/certificate_policy_service_test.go` | Create | Service tests |
| `internal/services/certificates/renewal_service.go` | Modify | Read lifetime action from policy; fall back to flat fields |
| `internal/container/service_container.go` | Modify | Wire `CertificatePolicyRepository` and `CertificatePolicyService` |
| `api/certificates.go` | Modify | Add `GET /{cert_id}/policy` and `PUT /{cert_id}/policy` routes + handlers |
| `api/certificates_policy_test.go` | Create | HTTP-layer tests for policy endpoints |

---

## Task 1: Define Certificate Policy model types

**Files:**
- Create: `model/certificate_policy.go`

- [ ] **Step 1: Create `model/certificate_policy.go`**

```go
package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// LifetimeActionType defines the action to take as a certificate nears expiry.
type LifetimeActionType string

const (
	LifetimeActionAutoRenew     LifetimeActionType = "AutoRenew"
	LifetimeActionEmailContacts LifetimeActionType = "EmailContacts"
)

// LifetimeAction specifies what to do N days before a certificate expires.
type LifetimeAction struct {
	Action           LifetimeActionType `json:"action"`
	DaysBeforeExpiry int                `json:"days_before_expiry"`
}

// KeyProperties specifies the cryptographic properties for the certificate's key.
type KeyProperties struct {
	Exportable bool   `json:"exportable"`
	KeyType    string `json:"key_type"`   // RSA, EC
	KeySize    int    `json:"key_size"`   // e.g. 2048, 4096 for RSA
	ReuseKey   bool   `json:"reuse_key"`
	Curve      string `json:"curve,omitempty"` // P-256, P-384, P-521
}

// X509Properties specifies the X.509 certificate properties.
type X509Properties struct {
	SubjectAltNames []string `json:"subject_alt_names,omitempty"` // DNS SANs
	EKU             []string `json:"eku,omitempty"`               // Extended Key Usage OIDs
	KeyUsage        []string `json:"key_usage,omitempty"`         // DigitalSignature, KeyEncipherment, etc.
	ValidityMonths  int      `json:"validity_months"`
}

// IssuerParameters identifies the certificate issuer.
type IssuerParameters struct {
	Name            string `json:"name"`             // "Self" or CA issuer name
	CertificateType string `json:"certificate_type"` // "OV-SSL", "EV-SSL", etc.
}

// CertificatePolicy is the policy resource associated with a certificate.
// It controls renewal behaviour, key properties, and X.509 properties.
type CertificatePolicy struct {
	ID            uuid.UUID          `json:"id"`
	CertificateID uuid.UUID          `json:"certificate_id"`
	UpdatedAt     time.Time          `json:"updated_at"`
	LifetimeAction LifetimeAction    `json:"lifetime_action"`
	KeyProperties  KeyProperties     `json:"key_properties"`
	X509Properties X509Properties    `json:"x509_properties"`
	Issuer         IssuerParameters  `json:"issuer"`
}

// --- HTTP request/response types ---

type SetCertificatePolicyRequest struct {
	LifetimeAction LifetimeAction   `json:"lifetime_action"`
	KeyProperties  KeyProperties    `json:"key_properties"`
	X509Properties X509Properties   `json:"x509_properties"`
	Issuer         IssuerParameters `json:"issuer"`
}

func SetCertificatePolicyRequestFromJSON(r io.Reader) (*SetCertificatePolicyRequest, error) {
	var req SetCertificatePolicyRequest
	return &req, json.NewDecoder(r).Decode(&req)
}
```

- [ ] **Step 2: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1 | head -10
```

- [ ] **Step 3: Commit**

```bash
git add model/certificate_policy.go
git commit -m "feat(model): add CertificatePolicy, LifetimeAction, KeyProperties, X509Properties types"
```

---

## Task 2: Add `certificate_policies` table

**Files:**
- Modify: `internal/db/db.go`

- [ ] **Step 1: Add table to `createOptimizedSchema`**

In `internal/db/db.go`, find `createOptimizedSchema`. After the `certificates` table, add:

```sql
CREATE TABLE IF NOT EXISTS certificate_policies (
    id TEXT PRIMARY KEY,
    certificate_id TEXT NOT NULL UNIQUE REFERENCES certificates(id) ON DELETE CASCADE,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lifetime_action TEXT NOT NULL DEFAULT '{"action":"AutoRenew","days_before_expiry":30}',
    key_properties TEXT NOT NULL DEFAULT '{"exportable":true,"key_type":"RSA","key_size":2048,"reuse_key":false}',
    x509_properties TEXT NOT NULL DEFAULT '{"validity_months":12}',
    issuer TEXT NOT NULL DEFAULT '{"name":"Self","certificate_type":""}'
);
CREATE INDEX IF NOT EXISTS idx_cert_policies_cert_id ON certificate_policies(certificate_id);
```

Note: the composite fields are stored as JSON strings — this avoids wide schemas and allows extension without migrations.

- [ ] **Step 2: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1 | head -5
```

- [ ] **Step 3: Commit**

```bash
git add internal/db/db.go
git commit -m "feat(db): add certificate_policies table"
```

---

## Task 3: Implement `CertificatePolicyRepository`

**Files:**
- Create: `internal/repositories/certificate_policy_repository.go`
- Create: `internal/repositories/certificate_policy_repository_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/repositories/certificate_policy_repository_test.go`:

```go
package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestCertificatePolicyRepository_SetAndGet(t *testing.T) {
	db := setupCertificateTestDB(t)
	certID := createTestCertRow(t, db) // helper: INSERT a row into certificates
	repo := repositories.NewCertificatePolicyRepository(db, newTestLogger(t))

	policy := &model.CertificatePolicy{
		ID:            uuid.New(),
		CertificateID: certID,
		UpdatedAt:     time.Now(),
		LifetimeAction: model.LifetimeAction{
			Action:           model.LifetimeActionAutoRenew,
			DaysBeforeExpiry: 14,
		},
		KeyProperties: model.KeyProperties{
			Exportable: true,
			KeyType:    "RSA",
			KeySize:    4096,
			ReuseKey:   false,
		},
		X509Properties: model.X509Properties{ValidityMonths: 24},
		Issuer:         model.IssuerParameters{Name: "Self"},
	}

	require.NoError(t, repo.Upsert(context.Background(), policy))

	got, err := repo.GetByCertificateID(context.Background(), certID)
	require.NoError(t, err)
	assert.Equal(t, model.LifetimeActionAutoRenew, got.LifetimeAction.Action)
	assert.Equal(t, 14, got.LifetimeAction.DaysBeforeExpiry)
	assert.Equal(t, 4096, got.KeyProperties.KeySize)
	assert.Equal(t, 24, got.X509Properties.ValidityMonths)
}

func TestCertificatePolicyRepository_NotFound(t *testing.T) {
	db := setupCertificateTestDB(t)
	repo := repositories.NewCertificatePolicyRepository(db, newTestLogger(t))

	_, err := repo.GetByCertificateID(context.Background(), uuid.New())
	require.Error(t, err)
}
```

- [ ] **Step 2: Implement the repository**

Create `internal/repositories/certificate_policy_repository.go`:

```go
package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// CertificatePolicyRepository manages certificate policy records.
type CertificatePolicyRepository interface {
	Upsert(ctx context.Context, policy *model.CertificatePolicy) error
	GetByCertificateID(ctx context.Context, certID uuid.UUID) (*model.CertificatePolicy, error)
}

type certPolicyRepository struct {
	db  *sql.DB
	log *logging.Logger
}

// NewCertificatePolicyRepository creates a new CertificatePolicyRepository.
func NewCertificatePolicyRepository(db *sql.DB, log *logging.Logger) CertificatePolicyRepository {
	return &certPolicyRepository{db: db, log: log}
}

func (r *certPolicyRepository) Upsert(ctx context.Context, p *model.CertificatePolicy) error {
	la, _ := json.Marshal(p.LifetimeAction)
	kp, _ := json.Marshal(p.KeyProperties)
	xp, _ := json.Marshal(p.X509Properties)
	iss, _ := json.Marshal(p.Issuer)

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO certificate_policies (id, certificate_id, updated_at, lifetime_action, key_properties, x509_properties, issuer)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(certificate_id) DO UPDATE SET
			id = excluded.id,
			updated_at = excluded.updated_at,
			lifetime_action = excluded.lifetime_action,
			key_properties = excluded.key_properties,
			x509_properties = excluded.x509_properties,
			issuer = excluded.issuer`,
		p.ID.String(), p.CertificateID.String(), time.Now(),
		string(la), string(kp), string(xp), string(iss),
	)
	if err != nil {
		return fmt.Errorf("failed to upsert certificate policy: %w", err)
	}
	return nil
}

func (r *certPolicyRepository) GetByCertificateID(ctx context.Context, certID uuid.UUID) (*model.CertificatePolicy, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, certificate_id, updated_at, lifetime_action, key_properties, x509_properties, issuer
		 FROM certificate_policies WHERE certificate_id = ?`,
		certID.String(),
	)

	var p model.CertificatePolicy
	var idStr, certIDStr string
	var updatedAt time.Time
	var laJSON, kpJSON, xpJSON, issJSON string

	err := row.Scan(&idStr, &certIDStr, &updatedAt, &laJSON, &kpJSON, &xpJSON, &issJSON)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificate policy not found for certificate %s", certID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan certificate policy: %w", err)
	}

	p.ID, _ = uuid.Parse(idStr)
	p.CertificateID, _ = uuid.Parse(certIDStr)
	p.UpdatedAt = updatedAt
	json.Unmarshal([]byte(laJSON), &p.LifetimeAction)
	json.Unmarshal([]byte(kpJSON), &p.KeyProperties)
	json.Unmarshal([]byte(xpJSON), &p.X509Properties)
	json.Unmarshal([]byte(issJSON), &p.Issuer)

	return &p, nil
}
```

- [ ] **Step 3: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/repositories/... -run "TestCertificatePolicyRepository" -v 2>&1 | tail -15
```

Expected: both tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/repositories/certificate_policy_repository.go internal/repositories/certificate_policy_repository_test.go
git commit -m "feat(repositories): add CertificatePolicyRepository with Upsert and GetByCertificateID"
```

---

## Task 4: Implement `CertificatePolicyService`

**Files:**
- Create: `internal/services/certificates/certificate_policy_service.go`
- Create: `internal/services/certificates/certificate_policy_service_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/services/certificates/certificate_policy_service_test.go`:

```go
package certificates_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestSetAndGetCertificatePolicy(t *testing.T) {
	svc, ownerID, _ := setupCertServiceWithKey(t)
	certID := createTestCert(t, svc, ownerID)

	policy := &model.SetCertificatePolicyRequest{
		LifetimeAction: model.LifetimeAction{
			Action:           model.LifetimeActionAutoRenew,
			DaysBeforeExpiry: 7,
		},
		KeyProperties: model.KeyProperties{Exportable: true, KeyType: "RSA", KeySize: 2048},
		X509Properties: model.X509Properties{ValidityMonths: 12},
		Issuer:         model.IssuerParameters{Name: "Self"},
	}

	require.NoError(t, svc.SetPolicy(context.Background(), certID, ownerID, policy))

	got, err := svc.GetPolicy(context.Background(), certID, ownerID)
	require.NoError(t, err)
	assert.Equal(t, 7, got.LifetimeAction.DaysBeforeExpiry)
	assert.Equal(t, 2048, got.KeyProperties.KeySize)
}

func TestGetPolicy_ForbiddenForOtherUser(t *testing.T) {
	svc, ownerID, _ := setupCertServiceWithKey(t)
	certID := createTestCert(t, svc, ownerID)
	other := uuid.New()

	require.NoError(t, svc.SetPolicy(context.Background(), certID, ownerID, &model.SetCertificatePolicyRequest{
		LifetimeAction: model.LifetimeAction{Action: model.LifetimeActionAutoRenew, DaysBeforeExpiry: 30},
		KeyProperties:  model.KeyProperties{Exportable: true, KeyType: "RSA", KeySize: 2048},
		X509Properties: model.X509Properties{ValidityMonths: 12},
		Issuer:         model.IssuerParameters{Name: "Self"},
	}))

	_, err := svc.GetPolicy(context.Background(), certID, other)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}
```

- [ ] **Step 2: Implement the service**

Create `internal/services/certificates/certificate_policy_service.go`:

```go
package certificates

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// CertificatePolicyService manages certificate policies.
type CertificatePolicyService interface {
	GetPolicy(ctx context.Context, certID, userID uuid.UUID) (*model.CertificatePolicy, error)
	SetPolicy(ctx context.Context, certID, userID uuid.UUID, req *model.SetCertificatePolicyRequest) error
}

type certPolicyService struct {
	certRepo   repositories.CertificateRepository
	policyRepo repositories.CertificatePolicyRepository
	logger     AuditLogger // use the same interface already defined in the certificates package
}

// NewCertificatePolicyService creates a new CertificatePolicyService.
func NewCertificatePolicyService(
	certRepo repositories.CertificateRepository,
	policyRepo repositories.CertificatePolicyRepository,
	logger AuditLogger,
) CertificatePolicyService {
	return &certPolicyService{certRepo: certRepo, policyRepo: policyRepo, logger: logger}
}

// GetPolicy retrieves the policy for a certificate, enforcing ownership.
func (s *certPolicyService) GetPolicy(ctx context.Context, certID, userID uuid.UUID) (*model.CertificatePolicy, error) {
	cert, err := s.certRepo.Read(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("certificate not found: %w", err)
	}
	if cert.UserID != userID {
		return nil, fmt.Errorf("forbidden: cannot access another user's certificate policy")
	}

	policy, err := s.policyRepo.GetByCertificateID(ctx, certID)
	if err != nil {
		// Return a default policy if none has been set
		return s.defaultPolicy(certID), nil
	}
	return policy, nil
}

// SetPolicy creates or replaces the policy for a certificate.
func (s *certPolicyService) SetPolicy(ctx context.Context, certID, userID uuid.UUID, req *model.SetCertificatePolicyRequest) error {
	cert, err := s.certRepo.Read(ctx, certID)
	if err != nil {
		return fmt.Errorf("certificate not found: %w", err)
	}
	if cert.UserID != userID {
		return fmt.Errorf("forbidden: cannot modify another user's certificate policy")
	}

	policy := &model.CertificatePolicy{
		ID:             uuid.New(),
		CertificateID:  certID,
		UpdatedAt:      time.Now(),
		LifetimeAction: req.LifetimeAction,
		KeyProperties:  req.KeyProperties,
		X509Properties: req.X509Properties,
		Issuer:         req.Issuer,
	}

	if err := s.policyRepo.Upsert(ctx, policy); err != nil {
		s.logger.LogAuditError(userID.String(), "set_certificate_policy", "failed", "failed to save policy", err)
		return fmt.Errorf("failed to save certificate policy: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "set_certificate_policy", "success",
		fmt.Sprintf("policy set for certificate %s", certID))
	return nil
}

// defaultPolicy returns a sensible default policy matching existing auto_renew/renewal_days fields.
func (s *certPolicyService) defaultPolicy(certID uuid.UUID) *model.CertificatePolicy {
	return &model.CertificatePolicy{
		CertificateID: certID,
		LifetimeAction: model.LifetimeAction{
			Action:           model.LifetimeActionAutoRenew,
			DaysBeforeExpiry: 30,
		},
		KeyProperties: model.KeyProperties{
			Exportable: true,
			KeyType:    "RSA",
			KeySize:    2048,
		},
		X509Properties: model.X509Properties{ValidityMonths: 12},
		Issuer:         model.IssuerParameters{Name: "Self"},
	}
}
```

- [ ] **Step 3: Check `AuditLogger` interface name in package**

Run `grep -r "AuditLogger\|auditLogger\|LogAuditInfo" internal/services/certificates/ | head -5` to confirm the exact interface name used. If it differs, use the correct name.

- [ ] **Step 4: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/services/certificates/... -run "TestSetAndGetCertificatePolicy|TestGetPolicy_Forbidden" -v 2>&1 | tail -20
```

Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/services/certificates/certificate_policy_service.go internal/services/certificates/certificate_policy_service_test.go
git commit -m "feat(services): add CertificatePolicyService with GetPolicy and SetPolicy"
```

---

## Task 5: Wire into service container

**Files:**
- Modify: `internal/container/service_container.go`

- [ ] **Step 1: Add repository and service fields**

Find the struct fields. Add:

```go
certPolicyRepo repositories.CertificatePolicyRepository
certPolicyService certificates.CertificatePolicyService
```

- [ ] **Step 2: Initialize in setup**

After the `certRepo` initialization, add:

```go
container.certPolicyRepo = repositories.NewCertificatePolicyRepository(db, logger)
container.certPolicyService = certificates.NewCertificatePolicyService(
    container.certRepo, container.certPolicyRepo, auditLogger,
)
```

- [ ] **Step 3: Add accessor**

```go
func (c *ServiceContainer) GetCertificatePolicyService() certificates.CertificatePolicyService {
    return c.certPolicyService
}
```

- [ ] **Step 4: Build**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... 2>&1 | head -10
```

- [ ] **Step 5: Commit**

```bash
git add internal/container/service_container.go
git commit -m "feat(container): wire CertificatePolicyRepository and CertificatePolicyService"
```

---

## Task 6: Update `RenewalService` to read from policy

**Files:**
- Modify: `internal/services/certificates/renewal_service.go`

- [ ] **Step 1: Locate the renewal check logic**

In `internal/services/certificates/renewal_service.go`, find where `auto_renew` and `renewal_days` are read from the certificate struct. Typically this looks like:

```go
if cert.AutoRenew && daysUntilExpiry <= cert.RenewalDays {
    // trigger renewal
}
```

- [ ] **Step 2: Add policy-aware renewal check**

Replace the flat-field check with a policy-first approach:

```go
// Prefer policy lifetime action; fall back to flat fields for backward compatibility
daysBeforeExpiry := cert.RenewalDays
shouldAutoRenew := cert.AutoRenew
lifetimeAction := model.LifetimeActionAutoRenew

if s.policyRepo != nil {
    if policy, err := s.policyRepo.GetByCertificateID(ctx, cert.ID); err == nil {
        daysBeforeExpiry = policy.LifetimeAction.DaysBeforeExpiry
        lifetimeAction = policy.LifetimeAction.Action
        shouldAutoRenew = (lifetimeAction == model.LifetimeActionAutoRenew)
    }
}

if shouldAutoRenew && daysUntilExpiry <= daysBeforeExpiry {
    // trigger renewal
}
```

- [ ] **Step 3: Add `policyRepo` to the renewal service struct**

Find the `renewalService` struct. Add:

```go
policyRepo repositories.CertificatePolicyRepository
```

Update the `NewRenewalService` constructor to accept and store it.

- [ ] **Step 4: Build and run renewal tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./internal/services/certificates/... -v 2>&1 | grep -E "PASS|FAIL|---"
```

Expected: no regressions; existing renewal tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/services/certificates/renewal_service.go
git commit -m "feat(certificates): renewal service reads lifetime action from policy; falls back to flat fields"
```

---

## Task 7: Add HTTP policy endpoints

**Files:**
- Modify: `api/certificates.go`
- Create: `api/certificates_policy_test.go`

- [ ] **Step 1: Write failing HTTP tests**

Create `api/certificates_policy_test.go`:

```go
package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestGetCertificatePolicy_ReturnsDefault(t *testing.T) {
	srv := newTestServer(t)
	certID := createTestCertificate(t, srv)

	resp := doRequest(t, srv, "GET", "/api/v1/certificates/"+certID+"/policy", nil)
	require.Equal(t, http.StatusOK, resp.Code)

	var policy model.CertificatePolicy
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&policy))
	assert.Equal(t, model.LifetimeActionAutoRenew, policy.LifetimeAction.Action)
}

func TestSetAndGetCertificatePolicy_HTTP(t *testing.T) {
	srv := newTestServer(t)
	certID := createTestCertificate(t, srv)

	setBody, _ := json.Marshal(model.SetCertificatePolicyRequest{
		LifetimeAction: model.LifetimeAction{Action: model.LifetimeActionAutoRenew, DaysBeforeExpiry: 7},
		KeyProperties:  model.KeyProperties{Exportable: true, KeyType: "RSA", KeySize: 4096},
		X509Properties: model.X509Properties{ValidityMonths: 24},
		Issuer:         model.IssuerParameters{Name: "Self"},
	})

	setResp := doRequest(t, srv, "PUT", "/api/v1/certificates/"+certID+"/policy", setBody)
	require.Equal(t, http.StatusOK, setResp.Code)

	getResp := doRequest(t, srv, "GET", "/api/v1/certificates/"+certID+"/policy", nil)
	require.Equal(t, http.StatusOK, getResp.Code)

	var got model.CertificatePolicy
	json.NewDecoder(getResp.Body).Decode(&got)
	assert.Equal(t, 7, got.LifetimeAction.DaysBeforeExpiry)
	assert.Equal(t, 4096, got.KeyProperties.KeySize)
}
```

- [ ] **Step 2: Run to confirm tests fail (404)**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./api/... -run "TestGetCertificatePolicy|TestSetAndGetCertificatePolicy" -v 2>&1 | tail -10
```

- [ ] **Step 3: Register routes**

In `api/certificates.go`, find the route registration function. Add before the log line:

```go
cert.Handle("/{cert_id:[A-Fa-f0-9-]+}/policy", ApiSessionRequired(api.App, getCertificatePolicy)).Methods("GET")
cert.Handle("/{cert_id:[A-Fa-f0-9-]+}/policy", ApiSessionRequired(api.App, setCertificatePolicy)).Methods("PUT")
```

- [ ] **Step 4: Implement `getCertificatePolicy` handler**

```go
func getCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certID, err := uuid.Parse(vars["cert_id"])
	if err != nil {
		c.SetInvalidParamError("cert_id")
		c.HandleError(w, r)
		return
	}

	userID := c.GetUserID()
	policySvc := c.App.GetServiceContainer().GetCertificatePolicyService()
	policy, err := policySvc.GetPolicy(r.Context(), certID, userID)
	if err != nil {
		c.SetError(err.Error(), http.StatusForbidden)
		c.HandleError(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}
```

- [ ] **Step 5: Implement `setCertificatePolicy` handler**

```go
func setCertificatePolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certID, err := uuid.Parse(vars["cert_id"])
	if err != nil {
		c.SetInvalidParamError("cert_id")
		c.HandleError(w, r)
		return
	}

	req, err := model.SetCertificatePolicyRequestFromJSON(r.Body)
	if err != nil {
		c.SetInvalidParamError("body")
		c.HandleError(w, r)
		return
	}

	userID := c.GetUserID()
	policySvc := c.App.GetServiceContainer().GetCertificatePolicyService()
	if err := policySvc.SetPolicy(r.Context(), certID, userID, req); err != nil {
		c.SetError(err.Error(), http.StatusForbidden)
		c.HandleError(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
}
```

- [ ] **Step 6: Build and run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build ./... && go test ./api/... -run "TestGetCertificatePolicy|TestSetAndGetCertificatePolicy" -v 2>&1 | tail -20
```

Expected: both tests PASS.

- [ ] **Step 7: Commit**

```bash
git add api/certificates.go api/certificates_policy_test.go
git commit -m "feat(api): add GET/PUT /certificates/{id}/policy endpoints"
```

---

## Task 8: Full regression pass

- [ ] **Step 1: Run full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go test ./... 2>&1 | grep -E "FAIL|ok" | sort
```

Expected: all packages `ok`.

- [ ] **Step 2: Build binary**

```bash
cd /home/numericlabs/data/rocket/rocketvault && go build -o /tmp/rocketvault-cert-policy . && echo "build ok"
```

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "feat: certificate policy resource — GET/PUT /certificates/{id}/policy with renewal integration"
```
