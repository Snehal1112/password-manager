# vaultapi Write: Certificates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `CreateCertificate` and `UpsertCertificatePolicy`, completing `vaultapi`'s write surface.

**Architecture:** Plan 18's shape, with one addition: a certificate is created *against an existing key*, so `CreateCertificate` accepts a key name and resolves it — consistent with how every other method addresses resources.

**Tech Stack:** Go 1.25, `github.com/google/uuid`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Write tier".

**Plan-of-plans:** This is plan 20 of 31, closing Group F's `vaultapi` work. Requires plans 01, 04, 07, 18 and 19 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **Vault-scoped routes only.**
- **Mutations are never retried.**
- **No type here may carry a private key or certificate PEM.**
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Verified request contracts

| Method | Route | Body |
|---|---|---|
| Create certificate | `POST /api/v1/vaults/{v}/certificates` | `model.CreateCertificateRequest` (`model/certificate.go:58`) |
| Upsert policy | `PUT /api/v1/vaults/{v}/certificates/{id}/policy` | `model.UpsertCertificatePolicyRequest` (`model/certificate_policy.go:30`) |

Two things this plan has to handle that the earlier write plans did not:

**A certificate is created against an existing key.** `CreateCertificateRequest.KeyID` is a required UUID string (`model/certificate.go:60`). Every other method in this package addresses resources by name and resolves internally, so this one does too: the exported request takes `KeyName`, and `CreateCertificate` resolves it through `KindKeys` before sending. A caller holding a UUID can still pass it, since `Resolver.Resolve` returns a parsed UUID unchanged.

`CAKeyID` and `CACertID` are optional and are also resolved from names, for the same reason.

**The policy upsert is another full replacement.** `UpsertCertificatePolicyRequest` has no pointer fields, exactly like the key rotation policy in plan 19. Omitting a value sets it to zero rather than leaving it alone. This client mirrors that, and plan 22's tool must present it as a replacement.

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/certificates_write.go` (new) | `CreateCertificateRequest`, `CreateCertificate`, `SetCertificatePolicyRequest`, `UpsertCertificatePolicy` |
| `internal/vaultapi/certificates_write_test.go` (new) | Both methods, including key resolution |

---

### Task 1: `CreateCertificate`, resolving the key by name

**Files:**
- Create: `internal/vaultapi/certificates_write.go`
- Create: `internal/vaultapi/certificates_write_test.go`

**Interfaces:**
- Consumes: `Client.Do` (plan 01), `Resolver.Resolve` and `KindKeys` (plan 04), `Certificate`, `certificateWire` (plan 07).
- Produces — plan 22's `create_certificate` calls this:
  - `type CreateCertificateRequest struct { Name, KeyName string; ValidityDays int; Tags []string; AutoRenew bool; RenewalDays int; CAKeyName, CACertName string; Enabled *bool; NotBefore *time.Time }`
  - `func (c *Client) CreateCertificate(ctx context.Context, vault string, req CreateCertificateRequest) (*Certificate, error)`

**Why resolve the key rather than take a UUID:** consistency is the whole argument. Every other method in this package takes a name, and a caller who has just created a key with `CreateKey` has its name in hand more readily than its UUID. Accepting only a UUID would make this the one method that behaves differently, for no benefit — and `Resolve` passes a UUID through unchanged, so nothing is lost.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/certificates_write_test.go`:

```go
package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// certWriteServer serves the key list plus a certificate write.
func certWriteServer(t *testing.T, keysBody string, status int, response string) (*httptest.Server, *writeProbe) {
	t.Helper()

	probe := &writeProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(keysBody))
			return
		}

		probe.calls++
		probe.method, probe.path = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&probe.body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return srv, probe
}

const keysForCertBody = `{"keys":[{"id":"` + rsaKeyID + `","name":"tls-key"}]}`

func TestCreateCertificate_ResolvesTheKeyNameToAnID(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated,
		`{"id":"`+tlsCertID+`","name":"tls-cert","auto_renew":true,"renewal_days":30}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365, AutoRenew: true, RenewalDays: 30,
	})
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/certificates", probe.path)
	require.Equal(t, rsaKeyID, probe.body["key_id"],
		"the exported API takes a key name; the wire takes its id")
	require.Equal(t, "tls-cert", got.Name)
}

func TestCreateCertificate_AcceptsAKeyUUIDDirectly(t *testing.T) {
	srv, probe := certWriteServer(t, `{"keys":[]}`, http.StatusCreated,
		`{"id":"`+tlsCertID+`","name":"tls-cert"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: rsaKeyID, ValidityDays: 365,
	})
	require.NoError(t, err)
	require.Equal(t, rsaKeyID, probe.body["key_id"],
		"a UUID passes through resolution unchanged, so nothing is lost by taking names")
}

func TestCreateCertificate_SendsTheCoreFields(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated,
		`{"id":"`+tlsCertID+`","name":"tls-cert"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365,
		AutoRenew: true, RenewalDays: 30, Tags: []string{"edge"},
	})
	require.NoError(t, err)

	require.Equal(t, "tls-cert", probe.body["name"])
	require.EqualValues(t, 365, probe.body["validity_days"])
	require.Equal(t, true, probe.body["auto_renew"])
	require.EqualValues(t, 30, probe.body["renewal_days"])
	require.Len(t, probe.body["tags"], 1)
}

func TestCreateCertificate_ResolvesOptionalCAReferences(t *testing.T) {
	keysBody := `{"keys":[{"id":"` + rsaKeyID + `","name":"tls-key"},
		{"id":"` + dbSecretID + `","name":"ca-key"}]}`
	certsBody := `{"certificates":[{"id":"` + apiSecretID + `","name":"ca-cert"}]}`

	probe := &writeProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/v1/vaults/prod/certificates" {
				_, _ = w.Write([]byte(certsBody))
				return
			}
			_, _ = w.Write([]byte(keysBody))
			return
		}
		probe.calls++
		probe.method, probe.path = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&probe.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + tlsCertID + `","name":"tls-cert"}`))
	}))
	defer srv.Close()

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365,
		CAKeyName: "ca-key", CACertName: "ca-cert",
	})
	require.NoError(t, err)

	require.Equal(t, dbSecretID, probe.body["ca_key_id"])
	require.Equal(t, apiSecretID, probe.body["ca_cert_id"])
}

func TestCreateCertificate_OmitsUnsetCAReferences(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated,
		`{"id":"`+tlsCertID+`","name":"tls-cert"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365,
	})
	require.NoError(t, err)

	for _, field := range []string{"ca_key_id", "ca_cert_id"} {
		_, present := probe.body[field]
		require.False(t, present, "an unset CA reference must be omitted, not sent empty")
	}
}

func TestCreateCertificate_UnknownKeyNameIsNotFound(t *testing.T) {
	srv, probe := certWriteServer(t, `{"keys":[]}`, http.StatusCreated, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "no-such-key", ValidityDays: 365,
	})
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Zero(t, probe.calls, "an unresolvable key must not produce a create call")
}

func TestCreateCertificate_RequiresVaultNameKeyAndValidity(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.CreateCertificate(context.Background(), "", CreateCertificateRequest{
		Name: "c", KeyName: "tls-key", ValidityDays: 365})
	require.ErrorContains(t, err, "vault is required")

	_, err = c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		KeyName: "tls-key", ValidityDays: 365})
	require.ErrorContains(t, err, "name is required")

	_, err = c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "c", ValidityDays: 365})
	require.ErrorContains(t, err, "key")

	_, err = c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "c", KeyName: "tls-key"})
	require.ErrorContains(t, err, "validity")

	require.Zero(t, probe.calls)
}

func TestCreateCertificate_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365,
	})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}

func TestCreateCertificate_CarriesNoPrivateMaterial(t *testing.T) {
	srv, _ := certWriteServer(t, keysForCertBody, http.StatusCreated,
		`{"id":"`+tlsCertID+`","name":"tls-cert","private_key":"-----BEGIN PRIVATE KEY-----LEAKED"}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365,
	})
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestCreateCertificate_ -v`
Expected: FAIL — `c.CreateCertificate undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/certificates_write.go`:

```go
package vaultapi

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// CreateCertificateRequest describes a certificate to issue.
//
// The key, and any CA references, are given by name. Every other method in
// this package addresses resources by name, and a caller who has just created
// a key has its name to hand more readily than its UUID. Resolve passes a
// UUID through unchanged, so a caller holding one loses nothing.
type CreateCertificateRequest struct {
	Name         string
	KeyName      string
	ValidityDays int
	Tags         []string
	AutoRenew    bool
	RenewalDays  int
	// CAKeyName and CACertName are optional issuer references.
	CAKeyName  string
	CACertName string
	Enabled    *bool
	NotBefore  *time.Time
}

// createCertificateBody mirrors model.CreateCertificateRequest
// (model/certificate.go:58), which addresses by id.
type createCertificateBody struct {
	Name         string     `json:"name"`
	KeyID        string     `json:"key_id"`
	ValidityDays int        `json:"validity_days"`
	Tags         []string   `json:"tags,omitempty"`
	AutoRenew    bool       `json:"auto_renew"`
	RenewalDays  int        `json:"renewal_days"`
	CAKeyID      string     `json:"ca_key_id,omitempty"`
	CACertID     string     `json:"ca_cert_id,omitempty"`
	Enabled      *bool      `json:"enabled,omitempty"`
	NotBefore    *time.Time `json:"not_before,omitempty"`
}

// CreateCertificate issues a certificate against an existing key.
func (c *Client) CreateCertificate(ctx context.Context, vault string, req CreateCertificateRequest) (*Certificate, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to create a certificate")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("vaultapi: certificate name is required")
	}
	if req.KeyName == "" {
		return nil, fmt.Errorf("vaultapi: a key is required to create a certificate")
	}
	if req.ValidityDays <= 0 {
		return nil, fmt.Errorf("vaultapi: validity_days must be positive, got %d", req.ValidityDays)
	}

	// One resolver serves every lookup below, so a shared list is fetched once.
	resolver := c.Resolver()

	keyID, err := resolver.Resolve(ctx, vault, KindKeys, req.KeyName)
	if err != nil {
		return nil, err
	}

	body := createCertificateBody{
		Name:         req.Name,
		KeyID:        keyID.String(),
		ValidityDays: req.ValidityDays,
		Tags:         req.Tags,
		AutoRenew:    req.AutoRenew,
		RenewalDays:  req.RenewalDays,
		Enabled:      req.Enabled,
		NotBefore:    req.NotBefore,
	}

	if req.CAKeyName != "" {
		caKeyID, err := resolver.Resolve(ctx, vault, KindKeys, req.CAKeyName)
		if err != nil {
			return nil, fmt.Errorf("vaultapi: resolving the CA key: %w", err)
		}
		body.CAKeyID = caKeyID.String()
	}
	if req.CACertName != "" {
		caCertID, err := resolver.Resolve(ctx, vault, KindCertificates, req.CACertName)
		if err != nil {
			return nil, fmt.Errorf("vaultapi: resolving the CA certificate: %w", err)
		}
		body.CACertID = caCertID.String()
	}

	var wire certificateWire
	path := fmt.Sprintf("/api/v1/vaults/%s/certificates", vault)
	if err := c.Do(ctx, http.MethodPost, path, body, &wire); err != nil {
		return nil, err
	}
	return certificateFromWire(wire)
}
```

Extract the wire conversion in `certificates.go` into a shared helper, since `GetCertificate` and `CreateCertificate` both need it:

```go
// certificateFromWire converts a decoded response into a Certificate.
func certificateFromWire(wire certificateWire) (*Certificate, error) {
	summary, err := wire.summary()
	if err != nil {
		return nil, err
	}
	return &Certificate{
		CertificateSummary: summary,
		AutoRenew:          wire.AutoRenew,
		RenewalDays:        wire.RenewalDays,
	}, nil
}
```

and have `GetCertificate` call it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run TestCreateCertificate_ -v`
Expected: PASS — all nine tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/certificates_write.go internal/vaultapi/certificates_write_test.go internal/vaultapi/certificates.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add CreateCertificate

A certificate is issued against an existing key, which the wire format
addresses by id. The exported request takes a key name instead, resolved
internally, because every other method here addresses by name and a caller who
just created a key has its name more readily than its UUID. Resolve passes a
UUID through unchanged, so nothing is lost.

Optional CA key and certificate references resolve the same way, through a
single shared resolver so the lists are fetched once."
```

---

### Task 2: `UpsertCertificatePolicy`

**Files:**
- Modify: `internal/vaultapi/certificates_write.go`
- Modify: `internal/vaultapi/certificates_write_test.go` (append)

**Interfaces:**
- Consumes: `Client.Do`, `Resolver.Resolve`, `CertificatePolicy` (plan 07).
- Produces — plan 22's `set_certificate_policy` calls this:
  - `type SetCertificatePolicyRequest struct { ValidityMonths int; KeyType string; KeySize int; Curve, Subject, SANs string; AutoRenew bool; DaysBeforeExpiry int; IssuerName string }`
  - `func (c *Client) UpsertCertificatePolicy(ctx context.Context, vault, name string, req SetCertificatePolicyRequest) (*CertificatePolicy, error)`

**Same replacement semantics as plan 19's rotation policy.** `UpsertCertificatePolicyRequest` has no pointer fields, so this is a full replacement. `KeySize` and `Curve` are `omitempty` on the wire because only one applies per key type — but `ValidityMonths`, `Subject`, `AutoRenew` and `DaysBeforeExpiry` are always sent.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/certificates_write_test.go`:

```go
const certsForPolicyBody = `{"certificates":[{"id":"` + tlsCertID + `","name":"tls-cert"}]}`

func TestUpsertCertificatePolicy_PutsToThePolicyRoute(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusOK,
		`{"certificate_id":"`+tlsCertID+`","validity_months":12,"key_type":"RSA","key_size":2048,
		  "subject":"CN=example.com","auto_renew":true,"days_before_expiry":30}`)

	c := newClientForTest(t, srv)
	got, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{
			ValidityMonths: 12, KeyType: "RSA", KeySize: 2048,
			Subject: "CN=example.com", AutoRenew: true, DaysBeforeExpiry: 30,
		})
	require.NoError(t, err)

	require.Equal(t, http.MethodPut, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/certificates/"+tlsCertID+"/policy", probe.path)
	require.Equal(t, "CN=example.com", got.Subject)
	require.Equal(t, 12, got.ValidityMonths)
}

func TestUpsertCertificatePolicy_SendsTheAlwaysPresentFields(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusOK,
		`{"certificate_id":"`+tlsCertID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: "CN=example.com"})
	require.NoError(t, err)

	for _, field := range []string{"validity_months", "key_type", "subject", "auto_renew", "days_before_expiry"} {
		_, present := probe.body[field]
		require.True(t, present, "field %q must always be sent: this is a full replacement", field)
	}
}

func TestUpsertCertificatePolicy_OmitsKeySizeAndCurveWhenUnset(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusOK,
		`{"certificate_id":"`+tlsCertID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: "CN=example.com"})
	require.NoError(t, err)

	for _, field := range []string{"key_size", "curve"} {
		_, present := probe.body[field]
		require.False(t, present, "only one of key_size and curve applies per key type")
	}
}

func TestUpsertCertificatePolicy_SendsSubjectVerbatim(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusOK,
		`{"certificate_id":"`+tlsCertID+`"}`)

	subject := "CN=example.com, OU=Platform, O=Example Ltd"
	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: subject})
	require.NoError(t, err)

	require.Equal(t, subject, probe.body["subject"],
		"a distinguished name must survive intact; this layer does not reformat it")
}

func TestUpsertCertificatePolicy_UnknownCertificateIsNotFound(t *testing.T) {
	srv, probe := certWriteServer(t, `{"certificates":[]}`, http.StatusOK, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "no-such-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: "CN=x"})
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Zero(t, probe.calls)
}

func TestUpsertCertificatePolicy_RequiresVaultAndName(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusOK, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.UpsertCertificatePolicy(context.Background(), "", "tls-cert", SetCertificatePolicyRequest{})
	require.ErrorContains(t, err, "vault is required")

	_, err = c.UpsertCertificatePolicy(context.Background(), "prod", "", SetCertificatePolicyRequest{})
	require.ErrorContains(t, err, "name is required")

	require.Zero(t, probe.calls)
}

func TestUpsertCertificatePolicy_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: "CN=x"})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}

func TestUpsertCertificatePolicy_ForbiddenSurfacesTheCertificatesOfficerHint(t *testing.T) {
	srv, _ := certWriteServer(t, certsForPolicyBody, http.StatusForbidden, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: "CN=x"})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Contains(t, apiErr.Hint, "Key Vault Certificates Officer")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestUpsertCertificatePolicy_ -v`
Expected: FAIL — `c.UpsertCertificatePolicy undefined`.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/vaultapi/certificates_write.go`, adding `"github.com/google/uuid"` to the imports:

```go
// SetCertificatePolicyRequest is a complete issuance policy.
//
// Like the key rotation policy, the server's request type has no pointer
// fields (model/certificate_policy.go:30), so an upsert is a full
// replacement: omitting a value sets it to zero rather than leaving it alone.
// KeySize and Curve are omitempty on the wire because only one applies per
// key type.
type SetCertificatePolicyRequest struct {
	ValidityMonths   int    `json:"validity_months"`
	KeyType          string `json:"key_type"`
	KeySize          int    `json:"key_size,omitempty"`
	Curve            string `json:"curve,omitempty"`
	Subject          string `json:"subject"`
	SANs             string `json:"sans,omitempty"`
	AutoRenew        bool   `json:"auto_renew"`
	DaysBeforeExpiry int    `json:"days_before_expiry"`
	IssuerName       string `json:"issuer_name,omitempty"`
}

// UpsertCertificatePolicy replaces a certificate's issuance policy.
func (c *Client) UpsertCertificatePolicy(ctx context.Context, vault, name string, req SetCertificatePolicyRequest) (*CertificatePolicy, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to set a certificate policy")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: certificate name is required to set a policy")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindCertificates, name)
	if err != nil {
		return nil, err
	}

	var wire struct {
		CertificateID    string `json:"certificate_id"`
		ValidityMonths   int    `json:"validity_months"`
		KeyType          string `json:"key_type"`
		KeySize          int    `json:"key_size"`
		Curve            string `json:"curve"`
		Subject          string `json:"subject"`
		SANs             string `json:"sans"`
		AutoRenew        bool   `json:"auto_renew"`
		DaysBeforeExpiry int    `json:"days_before_expiry"`
		IssuerName       string `json:"issuer_name"`
	}

	path := fmt.Sprintf("/api/v1/vaults/%s/certificates/%s/policy", vault, id)
	if err := c.Do(ctx, http.MethodPut, path, req, &wire); err != nil {
		return nil, err
	}

	certID, parseErr := uuid.Parse(wire.CertificateID)
	if parseErr != nil {
		certID = id
	}
	return &CertificatePolicy{
		CertificateID:    certID,
		ValidityMonths:   wire.ValidityMonths,
		KeyType:          wire.KeyType,
		KeySize:          wire.KeySize,
		Curve:            wire.Curve,
		Subject:          wire.Subject,
		SANs:             wire.SANs,
		AutoRenew:        wire.AutoRenew,
		DaysBeforeExpiry: wire.DaysBeforeExpiry,
		IssuerName:       wire.IssuerName,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/certificates_write.go internal/vaultapi/certificates_write_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add UpsertCertificatePolicy

A full replacement, like the key rotation policy: the server's request type
has no pointer fields, so omitting a value sets it to zero rather than leaving
it alone. Only key_size and curve are omitted when unset, since one applies
per key type. A distinguished name is sent verbatim; this layer does not
reformat it."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

`vaultapi`'s write surface is complete at this point. Confirm every mutation
is single-attempt:

```bash
go test ./internal/vaultapi/ -run 'IsAttemptedExactlyOnce' -v
```

Expected: five tests, one per mutating method across plans 18-20.

Confirm no write path can leak plaintext:

```bash
go test ./internal/vaultapi/ -run 'CarriesNoPrivateMaterial|ErrorNeverContainsTheValue|MarshalsWithoutLeaking' -v
```

## Notes for the next plan

Plans 21 and 22 register the write-tier tools on top of these methods.

**Two things plan 22 must decide explicitly rather than inherit:**

1. **`set_key_rotation_policy` and `set_certificate_policy` are replacements,
   not merges.** A caller adjusting one field zeroes the rest. The tool either
   says so in its description, or reads the current policy first and merges —
   but it must not present a replacement as an update.
2. **`create_certificate` needs a key that already exists.** The tool's
   description should say so, since a model asked to "create a TLS
   certificate" will otherwise try it without one and get a resolution error
   it cannot interpret.
