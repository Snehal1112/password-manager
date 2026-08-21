# vaultapi Write: Secrets, Vaults and Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `SetSecret`, `CreateVault` and `CreateRoleAssignment` to `internal/vaultapi` — the first mutating methods in the package.

**Architecture:** Each method is a single `Client.Do` with a typed request body. `SetSecret` is the only one with logic: it upserts by name, resolving first to decide between `POST` and `PUT`.

**Tech Stack:** Go 1.25, `github.com/google/uuid`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Write tier".

**Plan-of-plans:** This is plan 18 of 31, opening Group F. Requires plans 01, 04, 05, 07 and 08 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **Vault-scoped routes only.**
- **Mutations are never retried.** Plan 01 established this: `Client.Do` sends non-idempotent methods through the plain client, because `retry.RetryableHTTPClient` does not rewind bodies *and* because retrying a lost-response POST would duplicate the resource. Nothing here may work around that.
- **A secret value must never reach an error message or a log line.**
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Verified request contracts

| Method | Route | Body |
|---|---|---|
| Create secret | `POST /api/v1/vaults/{v}/secrets` | `model.CreateSecretRequest` (`model/secret.go:178`) |
| Update secret | `PUT /api/v1/vaults/{v}/secrets/{id}` | `model.UpdateSecretRequest` (`model/secret.go:195`) |
| Create vault | `POST /api/v1/vaults` | `model.CreateVaultRequest` (`model/vault.go:95`) |
| Grant role | `POST /api/v1/vaults/{v}/role-assignments` | `model.AssignRoleRequest` (`model/role_assignment.go:24`) |

Two details that shape the code:

- **`CreateSecretRequest.Value` is required; `UpdateSecretRequest.Value` is `omitempty`.** So an update can change tags or expiry without touching the value, which is what makes "set the expiry on this secret" possible without knowing its current value.
- **`AssignRoleRequest.Principal` accepts a username *or* a UUID**, and the server resolves it (`model/role_assignment.go:23`). No client-side resolution is needed or wanted here.

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/secrets_write.go` (new) | `SetSecretRequest`, `SetSecret` |
| `internal/vaultapi/vaults_write.go` (new) | `CreateVaultRequest`, `CreateVault` |
| `internal/vaultapi/access_write.go` (new) | `GrantRoleRequest`, `CreateRoleAssignment` |
| `internal/vaultapi/*_write_test.go` (new) | One per file |

---

### Task 1: `SetSecret`, upserting by name

**Files:**
- Create: `internal/vaultapi/secrets_write.go`
- Create: `internal/vaultapi/secrets_write_test.go`

**Interfaces:**
- Consumes: `Client.Do` (plan 01), `Resolver.Resolve` (plan 04), `SecretValue` (plan 05).
- Produces — plan 21's `set_secret` calls this:
  - `type SetSecretRequest struct { Name string; Value SecretValue; Tags []string; ContentType string; Enabled *bool; ExpiresAt, NotBefore *time.Time }`
  - `func (c *Client) SetSecret(ctx context.Context, vault string, req SetSecretRequest) (*Secret, bool, error)` — the bool reports whether the secret was created rather than updated.

**Why upsert rather than separate create and update tools:** a model asking to "set the database password" does not know or care whether one exists. Forcing it to check first costs a round trip and invites a race. The bool tells the caller which happened, so the tool can report it accurately.

**Why `Value` is a `SecretValue` on the request too:** it is a plaintext secret in memory. Making the request type carry the redacting type means a request struct logged or marshalled anywhere cannot leak it — the same protection the response side already has.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/secrets_write_test.go`:

```go
package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// writeProbe records what a mutating request sent.
type writeProbe struct {
	method string
	path   string
	body   map[string]any
	calls  int
}

// probeServer serves list and write routes, recording the write.
func probeServer(t *testing.T, listBody string, status int, response string) (*httptest.Server, *writeProbe) {
	t.Helper()

	probe := &writeProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(listBody))
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

func TestSetSecret_CreatesWhenTheNameIsUnknown(t *testing.T) {
	srv, probe := probeServer(t, `{"secrets":[],"total":0}`, http.StatusCreated,
		`{"id":"`+dbSecretID+`","name":"db-password","version":1}`)

	c := newClientForTest(t, srv)
	got, created, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", Value: SecretValue("hunter2"),
	})
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, "db-password", got.Name)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/secrets", probe.path)
	require.Equal(t, "hunter2", probe.body["value"])
}

func TestSetSecret_UpdatesWhenTheNameExists(t *testing.T) {
	listBody := `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`
	srv, probe := probeServer(t, listBody, http.StatusOK,
		`{"id":"`+dbSecretID+`","name":"db-password","version":4}`)

	c := newClientForTest(t, srv)
	got, created, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", Value: SecretValue("new-value"),
	})
	require.NoError(t, err)
	require.False(t, created, "an existing name is an update, not a create")
	require.Equal(t, 4, got.Version)

	require.Equal(t, http.MethodPut, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/secrets/"+dbSecretID, probe.path)
}

func TestSetSecret_SendsOptionalFields(t *testing.T) {
	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	enabled := true

	srv, probe := probeServer(t, `{"secrets":[],"total":0}`, http.StatusCreated,
		`{"id":"`+dbSecretID+`","name":"db-password"}`)

	c := newClientForTest(t, srv)
	_, _, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name:        "db-password",
		Value:       SecretValue("hunter2"),
		Tags:        []string{"prod", "db"},
		ContentType: "text/plain",
		Enabled:     &enabled,
		ExpiresAt:   &expires,
	})
	require.NoError(t, err)

	require.Equal(t, "text/plain", probe.body["content_type"])
	require.Equal(t, true, probe.body["enabled"])
	require.NotNil(t, probe.body["expires_at"])
	require.Len(t, probe.body["tags"], 2)
}

func TestSetSecret_UpdateWithoutAValueOmitsIt(t *testing.T) {
	// Changing only the expiry must not require knowing the current value.
	listBody := `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`
	srv, probe := probeServer(t, listBody, http.StatusOK, `{"id":"`+dbSecretID+`","name":"db-password"}`)

	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newClientForTest(t, srv)
	_, created, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", ExpiresAt: &expires,
	})
	require.NoError(t, err)
	require.False(t, created)

	_, present := probe.body["value"]
	require.False(t, present, "an update with no value must not send an empty one")
}

func TestSetSecret_CreateRequiresAValue(t *testing.T) {
	srv, probe := probeServer(t, `{"secrets":[],"total":0}`, http.StatusCreated, `{}`)

	c := newClientForTest(t, srv)
	_, _, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{Name: "new-secret"})
	require.ErrorContains(t, err, "value")
	require.Zero(t, probe.calls, "a request that cannot succeed must not be sent")
}

func TestSetSecret_RequiresANameAndVault(t *testing.T) {
	srv, _ := probeServer(t, `{"secrets":[],"total":0}`, http.StatusCreated, `{}`)
	c := newClientForTest(t, srv)

	_, _, err := c.SetSecret(context.Background(), "", SetSecretRequest{Name: "x", Value: "v"})
	require.ErrorContains(t, err, "vault is required")

	_, _, err = c.SetSecret(context.Background(), "prod", SetSecretRequest{Value: "v"})
	require.ErrorContains(t, err, "name is required")
}

func TestSetSecret_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := probeServer(t, `{"secrets":[],"total":0}`, http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, _, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", Value: SecretValue("hunter2"),
	})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls,
		"retrying a lost-response create would duplicate the secret")
}

func TestSetSecret_ErrorNeverContainsTheValue(t *testing.T) {
	srv, _ := probeServer(t, `{"secrets":[],"total":0}`, http.StatusForbidden,
		`{"message":"denied while writing hunter2-super-secret"}`)

	c := newClientForTest(t, srv)
	_, _, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", Value: SecretValue("hunter2-super-secret"),
	})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "hunter2-super-secret")
}

func TestSetSecretRequest_MarshalsWithoutLeakingTheValue(t *testing.T) {
	// The request struct itself must be safe to log or marshal.
	req := SetSecretRequest{Name: "db-password", Value: SecretValue("hunter2-super-secret")}

	encoded, err := json.Marshal(req)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "hunter2-super-secret",
		"a request carrying plaintext must redact like a response does")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestSetSecret -v`
Expected: FAIL — `c.SetSecret undefined`, `undefined: SetSecretRequest`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/secrets_write.go`:

```go
package vaultapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// SetSecretRequest describes a secret to create or update.
//
// Value is a SecretValue rather than a string so the request struct is as
// safe to log or marshal as a response is. A plaintext secret in a request
// body is exactly as sensitive as one in a response.
type SetSecretRequest struct {
	Name        string      `json:"name"`
	Value       SecretValue `json:"value,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	ContentType string      `json:"content_type,omitempty"`
	Enabled     *bool       `json:"enabled,omitempty"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
	NotBefore   *time.Time  `json:"not_before,omitempty"`
}

// createSecretBody mirrors model.CreateSecretRequest (model/secret.go:178).
// Value is a plain string here because this struct exists only to be
// marshalled onto the wire.
type createSecretBody struct {
	Name        string     `json:"name"`
	Value       string     `json:"value"`
	Tags        []string   `json:"tags,omitempty"`
	ContentType string     `json:"content_type,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
}

// updateSecretBody mirrors model.UpdateSecretRequest (model/secret.go:195).
// Every field is omitempty, so an update can change expiry or tags without
// touching the value.
type updateSecretBody struct {
	Value       string     `json:"value,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	ContentType *string    `json:"content_type,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	NotBefore   *time.Time `json:"not_before,omitempty"`
}

// SetSecret creates a secret, or updates it when the name already exists.
// The bool reports which happened.
//
// Upserting is deliberate: a caller asking to set a secret does not
// necessarily know whether one exists, and forcing a check first costs a
// round trip and invites a race between the check and the write.
func (c *Client) SetSecret(ctx context.Context, vault string, req SetSecretRequest) (*Secret, bool, error) {
	if vault == "" {
		return nil, false, fmt.Errorf("vaultapi: vault is required to set a secret")
	}
	if req.Name == "" {
		return nil, false, fmt.Errorf("vaultapi: secret name is required")
	}

	existingID, resolveErr := c.Resolver().Resolve(ctx, vault, KindSecrets, req.Name)
	exists := resolveErr == nil
	if resolveErr != nil {
		// A missing name means "create". Anything else -- a denial, an
		// ambiguous name, an unreachable server -- is a real failure and
		// must not be silently treated as absence.
		var apiErr *APIError
		if errors.As(resolveErr, &apiErr) {
			return nil, false, resolveErr
		}
		if !isNotFound(resolveErr) {
			return nil, false, resolveErr
		}
	}

	if exists {
		body := updateSecretBody{
			Value:     req.Value.Reveal(),
			Tags:      req.Tags,
			Enabled:   req.Enabled,
			ExpiresAt: req.ExpiresAt,
			NotBefore: req.NotBefore,
		}
		if req.ContentType != "" {
			body.ContentType = &req.ContentType
		}

		var updated secretWire
		path := fmt.Sprintf("/api/v1/vaults/%s/secrets/%s", vault, existingID)
		if err := c.Do(ctx, http.MethodPut, path, body, &updated); err != nil {
			return nil, false, err
		}
		secret, err := secretFromWire(updated)
		return secret, false, err
	}

	if req.Value == "" {
		return nil, false, fmt.Errorf("vaultapi: a value is required to create secret %q", req.Name)
	}

	body := createSecretBody{
		Name:        req.Name,
		Value:       req.Value.Reveal(),
		Tags:        req.Tags,
		ContentType: req.ContentType,
		Enabled:     req.Enabled,
		ExpiresAt:   req.ExpiresAt,
		NotBefore:   req.NotBefore,
	}

	var created secretWire
	path := fmt.Sprintf("/api/v1/vaults/%s/secrets", vault)
	if err := c.Do(ctx, http.MethodPost, path, body, &created); err != nil {
		return nil, false, err
	}
	secret, err := secretFromWire(created)
	return secret, true, err
}

// isNotFound reports whether err is a resolution miss rather than a failure.
func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no secrets named")
}
```

Add `"strings"` to the imports. Also extract the wire-to-`Secret` conversion in `secrets.go` into a reusable helper, since `GetSecret` and `SetSecret` now both need it:

```go
// secretFromWire converts a decoded response into a Secret.
func secretFromWire(wire secretWire) (*Secret, error) {
	summary, err := wire.summary()
	if err != nil {
		return nil, err
	}
	return &Secret{
		SecretSummary: summary,
		Value:         SecretValue(wire.Value),
		ContentType:   wire.ContentType,
		Enabled:       wire.Enabled,
		ExpiresAt:     wire.ExpiresAt,
		NotBefore:     wire.NotBefore,
	}, nil
}
```

and have `GetSecret` call it.

**Note on `isNotFound`:** matching on message text is fragile. It works because plan 04's `notFoundError` owns that wording and plan 04's tests pin it. A cleaner fix would be a typed `ErrNotFound` in `resolve.go` — if this feels uncomfortable while implementing, add that sentinel and use `errors.Is` instead. That is a strict improvement and should not be deferred if the implementer has the context.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run TestSetSecret -v`
Expected: PASS — all nine tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/secrets_write.go internal/vaultapi/secrets_write_test.go internal/vaultapi/secrets.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add SetSecret, upserting by name

A caller asking to set a secret does not necessarily know whether one exists,
and forcing a check first costs a round trip and invites a race. The returned
bool reports which happened so the caller can say so accurately.

SetSecretRequest.Value is a SecretValue, so a request struct is as safe to log
or marshal as a response. An update omits the value entirely when none is
given, which is what makes changing an expiry possible without knowing the
current value. A failed create is attempted exactly once: retrying a
lost-response POST would duplicate the secret."
```

---

### Task 2: `CreateVault`

**Files:**
- Create: `internal/vaultapi/vaults_write.go`
- Create: `internal/vaultapi/vaults_write_test.go`

**Interfaces:**
- Consumes: `Client.Do` (plan 01), `Vault`, `vaultWire` (plan 07).
- Produces — plan 21's `create_vault` calls this:
  - `type CreateVaultRequest struct { Name string; Enabled, PurgeProtection *bool; RetentionDays *int; Tags map[string]string }`
  - `func (c *Client) CreateVault(ctx context.Context, req CreateVaultRequest) (*Vault, error)`

**Why the pointers:** `model.CreateVaultRequest` uses `*bool` and `*int` so that omitting a field means "server default" rather than "false" or "zero". Mirroring that exactly matters here — sending `purge_protection: false` explicitly is a different statement from not mentioning it, and a vault created with retention silently set to 0 would be a bad surprise.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/vaults_write_test.go`:

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

// vaultWriteServer records the create-vault request.
func vaultWriteServer(t *testing.T, status int, response string) (*httptest.Server, *writeProbe) {
	t.Helper()

	probe := &writeProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestCreateVault_PostsToTheUnscopedRoute(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated,
		`{"id":"`+prodVaultID+`","name":"prod","enabled":true,"retention_days":90}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateVault(context.Background(), CreateVaultRequest{Name: "prod"})
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults", probe.path)
	require.Equal(t, "prod", got.Name)
	require.Equal(t, 90, got.RetentionDays)
}

func TestCreateVault_OmitsUnsetOptionalFields(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+prodVaultID+`","name":"prod"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{Name: "prod"})
	require.NoError(t, err)

	for _, field := range []string{"enabled", "purge_protection", "retention_days"} {
		_, present := probe.body[field]
		require.False(t, present,
			"omitting %q must mean 'server default', not an explicit zero value", field)
	}
}

func TestCreateVault_SendsExplicitOptionalFields(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+prodVaultID+`","name":"prod"}`)

	enabled, protect, retention := true, true, 30
	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{
		Name:            "prod",
		Enabled:         &enabled,
		PurgeProtection: &protect,
		RetentionDays:   &retention,
		Tags:            map[string]string{"env": "production"},
	})
	require.NoError(t, err)

	require.Equal(t, true, probe.body["enabled"])
	require.Equal(t, true, probe.body["purge_protection"])
	require.EqualValues(t, 30, probe.body["retention_days"])
	require.NotNil(t, probe.body["tags"])
}

func TestCreateVault_ExplicitFalseIsSentNotOmitted(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+prodVaultID+`","name":"prod"}`)

	protect := false
	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{
		Name: "prod", PurgeProtection: &protect,
	})
	require.NoError(t, err)

	value, present := probe.body["purge_protection"]
	require.True(t, present, "an explicit false is a different statement from silence")
	require.Equal(t, false, value)
}

func TestCreateVault_RequiresAName(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{})
	require.ErrorContains(t, err, "name is required")
	require.Zero(t, probe.calls)
}

func TestCreateVault_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{Name: "prod"})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}

func TestCreateVault_ConflictIsTypedAsSuch(t *testing.T) {
	srv, _ := vaultWriteServer(t, http.StatusConflict, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{Name: "prod"})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindConflict, apiErr.Kind,
		"a duplicate vault name is a conflict the caller can explain")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestCreateVault_ -v`
Expected: FAIL — `c.CreateVault undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/vaults_write.go`:

```go
package vaultapi

import (
	"context"
	"fmt"
	"net/http"
)

// CreateVaultRequest describes a vault to create.
//
// The optional fields are pointers, mirroring model.CreateVaultRequest
// (model/vault.go:95), so that omitting one means "use the server's default"
// rather than "false" or "zero". Sending purge_protection: false explicitly
// is a different statement from not mentioning it, and a vault created with
// retention silently set to zero would be an unpleasant surprise.
type CreateVaultRequest struct {
	Name            string            `json:"name"`
	Enabled         *bool             `json:"enabled,omitempty"`
	PurgeProtection *bool             `json:"purge_protection,omitempty"`
	RetentionDays   *int              `json:"retention_days,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
}

// CreateVault creates a vault.
func (c *Client) CreateVault(ctx context.Context, req CreateVaultRequest) (*Vault, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("vaultapi: vault name is required")
	}

	var wire vaultWire
	if err := c.Do(ctx, http.MethodPost, "/api/v1/vaults", req, &wire); err != nil {
		return nil, err
	}

	vault, err := wire.toVault()
	if err != nil {
		return nil, err
	}
	return &vault, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run TestCreateVault_ -v`
Expected: PASS — all seven tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/vaults_write.go internal/vaultapi/vaults_write_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add CreateVault

Optional fields are pointers, mirroring model.CreateVaultRequest, so omitting
one means 'use the server default' rather than false or zero. An explicit
false is a different statement from silence, and a vault created with
retention silently set to zero would be an unpleasant surprise."
```

---

### Task 3: `CreateRoleAssignment`

**Files:**
- Create: `internal/vaultapi/access_write.go`
- Create: `internal/vaultapi/access_write_test.go`

**Interfaces:**
- Consumes: `Client.Do` (plan 01), `RoleAssignment`, `roleAssignmentWire` (plan 08).
- Produces — plan 21's `grant_vault_role` calls this:
  - `type GrantRoleRequest struct { Principal, PrincipalType, Role string }`
  - `func (c *Client) CreateRoleAssignment(ctx context.Context, vault string, req GrantRoleRequest) (*RoleAssignment, error)`

**Two things this method deliberately does not do:**

- **It does not resolve the principal.** `AssignRoleRequest.Principal` accepts a username or a UUID and the server resolves it (`model/role_assignment.go:23`). Duplicating that client-side would add a failure mode for no benefit.
- **It does not validate the role name.** The server owns the list in `model/azure_roles.go`, and a client-side copy would drift the moment a role is added. A bad name produces a clear server error.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/access_write_test.go`:

```go
package vaultapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateRoleAssignment_PostsToTheVaultScopedRoute(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated,
		`{"id":"`+assignmentID+`","principal_id":"`+dbSecretID+`","principal_username":"mcp-agent",
		  "principal_type":"service_account","role":"Key Vault Secrets User","vault_name":"prod"}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: "mcp-agent", PrincipalType: "service_account", Role: "Key Vault Secrets User",
	})
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/role-assignments", probe.path)
	require.Equal(t, "Key Vault Secrets User", got.Role)
	require.Equal(t, "mcp-agent", got.PrincipalUsername)
}

func TestCreateRoleAssignment_SendsThePrincipalVerbatim(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+assignmentID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: "alice", Role: "Key Vault Reader",
	})
	require.NoError(t, err)

	require.Equal(t, "alice", probe.body["principal"],
		"the server resolves a username or UUID; the client must not")
	require.Equal(t, "Key Vault Reader", probe.body["role"])
}

func TestCreateRoleAssignment_AcceptsAUUIDPrincipal(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+assignmentID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: dbSecretID, Role: "Key Vault Reader",
	})
	require.NoError(t, err)
	require.Equal(t, dbSecretID, probe.body["principal"])
}

func TestCreateRoleAssignment_OmitsPrincipalTypeWhenUnset(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+assignmentID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: "alice", Role: "Key Vault Reader",
	})
	require.NoError(t, err)

	_, present := probe.body["principal_type"]
	require.False(t, present, "the server defaults it to user")
}

func TestCreateRoleAssignment_DoesNotValidateTheRoleName(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusBadRequest, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: "alice", Role: "Not A Real Role",
	})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls,
		"the server owns the role list; a client-side copy would drift")
}

func TestCreateRoleAssignment_RequiresVaultPrincipalAndRole(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.CreateRoleAssignment(context.Background(), "", GrantRoleRequest{Principal: "a", Role: "r"})
	require.ErrorContains(t, err, "vault is required")

	_, err = c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{Role: "r"})
	require.ErrorContains(t, err, "principal is required")

	_, err = c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{Principal: "a"})
	require.ErrorContains(t, err, "role is required")

	require.Zero(t, probe.calls)
}

func TestCreateRoleAssignment_ForbiddenNamesTheDataAccessAdminRole(t *testing.T) {
	srv, _ := vaultWriteServer(t, http.StatusForbidden, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: "alice", Role: "Key Vault Reader",
	})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Contains(t, apiErr.Hint, "Key Vault Data Access Administrator")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestCreateRoleAssignment_ -v`
Expected: FAIL — `c.CreateRoleAssignment undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/access_write.go`:

```go
package vaultapi

import (
	"context"
	"fmt"
	"net/http"
)

// GrantRoleRequest describes a role grant.
//
// Principal accepts a username or a UUID: the server resolves it
// (model/role_assignment.go:23), so this client deliberately does not.
// PrincipalType is optional and defaults to "user" server-side; the only
// other accepted value is "service_account".
type GrantRoleRequest struct {
	Principal     string `json:"principal"`
	PrincipalType string `json:"principal_type,omitempty"`
	Role          string `json:"role"`
}

// CreateRoleAssignment grants a built-in role to a principal in a vault.
//
// The role name is not validated here. The server owns the list in
// model/azure_roles.go, and a client-side copy would drift the moment a role
// is added; a bad name produces a clear server error instead.
func (c *Client) CreateRoleAssignment(ctx context.Context, vault string, req GrantRoleRequest) (*RoleAssignment, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to grant a role")
	}
	if req.Principal == "" {
		return nil, fmt.Errorf("vaultapi: principal is required to grant a role")
	}
	if req.Role == "" {
		return nil, fmt.Errorf("vaultapi: role is required to grant a role")
	}

	var wire roleAssignmentWire
	path := fmt.Sprintf("/api/v1/vaults/%s/role-assignments", vault)
	if err := c.Do(ctx, http.MethodPost, path, req, &wire); err != nil {
		return nil, err
	}

	assignment := wire.toAssignment()
	return &assignment, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/access_write.go internal/vaultapi/access_write_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add CreateRoleAssignment

Two things it deliberately does not do. It does not resolve the principal:
the server accepts a username or a UUID and resolves it, so duplicating that
would add a failure mode for no benefit. It does not validate the role name:
the server owns that list, and a client-side copy would drift the moment a
role is added."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

The two properties worth confirming directly:

```bash
# Mutations are attempted exactly once.
go test ./internal/vaultapi/ -run 'IsAttemptedExactlyOnce' -v

# No request or error carries a plaintext value.
go test ./internal/vaultapi/ -run 'ErrorNeverContainsTheValue|MarshalsWithoutLeaking' -v
```

## Notes for the next plan

Plans 19 and 20 add the key and certificate write methods, following the same
shape. What carries over:

- Validate arguments before sending, so a request that cannot succeed is never
  made.
- Mutations go through `Client.Do` unretried; nothing works around that.
- Mirror the server's pointer-vs-value choices exactly, so "omitted" and
  "explicitly zero" stay distinguishable.
- Do not duplicate server-side validation the server does better.

One loose end recorded here rather than left implicit: `isNotFound` in
`secrets_write.go` matches on error message text. It works because plan 04
owns that wording and pins it in tests, but a typed sentinel in `resolve.go`
would be better. Plan 19 needs the same distinction for keys — **add
`ErrResourceNotFound` there and retrofit `SetSecret` to use it** rather than
adding a second string match.
