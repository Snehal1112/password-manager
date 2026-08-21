# vaultapi Write: Keys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `CreateKey`, `RotateKey` and `UpsertKeyRotationPolicy` to `internal/vaultapi`, and replace plan 18's string-matched not-found check with a typed sentinel.

**Architecture:** Plan 18's shape. The one new piece is `ErrResourceNotFound` in `resolve.go`, which plan 18 explicitly deferred to here — both `SetSecret` and any future upsert need to tell "no such name" apart from "denied", and matching on message text is the wrong way to do it.

**Tech Stack:** Go 1.25, `github.com/google/uuid`, `github.com/stretchr/testify`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — section "Tool surface > Write tier".

**Plan-of-plans:** This is plan 19 of 31. Requires plans 01, 04, 06 and 18 committed.

## Global Constraints

- Go 1.25.0. No new dependencies.
- **Vault-scoped routes only.**
- **Mutations are never retried.**
- **No type here may carry private key material.**
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## Verified request contracts

| Method | Route | Body |
|---|---|---|
| Create key | `POST /api/v1/vaults/{v}/keys` | `model.CreateKeyRequest` (`model/key.go:96`) |
| Rotate key | `POST /api/v1/vaults/{v}/keys/{id}/rotate` | none |
| Upsert policy | `PUT /api/v1/vaults/{v}/keys/{id}/rotationpolicy` | `model.UpsertKeyRotationPolicyRequest` (`model/key_rotation_policy.go:32`) |

**Key types are `RSA`, `ECDSA` and `OCT`** — the handler rejects anything else with *"type: must be RSA, ECDSA, or OCT"* (`api/keys.go:338`). Note it is `ECDSA`, not `EC`.

**`OCT` keys are HSM-only by design.** `KeyService.CreateOctKey` fails with `crypto.ErrOctKeysRequireHSM` unless `hsm.enabled` is true (`api/keys.go:430`), mirroring Azure, where Managed HSM never allows symmetric key creation on standard vaults. That is a server-side rule this client should surface clearly, not pre-empt: whether HSM is enabled is the server's state, not the client's.

**`UpsertKeyRotationPolicyRequest` has no pointers.** All four fields are plain values, so an upsert always sends a complete policy. There is no partial update — sending one field zeroes the others. That is the server's contract and this client mirrors it, but it is a sharp edge worth naming, and plan 22's tool must not present the operation as if it merged.

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/resolve.go` (modify) | `ErrResourceNotFound` sentinel |
| `internal/vaultapi/secrets_write.go` (modify) | Use the sentinel instead of a string match |
| `internal/vaultapi/keys_write.go` (new) | `CreateKeyRequest`, `CreateKey`, `RotateKey`, `UpsertKeyRotationPolicy` |
| `internal/vaultapi/keys_write_test.go` (new) | All three methods |

---

### Task 1: `ErrResourceNotFound`, replacing the string match

**Files:**
- Modify: `internal/vaultapi/resolve.go`
- Modify: `internal/vaultapi/secrets_write.go`
- Modify: `internal/vaultapi/resolve_test.go` (append)
- Modify: `internal/vaultapi/secrets_write_test.go` (append)

**Interfaces:**
- Consumes: `notFoundError` (plan 04), `isNotFound` (plan 18).
- Produces:
  - `var ErrResourceNotFound = errors.New(...)`
  - `isNotFound` is deleted; callers use `errors.Is(err, ErrResourceNotFound)`.

**Why now rather than later:** plan 18 shipped `isNotFound` matching on the substring `"no secrets named"`. That works only because plan 04 owns the wording and pins it — but this plan needs the same distinction for keys, and adding a second string match would make the fragility a pattern instead of a one-off. Fixing it here costs one sentinel and removes the whole class of problem.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/resolve_test.go`:

```go
func TestResolver_NotFoundIsErrResourceNotFound(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[],"total":0}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "missing")
	require.ErrorIs(t, err, ErrResourceNotFound,
		"callers must be able to tell absence from denial without matching on text")
}

func TestResolver_NotFoundStillCarriesItsMessage(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "db-passwrd")
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Contains(t, err.Error(), "did you mean",
		"wrapping must not cost the near-miss suggestion")
}

func TestResolver_AmbiguousIsNotErrResourceNotFound(t *testing.T) {
	srv, _ := listServer(t, map[string]string{
		"/api/v1/vaults/prod/secrets": `{"secrets":[
			{"id":"` + dbSecretID + `","name":"dup"},
			{"id":"` + apiSecretID + `","name":"dup"}
		],"total":2}`,
	})
	defer srv.Close()

	_, err := newResolverForTest(t, srv).Resolve(context.Background(), "prod", KindSecrets, "dup")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrResourceNotFound,
		"an ambiguous name is present twice, not absent")
}

func TestResolver_ForbiddenIsNotErrResourceNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	_, err = c.Resolver().Resolve(context.Background(), "prod", KindSecrets, "anything")
	require.NotErrorIs(t, err, ErrResourceNotFound,
		"conflating denial with absence would silently turn a permission failure into a create")
}
```

Append to `internal/vaultapi/secrets_write_test.go`:

```go
func TestSetSecret_ForbiddenResolveDoesNotBecomeACreate(t *testing.T) {
	var writeCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeCalls++
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := newClientForTest(t, srv)
	_, _, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", Value: SecretValue("hunter2"),
	})

	require.Error(t, err)
	require.Zero(t, writeCalls,
		"a denied listing must not be read as 'the secret does not exist' and become a create")

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindForbidden, apiErr.Kind)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestResolver_NotFoundIs|TestResolver_Ambiguous|TestResolver_ForbiddenIs|TestSetSecret_ForbiddenResolve' -v`
Expected: FAIL — `undefined: ErrResourceNotFound`.

- [ ] **Step 3: Write minimal implementation**

In `internal/vaultapi/resolve.go`, add the sentinel and wrap:

```go
// ErrResourceNotFound reports that a named resource does not exist in a
// vault.
//
// It exists so callers can tell absence from denial with errors.Is rather
// than by matching on message text. That distinction is load-bearing: an
// upsert that read a 403 as "does not exist" would turn a permission failure
// into a create.
var ErrResourceNotFound = errors.New("resource not found")
```

Add `"errors"` to the imports, and wrap in `notFoundError`:

```go
func notFoundError(vault string, kind Kind, name string, items []namedItem) error {
	near := nearMisses(name, items)
	if len(near) == 0 {
		return fmt.Errorf("vaultapi: no %s named %q in vault %q: %w", kind, name, vault, ErrResourceNotFound)
	}
	return fmt.Errorf("vaultapi: no %s named %q in vault %q; did you mean %s?: %w",
		kind, name, vault, strings.Join(quoteAll(near), ", "), ErrResourceNotFound)
}
```

In `internal/vaultapi/secrets_write.go`, delete `isNotFound` entirely and replace the resolution branch:

```go
	existingID, resolveErr := c.Resolver().Resolve(ctx, vault, KindSecrets, req.Name)
	exists := resolveErr == nil
	if resolveErr != nil && !errors.Is(resolveErr, ErrResourceNotFound) {
		// Only a genuine absence means "create". A denial, an ambiguous name,
		// or an unreachable server is a real failure.
		return nil, false, resolveErr
	}
```

The `"strings"` import in `secrets_write.go` becomes unused — remove it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package. Plan 04's existing message assertions still hold, since wrapping appends rather than replaces.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/resolve.go internal/vaultapi/resolve_test.go internal/vaultapi/secrets_write.go internal/vaultapi/secrets_write_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "refactor(vaultapi): add ErrResourceNotFound, replacing a string match

SetSecret distinguished absence from failure by matching the substring 'no
secrets named'. That worked only because one function owned the wording, and
this plan needs the same distinction for keys -- a second string match would
have made the fragility a pattern.

The distinction is load-bearing: an upsert that read a 403 as 'does not exist'
would turn a permission failure into a create. A test now pins that a denied
listing never becomes a write."
```

---

### Task 2: `CreateKey`

**Files:**
- Create: `internal/vaultapi/keys_write.go`
- Create: `internal/vaultapi/keys_write_test.go`

**Interfaces:**
- Consumes: `Client.Do` (plan 01), `Key`, `keyWire` (plan 06).
- Produces — plan 22's `create_key` calls this:
  - `type CreateKeyRequest struct { Name, Type string; Bits int; Curve string; Tags []string; Enabled *bool; ExpiresAt, NotBefore *time.Time }`
  - `func (c *Client) CreateKey(ctx context.Context, vault string, req CreateKeyRequest) (*Key, error)`

**What is validated here and what is not:**

- **Validated:** name, type, and vault are present, and the type is one of the three the server accepts. Catching a typo like `EC` before a round trip is worth it, and the list is small and stable.
- **Not validated:** bits for RSA, curve for ECDSA, or whether HSM is enabled for OCT. The server owns those rules — particularly the HSM one, which depends on server state this client cannot see.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/keys_write_test.go`:

```go
package vaultapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateKey_PostsToTheVaultScopedRoute(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated,
		`{"id":"`+rsaKeyID+`","name":"signing-key","type":"RSA","bits":2048,"enabled":true}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "signing-key", Type: "RSA", Bits: 2048,
	})
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/keys", probe.path)
	require.Equal(t, "signing-key", got.Name)
	require.Equal(t, 2048, got.Bits)
	require.EqualValues(t, 2048, probe.body["bits"])
}

func TestCreateKey_AcceptsTheThreeServerTypes(t *testing.T) {
	for _, keyType := range []string{"RSA", "ECDSA", "OCT"} {
		t.Run(keyType, func(t *testing.T) {
			srv, probe := vaultWriteServer(t, http.StatusCreated,
				`{"id":"`+rsaKeyID+`","name":"k","type":"`+keyType+`"}`)

			c := newClientForTest(t, srv)
			_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
				Name: "k", Type: keyType, Bits: 2048,
			})
			require.NoError(t, err)
			require.Equal(t, keyType, probe.body["type"])
		})
	}
}

func TestCreateKey_RejectsAnUnknownTypeBeforeSending(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{}`)

	c := newClientForTest(t, srv)
	// "EC" is the natural guess and is wrong: the server wants "ECDSA".
	_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "k", Type: "EC", Bits: 256,
	})
	require.ErrorContains(t, err, "ECDSA")
	require.Zero(t, probe.calls, "a typo worth catching before a round trip")
}

func TestCreateKey_SendsCurveForECDSA(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated,
		`{"id":"`+rsaKeyID+`","name":"ec-key","type":"ECDSA","curve":"P-256"}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "ec-key", Type: "ECDSA", Curve: "P-256",
	})
	require.NoError(t, err)
	require.Equal(t, "P-256", probe.body["curve"])
	require.Equal(t, "P-256", got.Curve)
}

func TestCreateKey_DoesNotPreemptTheHSMRuleForOCT(t *testing.T) {
	// Whether HSM is enabled is server state this client cannot see, so an
	// OCT request must be sent and the server's refusal surfaced.
	srv, probe := vaultWriteServer(t, http.StatusBadRequest,
		`{"message":"symmetric keys require an HSM"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "aes-key", Type: "OCT", Bits: 256,
	})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls, "the server decides whether OCT is available, not this client")
}

func TestCreateKey_SendsOptionalFields(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+rsaKeyID+`","name":"k","type":"RSA"}`)

	enabled := true
	c := newClientForTest(t, srv)
	_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "k", Type: "RSA", Bits: 2048, Tags: []string{"prod"}, Enabled: &enabled,
	})
	require.NoError(t, err)

	require.Equal(t, true, probe.body["enabled"])
	require.Len(t, probe.body["tags"], 1)
}

func TestCreateKey_RequiresVaultNameAndType(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.CreateKey(context.Background(), "", CreateKeyRequest{Name: "k", Type: "RSA"})
	require.ErrorContains(t, err, "vault is required")

	_, err = c.CreateKey(context.Background(), "prod", CreateKeyRequest{Type: "RSA"})
	require.ErrorContains(t, err, "name is required")

	_, err = c.CreateKey(context.Background(), "prod", CreateKeyRequest{Name: "k"})
	require.ErrorContains(t, err, "type is required")

	require.Zero(t, probe.calls)
}

func TestCreateKey_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "k", Type: "RSA", Bits: 2048,
	})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}

func TestCreateKey_CarriesNoPrivateMaterial(t *testing.T) {
	srv, _ := vaultWriteServer(t, http.StatusCreated,
		`{"id":"`+rsaKeyID+`","name":"k","type":"RSA","value":"-----BEGIN PRIVATE KEY-----LEAKED"}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateKey(context.Background(), "prod", CreateKeyRequest{
		Name: "k", Type: "RSA", Bits: 2048,
	})
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED")
}
```

Add `"encoding/json"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestCreateKey_ -v`
Expected: FAIL — `c.CreateKey undefined`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/keys_write.go`:

```go
package vaultapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// keyTypes are the values the server accepts (api/keys.go:338).
var keyTypes = []string{"RSA", "ECDSA", "OCT"}

// CreateKeyRequest describes a key to create.
type CreateKeyRequest struct {
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Bits      int        `json:"bits,omitempty"`
	Curve     string     `json:"curve,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
	Enabled   *bool      `json:"enabled,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
}

// CreateKey creates a key in vault.
//
// The type is checked locally because the accepted set is small, stable, and
// easy to get wrong -- "EC" is the natural guess and the server wants
// "ECDSA". Nothing else is: bit sizes, curves, and whether an OCT key is
// possible all depend on server configuration this client cannot see. An OCT
// key requires HSM (api/keys.go:430), which is the server's state to report.
func (c *Client) CreateKey(ctx context.Context, vault string, req CreateKeyRequest) (*Key, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to create a key")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required")
	}
	if req.Type == "" {
		return nil, fmt.Errorf("vaultapi: key type is required; one of %s", strings.Join(keyTypes, ", "))
	}
	if !isKnownKeyType(req.Type) {
		return nil, fmt.Errorf("vaultapi: unknown key type %q; must be one of %s",
			req.Type, strings.Join(keyTypes, ", "))
	}

	var wire keyWire
	path := fmt.Sprintf("/api/v1/vaults/%s/keys", vault)
	if err := c.Do(ctx, http.MethodPost, path, req, &wire); err != nil {
		return nil, err
	}
	return keyFromWire(wire)
}

func isKnownKeyType(value string) bool {
	for _, known := range keyTypes {
		if known == value {
			return true
		}
	}
	return false
}
```

Extract the wire conversion in `keys.go` into a shared helper, since `GetKey` and `CreateKey` now both need it:

```go
// keyFromWire converts a decoded response into a Key.
func keyFromWire(wire keyWire) (*Key, error) {
	summary, err := wire.summary()
	if err != nil {
		return nil, err
	}
	return &Key{
		KeySummary: summary,
		Bits:       wire.Bits,
		Curve:      wire.Curve,
		PublicJWK:  PublicJWK{N: wire.N, E: wire.E, X: wire.X, Y: wire.Y},
		UpdatedAt:  wire.UpdatedAt,
	}, nil
}
```

and have `GetKey` call it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run TestCreateKey_ -v`
Expected: PASS — all nine tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/keys_write.go internal/vaultapi/keys_write_test.go internal/vaultapi/keys.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add CreateKey

The key type is checked locally: the set is small, stable, and easy to get
wrong, since 'EC' is the natural guess and the server wants 'ECDSA'. Nothing
else is checked. Bit sizes, curves, and whether an OCT key is possible all
depend on server state this client cannot see -- OCT requires HSM, which is
the server's to report, so the request is sent and its refusal surfaced."
```

---

### Task 3: `RotateKey` and `UpsertKeyRotationPolicy`

**Files:**
- Modify: `internal/vaultapi/keys_write.go`
- Modify: `internal/vaultapi/keys_write_test.go` (append)

**Interfaces:**
- Consumes: `Client.Do`, `Resolver.Resolve`, `KeyRotationPolicy` (plan 06).
- Produces — plan 22's `rotate_key` and `set_key_rotation_policy` call these:
  - `func (c *Client) RotateKey(ctx context.Context, vault, name string) (*Key, error)`
  - `type SetKeyRotationPolicyRequest struct { RotateAfterDays, NotifyBeforeExpiryDays, ExpiryDays int; Enabled bool }`
  - `func (c *Client) UpsertKeyRotationPolicy(ctx context.Context, vault, name string, req SetKeyRotationPolicyRequest) (*KeyRotationPolicy, error)`

**The sharp edge in the policy upsert:** `model.UpsertKeyRotationPolicyRequest` has **no pointer fields** (`model/key_rotation_policy.go:32`). Every upsert sends a complete policy, so omitting a field sets it to zero rather than leaving it alone. There is no partial update. This client mirrors that contract exactly rather than faking a merge — but plan 22's tool must present it as a full replacement, or a caller adjusting one field will silently zero the rest.

- [ ] **Step 1: Write the failing test**

Append to `internal/vaultapi/keys_write_test.go`:

```go
func TestRotateKey_PostsToTheRotateRoute(t *testing.T) {
	srv, probe := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusOK,
		`{"id":"`+rsaKeyID+`","name":"signing-key","type":"RSA"}`)

	c := newClientForTest(t, srv)
	got, err := c.RotateKey(context.Background(), "prod", "signing-key")
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/rotate", probe.path)
	require.Equal(t, "signing-key", got.Name)
}

func TestRotateKey_SendsNoBody(t *testing.T) {
	srv, probe := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusOK, `{"id":"`+rsaKeyID+`","name":"signing-key"}`)

	c := newClientForTest(t, srv)
	_, err := c.RotateKey(context.Background(), "prod", "signing-key")
	require.NoError(t, err)
	require.Empty(t, probe.body, "the rotate route takes no body")
}

func TestRotateKey_AcceptsAUUID(t *testing.T) {
	srv, probe := probeServer(t, `{"keys":[]}`, http.StatusOK, `{"id":"`+rsaKeyID+`","name":"k"}`)

	c := newClientForTest(t, srv)
	_, err := c.RotateKey(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/rotate", probe.path)
}

func TestRotateKey_UnknownNameIsNotFound(t *testing.T) {
	srv, probe := probeServer(t, `{"keys":[]}`, http.StatusOK, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.RotateKey(context.Background(), "prod", "nope")
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Zero(t, probe.calls, "an unresolvable name must not produce a rotate call")
}

func TestRotateKey_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.RotateKey(context.Background(), "prod", "signing-key")
	require.Error(t, err)
	require.Equal(t, 1, probe.calls,
		"retrying a lost-response rotate would create a second key version")
}

func TestUpsertKeyRotationPolicy_PutsAllFourFields(t *testing.T) {
	srv, probe := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusOK,
		`{"key_id":"`+rsaKeyID+`","rotate_after_days":90,"notify_before_expiry_days":14,
		  "expiry_days":365,"enabled":true,"next_rotation_at":"2026-11-01T00:00:00Z"}`)

	c := newClientForTest(t, srv)
	got, err := c.UpsertKeyRotationPolicy(context.Background(), "prod", "signing-key",
		SetKeyRotationPolicyRequest{
			RotateAfterDays: 90, NotifyBeforeExpiryDays: 14, ExpiryDays: 365, Enabled: true,
		})
	require.NoError(t, err)

	require.Equal(t, http.MethodPut, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/rotationpolicy", probe.path)
	require.EqualValues(t, 90, probe.body["rotate_after_days"])
	require.EqualValues(t, 14, probe.body["notify_before_expiry_days"])
	require.EqualValues(t, 365, probe.body["expiry_days"])
	require.Equal(t, true, probe.body["enabled"])
	require.Equal(t, 90, got.RotateAfterDays)
}

func TestUpsertKeyRotationPolicy_SendsZeroesRatherThanOmitting(t *testing.T) {
	// The server's request type has no pointers, so an upsert is always a
	// full replacement. Omitting a field would be a lie about what happens.
	srv, probe := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusOK, `{"key_id":"`+rsaKeyID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertKeyRotationPolicy(context.Background(), "prod", "signing-key",
		SetKeyRotationPolicyRequest{RotateAfterDays: 30})
	require.NoError(t, err)

	for _, field := range []string{"rotate_after_days", "notify_before_expiry_days", "expiry_days", "enabled"} {
		_, present := probe.body[field]
		require.True(t, present, "field %q must be sent: this is a full replacement", field)
	}
	require.EqualValues(t, 0, probe.body["expiry_days"])
}

func TestUpsertKeyRotationPolicy_RequiresVaultAndName(t *testing.T) {
	srv, probe := probeServer(t, `{"keys":[]}`, http.StatusOK, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.UpsertKeyRotationPolicy(context.Background(), "", "k", SetKeyRotationPolicyRequest{})
	require.ErrorContains(t, err, "vault is required")

	_, err = c.UpsertKeyRotationPolicy(context.Background(), "prod", "", SetKeyRotationPolicyRequest{})
	require.ErrorContains(t, err, "name is required")

	require.Zero(t, probe.calls)
}

func TestUpsertKeyRotationPolicy_ForbiddenSurfacesTheCryptoOfficerHint(t *testing.T) {
	srv, _ := probeServer(t,
		`{"keys":[{"id":"`+rsaKeyID+`","name":"signing-key"}]}`,
		http.StatusForbidden, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertKeyRotationPolicy(context.Background(), "prod", "signing-key",
		SetKeyRotationPolicyRequest{RotateAfterDays: 90})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Contains(t, apiErr.Hint, "Key Vault Crypto Officer")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestRotateKey_|TestUpsertKeyRotationPolicy_' -v`
Expected: FAIL — `c.RotateKey undefined`, `c.UpsertKeyRotationPolicy undefined`.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/vaultapi/keys_write.go`:

```go
// RotateKey creates a new version of a key.
func (c *Client) RotateKey(ctx context.Context, vault, name string) (*Key, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to rotate a key")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to rotate a key")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	var wire keyWire
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/rotate", vault, id)
	// The rotate route takes no body.
	if err := c.Do(ctx, http.MethodPost, path, nil, &wire); err != nil {
		return nil, err
	}
	return keyFromWire(wire)
}

// SetKeyRotationPolicyRequest is a complete rotation policy.
//
// Every field is a plain value, not a pointer, mirroring
// model.UpsertKeyRotationPolicyRequest (model/key_rotation_policy.go:32).
// That means an upsert is always a full replacement: omitting a field sets it
// to zero rather than leaving it alone. There is no partial update, and
// callers must present the operation that way rather than implying a merge.
type SetKeyRotationPolicyRequest struct {
	RotateAfterDays        int  `json:"rotate_after_days"`
	NotifyBeforeExpiryDays int  `json:"notify_before_expiry_days"`
	ExpiryDays             int  `json:"expiry_days"`
	Enabled                bool `json:"enabled"`
}

// UpsertKeyRotationPolicy replaces a key's rotation policy.
func (c *Client) UpsertKeyRotationPolicy(ctx context.Context, vault, name string, req SetKeyRotationPolicyRequest) (*KeyRotationPolicy, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to set a key rotation policy")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to set a rotation policy")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	var wire struct {
		KeyID                  string     `json:"key_id"`
		RotateAfterDays        int        `json:"rotate_after_days"`
		NotifyBeforeExpiryDays int        `json:"notify_before_expiry_days"`
		ExpiryDays             int        `json:"expiry_days"`
		Enabled                bool       `json:"enabled"`
		LastRotatedAt          *time.Time `json:"last_rotated_at"`
		NextRotationAt         time.Time  `json:"next_rotation_at"`
	}

	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/rotationpolicy", vault, id)
	if err := c.Do(ctx, http.MethodPut, path, req, &wire); err != nil {
		return nil, err
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	return &KeyRotationPolicy{
		KeyID:                  keyID,
		RotateAfterDays:        wire.RotateAfterDays,
		NotifyBeforeExpiryDays: wire.NotifyBeforeExpiryDays,
		ExpiryDays:             wire.ExpiryDays,
		Enabled:                wire.Enabled,
		LastRotatedAt:          wire.LastRotatedAt,
		NextRotationAt:         wire.NextRotationAt,
	}, nil
}
```

Add `"github.com/google/uuid"` to the imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/keys_write.go internal/vaultapi/keys_write_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add RotateKey and UpsertKeyRotationPolicy

Rotation is attempted exactly once: retrying a lost-response rotate would
create a second key version.

The policy upsert is a full replacement, not a merge. The server's request
type has no pointer fields, so omitting one sets it to zero rather than
leaving it alone. This client mirrors that exactly and sends all four fields
-- omitting them would be a lie about what the operation does."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, race-clean, no vet findings.

Confirm the string match is gone:

```bash
grep -rn "no secrets named" --include="*.go" internal/vaultapi/ | grep -v _test
```

Expected: exactly one hit, in `resolve.go`, where the message is produced —
none where it is matched.

Confirm mutations remain single-attempt:

```bash
go test ./internal/vaultapi/ -run 'IsAttemptedExactlyOnce' -v
```

## Notes for the next plan

Plan 20 adds the certificate write methods and closes out `vaultapi`'s write
surface. It is the smallest plan in the group — two methods, no new patterns.

Carry into plan 22: **`set_key_rotation_policy` must be described as replacing
the policy, not updating it.** A caller adjusting `rotate_after_days` on an
existing policy will zero the other three fields unless the tool reads the
current policy first and merges — which is a decision plan 22 has to make
explicitly, not inherit by accident.
