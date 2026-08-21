# vaultapi HTTP Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create `internal/vaultapi` with a `Client` that performs authenticated, correlation-tagged JSON requests against the RocketVault REST API, returning typed errors that never leak upstream response bodies.

**Architecture:** `Client.Do` is the single request path for every later domain method. It attaches a bearer token from a `TokenSource`, tags the request with a correlation ID for audit tracing, and converts non-2xx responses into a typed `*APIError` whose message is derived from the *request we sent*, never from the response body. Retry and circuit breaking come from the existing `retry.RetryableHTTPClient`, applied to idempotent GETs only.

**Tech Stack:** Go 1.25, `net/http`, `encoding/json`, `github.com/stretchr/testify`, `internal/retry`, `internal/cliclient`.

**Spec:** `docs/superpowers/specs/2026-08-21-mcp-server-design.md` — sections "Architecture > Data flow", "Authentication", "Error handling".

**Plan-of-plans:** This is plan 01 of 31. No predecessors.

## Global Constraints

- Go 1.25.0. No new direct dependencies in this plan (the MCP SDK arrives in plan 10).
- **Vault-scoped routes only.** Callers pass full paths like `/api/v1/vaults/{vault}/secrets`. This package never constructs a flat `/api/v1/secrets` path.
- **Upstream response bodies are never surfaced.** Error payloads can echo request material including secret values.
- **`vaultapi` must never import the MCP SDK** or `internal/mcpserver`. It is a general REST client, reusable by the pending CLI remote-mode work.
- Comments: short full sentences ending in a punctuation mark. No emojis.
- Commits signed with GPG key `61D246B30285ED35`.
- TDD: failing test → verify it fails → minimal implementation → verify it passes → commit.

## File structure

| File | Responsibility |
|---|---|
| `internal/vaultapi/client.go` (new) | `Config`, `Client`, `Do`, `TokenSource` interface, correlation-ID context helpers |
| `internal/vaultapi/errors.go` (new) | `ErrorKind`, `APIError`, status → typed error mapping, request-derived hints |
| `internal/vaultapi/client_test.go` (new) | `Do` behavior: headers, decoding, method handling |
| `internal/vaultapi/errors_test.go` (new) | Status mapping, body-leak prevention, role hints |
| `internal/vaultapi/testhelpers_test.go` (new) | `staticToken` stub shared by tests in this package |

---

### Task 1: `Client.Do` with auth and correlation headers

**Files:**
- Create: `internal/vaultapi/client.go`
- Create: `internal/vaultapi/client_test.go`
- Create: `internal/vaultapi/testhelpers_test.go`

**Interfaces:**
- Consumes: nothing from earlier plans (this is the first).
- Produces — later plans depend on exactly these:
  - `type TokenSource interface { Token(ctx context.Context) (string, error) }` — plan 02 and plan 03 implement it.
  - `func New(cfg Config) (*Client, error)` where `Config{BaseURL string; HTTPClient *http.Client; Tokens TokenSource}`.
  - `func (c *Client) Do(ctx context.Context, method, path string, body, out any) error` — every domain method in plans 05-08, 18-20, 23, 26 calls this.
  - `func WithCorrelationID(ctx context.Context, id string) context.Context`
  - `func CorrelationIDFrom(ctx context.Context) string`
  - `const CorrelationHeader = "X-RocketVault-Correlation-Id"`

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/testhelpers_test.go`:

```go
package vaultapi

import "context"

// staticToken is a TokenSource returning a fixed token, for tests that are
// not exercising token acquisition itself.
type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }
```

Create `internal/vaultapi/client_test.go`:

```go
package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDo_SendsBearerTokenAndCorrelationID(t *testing.T) {
	var gotAuth, gotCorrelation, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCorrelation = r.Header.Get(CorrelationHeader)
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"db-password"}`))
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("tok-123")})
	require.NoError(t, err)

	var out struct {
		Name string `json:"name"`
	}
	ctx := WithCorrelationID(context.Background(), "corr-abc")
	err = c.Do(ctx, http.MethodGet, "/api/v1/vaults/default/secrets", nil, &out)
	require.NoError(t, err)

	require.Equal(t, "Bearer tok-123", gotAuth)
	require.Equal(t, "corr-abc", gotCorrelation)
	require.Equal(t, "application/json", gotAccept)
	require.Equal(t, "db-password", out.Name)
}

func TestDo_EncodesRequestBodyAndSetsContentType(t *testing.T) {
	var gotBody, gotContentType, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		gotContentType = r.Header.Get("Content-Type")
		gotMethod = r.Method
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	payload := map[string]string{"name": "api-key"}
	err = c.Do(context.Background(), http.MethodPost, "/api/v1/vaults/prod/secrets", payload, nil)
	require.NoError(t, err)

	require.JSONEq(t, `{"name":"api-key"}`, gotBody)
	require.Equal(t, "application/json", gotContentType)
	require.Equal(t, http.MethodPost, gotMethod)
}

func TestDo_OmitsCorrelationHeaderWhenAbsent(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header[http.CanonicalHeaderKey(CorrelationHeader)]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	require.NoError(t, c.Do(context.Background(), http.MethodGet, "/api/v1/vaults", nil, nil))
	require.False(t, present, "correlation header must be absent when no ID is set")
}

func TestNew_RequiresBaseURLTokensAndHTTPClient(t *testing.T) {
	_, err := New(Config{HTTPClient: http.DefaultClient, Tokens: staticToken("t")})
	require.ErrorContains(t, err, "BaseURL")

	_, err = New(Config{BaseURL: "https://vault.example", HTTPClient: http.DefaultClient})
	require.ErrorContains(t, err, "Tokens")

	_, err = New(Config{BaseURL: "https://vault.example", Tokens: staticToken("t")})
	require.ErrorContains(t, err, "HTTPClient")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestDo_|TestNew_' -v`
Expected: FAIL — the package does not compile, `undefined: New`, `undefined: Config`, `undefined: CorrelationHeader`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/client.go`:

```go
// Package vaultapi is a typed REST client for the RocketVault HTTP API. It is
// deliberately independent of any consumer: the MCP server uses it today and
// the CLI's remote mode is expected to use it next, so nothing here may import
// internal/mcpserver or the MCP SDK.
package vaultapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CorrelationHeader carries a per-request identifier so a tool call can be
// traced to its API request and the audit entry it produced.
const CorrelationHeader = "X-RocketVault-Correlation-Id"

type correlationKey struct{}

// WithCorrelationID attaches a correlation identifier to ctx.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey{}, id)
}

// CorrelationIDFrom returns the correlation identifier attached to ctx, or the
// empty string when none is set.
func CorrelationIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}

// TokenSource yields a bearer token for the RocketVault API. Implementations
// are responsible for their own caching and refresh.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Config holds everything Client needs. All three fields are required.
type Config struct {
	// BaseURL is the server root, e.g. "https://vault.example.com". A
	// trailing slash is trimmed.
	BaseURL string
	// HTTPClient is the transport, normally built by cliclient.NewHTTPClient
	// so TLS trust flags are honored.
	HTTPClient *http.Client
	// Tokens supplies the bearer token for every request.
	Tokens TokenSource
}

// Client performs authenticated JSON requests against the RocketVault API.
type Client struct {
	baseURL string
	http    *http.Client
	tokens  TokenSource
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("vaultapi: Config.BaseURL is required")
	}
	if cfg.Tokens == nil {
		return nil, fmt.Errorf("vaultapi: Config.Tokens is required")
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("vaultapi: Config.HTTPClient is required")
	}
	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		http:    cfg.HTTPClient,
		tokens:  cfg.Tokens,
	}, nil
}

// Do performs one request. body is JSON-encoded when non-nil; out is
// JSON-decoded from the response when non-nil. A non-2xx response becomes an
// *APIError and out is left untouched.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vaultapi: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("vaultapi: %s %s: unexpected status %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("vaultapi: decode %s %s response: %w", method, path, err)
	}
	return nil
}

// newRequest builds the authenticated request for one attempt.
func (c *Client) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("vaultapi: encode request body: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, payload)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: build request: %w", err)
	}

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: obtain token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if id := CorrelationIDFrom(ctx); id != "" {
		req.Header.Set(CorrelationHeader, id)
	}
	return req, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -run 'TestDo_|TestNew_' -v`
Expected: PASS, all four tests.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/client.go internal/vaultapi/client_test.go internal/vaultapi/testhelpers_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): add authenticated JSON request client

Do() is the single request path every domain method will use. It attaches a
bearer token from a TokenSource and tags each request with a correlation ID so
a tool call can be traced to its API request and audit entry."
```

---

### Task 2: Typed errors that never leak response bodies

**Files:**
- Create: `internal/vaultapi/errors.go`
- Create: `internal/vaultapi/errors_test.go`
- Modify: `internal/vaultapi/client.go` (replace the `unexpected status` line in `Do` with `newAPIError`)

**Interfaces:**
- Consumes: `Client.Do` from Task 1.
- Produces — later plans depend on these:
  - `type ErrorKind int` with `KindUnknown`, `KindUnauthorized`, `KindForbidden`, `KindNotFound`, `KindConflict`, `KindServer`.
  - `type APIError struct { Kind ErrorKind; StatusCode int; Method, Path, Hint string }` implementing `error`.
  - Plan 13-15, 21-22, 25 and 27 map `*APIError` onto MCP `isError` results using `errors.As`.

**Why the body is discarded:** a 403 or 409 body can echo the request payload, and for `set_secret` that payload is a secret value. The hint is therefore derived from the request line we sent, which contains no secret material.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/errors_test.go`:

```go
package vaultapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// doAgainstStatus runs one request against a server that always replies with
// status and body, and returns the resulting error.
func doAgainstStatus(t *testing.T, status int, body, method, path string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)
	return c.Do(context.Background(), method, path, nil, nil)
}

func TestAPIError_MapsStatusToKind(t *testing.T) {
	cases := []struct {
		status int
		want   ErrorKind
	}{
		{http.StatusUnauthorized, KindUnauthorized},
		{http.StatusForbidden, KindForbidden},
		{http.StatusNotFound, KindNotFound},
		{http.StatusConflict, KindConflict},
		{http.StatusInternalServerError, KindServer},
		{http.StatusBadGateway, KindServer},
		{http.StatusTeapot, KindUnknown},
	}
	for _, tc := range cases {
		err := doAgainstStatus(t, tc.status, `{}`, http.MethodGet, "/api/v1/vaults")
		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, tc.want, apiErr.Kind, "status %d", tc.status)
		require.Equal(t, tc.status, apiErr.StatusCode)
	}
}

func TestAPIError_NeverLeaksResponseBody(t *testing.T) {
	leaky := `{"message":"denied while writing value s3cr3t-p4ssw0rd"}`
	err := doAgainstStatus(t, http.StatusForbidden, leaky, http.MethodPut,
		"/api/v1/vaults/prod/secrets/1f0c8a3e-0000-0000-0000-000000000000")

	require.NotContains(t, err.Error(), "s3cr3t-p4ssw0rd")
	require.NotContains(t, err.Error(), "denied while writing")
}

func TestAPIError_ForbiddenCarriesActionableRoleHint(t *testing.T) {
	err := doAgainstStatus(t, http.StatusForbidden, `{}`, http.MethodGet, "/api/v1/vaults/prod/secrets")

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Contains(t, apiErr.Hint, "secrets/read")
	require.Contains(t, apiErr.Hint, "Key Vault Secrets User")
	require.Contains(t, apiErr.Error(), "prod")
}

func TestAPIError_HintDistinguishesReadFromWrite(t *testing.T) {
	readErr := doAgainstStatus(t, http.StatusForbidden, `{}`, http.MethodGet, "/api/v1/vaults/prod/keys")
	writeErr := doAgainstStatus(t, http.StatusForbidden, `{}`, http.MethodPost, "/api/v1/vaults/prod/keys")

	var readAPI, writeAPI *APIError
	require.ErrorAs(t, readErr, &readAPI)
	require.ErrorAs(t, writeErr, &writeAPI)
	require.Contains(t, readAPI.Hint, "keys/read")
	require.Contains(t, writeAPI.Hint, "keys/create")
	require.NotEqual(t, readAPI.Hint, writeAPI.Hint)
}

func TestAPIError_UnauthorizedTellsOperatorToLogIn(t *testing.T) {
	err := doAgainstStatus(t, http.StatusUnauthorized, `{}`, http.MethodGet, "/api/v1/vaults")
	require.Contains(t, err.Error(), "rocketvault users login")
}

func TestAPIError_ServerKindIsRetryable(t *testing.T) {
	err := doAgainstStatus(t, http.StatusServiceUnavailable, `{}`, http.MethodGet, "/api/v1/vaults")
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.True(t, apiErr.Retryable())

	err = doAgainstStatus(t, http.StatusNotFound, `{}`, http.MethodGet, "/api/v1/vaults")
	require.ErrorAs(t, err, &apiErr)
	require.False(t, apiErr.Retryable())
}

func TestAPIError_IsDiscoverableWithErrorsAs(t *testing.T) {
	err := doAgainstStatus(t, http.StatusNotFound, `{}`, http.MethodGet, "/api/v1/vaults/prod/keys")
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run TestAPIError_ -v`
Expected: FAIL — `undefined: ErrorKind`, `undefined: APIError`, `undefined: KindForbidden`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/vaultapi/errors.go`:

```go
package vaultapi

import (
	"fmt"
	"net/http"
	"strings"
)

// ErrorKind classifies an API failure so callers can react without matching
// on status codes.
type ErrorKind int

const (
	// KindUnknown is any status this package does not classify.
	KindUnknown ErrorKind = iota
	KindUnauthorized
	KindForbidden
	KindNotFound
	KindConflict
	KindServer
)

// APIError describes a non-2xx response.
//
// It deliberately carries no part of the response body. A 403 or 409 payload
// can echo the request that produced it, and for a secret write that request
// contains a secret value. Everything user-facing here is derived from the
// request line we sent, which holds no secret material.
type APIError struct {
	Kind       ErrorKind
	StatusCode int
	Method     string
	Path       string
	// Hint is operator-facing guidance, such as the data action that was
	// denied and a role that would grant it.
	Hint string
}

func (e *APIError) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("%s %s: %s (HTTP %d)", e.Method, e.Path, e.Hint, e.StatusCode)
	}
	return fmt.Sprintf("%s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
}

// Retryable reports whether retrying the same request could plausibly succeed.
func (e *APIError) Retryable() bool { return e.Kind == KindServer }

// newAPIError classifies a response. The response body is never read.
func newAPIError(method, path string, statusCode int) *APIError {
	err := &APIError{
		Kind:       kindForStatus(statusCode),
		StatusCode: statusCode,
		Method:     method,
		Path:       path,
	}
	err.Hint = hintFor(err)
	return err
}

func kindForStatus(status int) ErrorKind {
	switch {
	case status == http.StatusUnauthorized:
		return KindUnauthorized
	case status == http.StatusForbidden:
		return KindForbidden
	case status == http.StatusNotFound:
		return KindNotFound
	case status == http.StatusConflict:
		return KindConflict
	case status >= http.StatusInternalServerError:
		return KindServer
	default:
		return KindUnknown
	}
}

// hintFor builds operator-facing guidance from the request line alone.
func hintFor(e *APIError) string {
	switch e.Kind {
	case KindUnauthorized:
		return "not authenticated — run `rocketvault users login`, or check the MCP service-account credentials"
	case KindForbidden:
		resource, verb := resourceAndVerb(e.Method, e.Path)
		action := fmt.Sprintf("Microsoft.KeyVault/vaults/%s/%s", resource, verb)
		role := roleFor(resource, verb)
		vault := vaultFromPath(e.Path)
		if vault == "" {
			return fmt.Sprintf("principal lacks %s; grant e.g. %q", action, role)
		}
		return fmt.Sprintf("principal lacks %s in vault %q; grant e.g. %q", action, vault, role)
	case KindNotFound:
		return "no such resource in this vault"
	case KindConflict:
		return "a resource with that name already exists, or the operation conflicts with current state"
	case KindServer:
		return "the server failed to handle the request"
	default:
		return ""
	}
}

// resourceAndVerb derives the data-action resource and verb from the request.
func resourceAndVerb(method, path string) (resource, verb string) {
	resource = "secrets"
	for _, candidate := range []string{"secrets", "keys", "certificates", "role-assignments"} {
		if strings.Contains(path, "/"+candidate) {
			resource = candidate
			break
		}
	}

	switch method {
	case http.MethodGet, http.MethodHead:
		verb = "read"
	case http.MethodPost:
		verb = "create"
	case http.MethodPut, http.MethodPatch:
		verb = "update"
	case http.MethodDelete:
		verb = "delete"
		if strings.HasSuffix(path, "/purge") {
			verb = "purge"
		}
	default:
		verb = "read"
	}
	return resource, verb
}

// roleFor names a built-in role that grants the given action. The names come
// from model/azure_roles.go.
func roleFor(resource, verb string) string {
	readOnly := verb == "read"
	switch resource {
	case "keys":
		if readOnly {
			return "Key Vault Crypto User"
		}
		return "Key Vault Crypto Officer"
	case "certificates":
		if readOnly {
			return "Key Vault Certificate User"
		}
		return "Key Vault Certificates Officer"
	case "role-assignments":
		return "Key Vault Data Access Administrator"
	default:
		if readOnly {
			return "Key Vault Secrets User"
		}
		return "Key Vault Secrets Officer"
	}
}

// vaultFromPath extracts the vault name from a vault-scoped path such as
// /api/v1/vaults/prod/secrets. It returns "" for any other shape.
func vaultFromPath(path string) string {
	const marker = "/vaults/"
	idx := strings.Index(path, marker)
	if idx < 0 {
		return ""
	}
	rest := path[idx+len(marker):]
	if rest == "" {
		return ""
	}
	if slash := strings.Index(rest, "/"); slash >= 0 {
		return rest[:slash]
	}
	return rest
}
```

Then in `internal/vaultapi/client.go`, replace this line in `Do`:

```go
		return fmt.Errorf("vaultapi: %s %s: unexpected status %d", method, path, resp.StatusCode)
```

with:

```go
		return newAPIError(method, path, resp.StatusCode)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -v`
Expected: PASS — all Task 1 and Task 2 tests.

Note: `TestAPIError_MapsStatusToKind` sends `GET /api/v1/vaults`, whose path has no trailing vault segment, so `vaultFromPath` returns `""` and the hint omits the vault clause. That is intentional and covered by `TestAPIError_ForbiddenCarriesActionableRoleHint`, which uses a vault-scoped path.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/errors.go internal/vaultapi/errors_test.go internal/vaultapi/client.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): map non-2xx responses to typed, body-free errors

A 403 now names the denied data action and a role that would grant it, built
entirely from the request line. The response body is never read: a 403 or 409
payload can echo the request, and for a secret write that request carries a
secret value."
```

---

### Task 3: Retry and circuit breaking for idempotent requests only

**Files:**
- Modify: `internal/vaultapi/client.go` (`Config`, `Client`, `Do`)
- Create: `internal/vaultapi/retry_test.go`

**Interfaces:**
- Consumes: `Client.Do` and `*APIError` from Tasks 1 and 2; `retry.NewRetryableHTTPClient(client retry.HTTPClient, policy retry.Policy, cb *retry.CircuitBreaker) *retry.RetryableHTTPClient` (`internal/retry/repository_wrapper.go:173`); `retry.ExternalServicePolicy()` (`internal/retry/retry.go:62`); `retry.NewCircuitBreaker(retry.DefaultCircuitBreaker())` (`internal/retry/retry.go:144,116`).
- Produces: no new exported surface. `Config` gains `DisableRetry bool` and `RetryPolicy retry.Policy`.

**Why `RetryPolicy` is configurable:** `retry.ExternalServicePolicy()` is 5 attempts with 1s → 2s → 4s → 8s backoff (`retry.go:62-68`), so a test that exhausts it would block for ~15 seconds. Tests therefore inject a fast policy. This mirrors the existing convention in `vaultclient.Config`, whose `RetryPolicy` field documents "Zero value (MaxAttempts == 0) defaults to `retry.ExternalServicePolicy()`" — follow that exact zero-value semantic so the two clients behave alike.

**Why GETs only — this is a correctness requirement, not a preference:**

1. `retry.RetryableHTTPClient.Do` re-issues **the same `*http.Request`** on each attempt (`repository_wrapper.go:199-217`) and never rewinds the body. Attempt 2 of a POST would therefore send an empty body, silently creating a malformed resource.
2. Even with a correct rewind, auto-retrying a non-idempotent mutation is wrong here: a `POST /secrets` that succeeded server-side but whose response was lost would be retried into a duplicate secret.

So `GET` and `HEAD` go through the retrying client; every other method goes through the plain client and fails fast. Do not "fix" this by making mutations retry.

- [ ] **Step 1: Write the failing test**

Create `internal/vaultapi/retry_test.go`:

```go
package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rocketvault/internal/retry"
)

// fastPolicy is ExternalServicePolicy's shape with millisecond delays, so
// retry tests finish in milliseconds instead of the ~15s the real policy
// would take to exhaust.
func fastPolicy() retry.Policy {
	p := retry.ExternalServicePolicy()
	p.MaxAttempts = 3
	p.InitialDelay = time.Millisecond
	p.MaxDelay = 5 * time.Millisecond
	return p
}

func TestDo_RetriesIdempotentGetOnServerError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t"), RetryPolicy: fastPolicy()})
	require.NoError(t, err)

	var out struct {
		OK bool `json:"ok"`
	}
	require.NoError(t, c.Do(context.Background(), http.MethodGet, "/api/v1/vaults", nil, &out))
	require.True(t, out.OK)
	require.EqualValues(t, 3, atomic.LoadInt32(&attempts))
}

func TestDo_DoesNotRetryMutations(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	err = c.Do(context.Background(), http.MethodPost, "/api/v1/vaults/prod/secrets",
		map[string]string{"name": "api-key"}, nil)
	require.Error(t, err)
	require.EqualValues(t, 1, atomic.LoadInt32(&attempts),
		"a mutation must be attempted exactly once: retrying could duplicate the resource")
}

func TestDo_MutationBodySurvivesBecauseItIsNotRetried(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t")})
	require.NoError(t, err)

	require.NoError(t, c.Do(context.Background(), http.MethodPost, "/api/v1/vaults/prod/secrets",
		map[string]string{"name": "api-key"}, nil))
	require.JSONEq(t, `{"name":"api-key"}`, gotBody)
}

func TestDo_GivesUpAfterMaxAttempts(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t"), RetryPolicy: fastPolicy()})
	require.NoError(t, err)

	err = c.Do(context.Background(), http.MethodGet, "/api/v1/vaults", nil, nil)
	require.Error(t, err)

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindServer, apiErr.Kind)
	require.Greater(t, atomic.LoadInt32(&attempts), int32(1))
}

func TestDo_DisableRetryMakesGetSingleAttempt(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, HTTPClient: srv.Client(), Tokens: staticToken("t"), DisableRetry: true})
	require.NoError(t, err)

	require.Error(t, c.Do(context.Background(), http.MethodGet, "/api/v1/vaults", nil, nil))
	require.EqualValues(t, 1, atomic.LoadInt32(&attempts))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/vaultapi/ -run 'TestDo_Retries|TestDo_DoesNotRetry|TestDo_GivesUp|TestDo_Disable|TestDo_MutationBody' -v`
Expected: FAIL — `unknown field DisableRetry in struct literal`, and `TestDo_RetriesIdempotentGetOnServerError` fails with 1 attempt instead of 3.

- [ ] **Step 3: Write minimal implementation**

In `internal/vaultapi/client.go`, add the import:

```go
	"rocketvault/internal/retry"
```

Add the field to `Config`:

```go
	// DisableRetry turns off retry and circuit breaking for idempotent
	// requests. Tests set it to assert single-attempt behavior; production
	// callers leave it false.
	DisableRetry bool

	// RetryPolicy controls retry behavior for idempotent requests. The zero
	// value (MaxAttempts == 0) defaults to retry.ExternalServicePolicy(),
	// matching the same field on vaultclient.Config. Tests override it to
	// keep delays in milliseconds.
	RetryPolicy retry.Policy
```

Add the field to `Client`:

```go
	// retrying wraps http for idempotent requests only. It is nil when
	// DisableRetry is set.
	retrying *retry.RetryableHTTPClient
```

In `New`, build it before returning:

```go
	client := &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		http:    cfg.HTTPClient,
		tokens:  cfg.Tokens,
	}
	if !cfg.DisableRetry {
		policy := cfg.RetryPolicy
		if policy.MaxAttempts == 0 {
			policy = retry.ExternalServicePolicy()
		}
		client.retrying = retry.NewRetryableHTTPClient(
			cfg.HTTPClient,
			policy,
			retry.NewCircuitBreaker(retry.DefaultCircuitBreaker()),
		)
	}
	return client, nil
```

Replace the `c.http.Do(req)` call in `Do` with a dispatch through a new helper, and add the helper:

```go
	resp, err := c.send(req)
```

```go
// send routes the request through the retrying client when it is safe to
// repeat, and through the plain client otherwise.
//
// Only GET and HEAD are repeated. Two independent reasons require this:
// retry.RetryableHTTPClient re-issues the same *http.Request without rewinding
// its body, so a retried POST would send an empty one; and retrying a
// non-idempotent mutation risks creating the resource twice when it was the
// response, not the write, that was lost.
func (c *Client) send(req *http.Request) (*http.Response, error) {
	if c.retrying != nil && isIdempotent(req.Method) {
		return c.retrying.Do(req)
	}
	return c.http.Do(req)
}

func isIdempotent(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/vaultapi/ -race -v`
Expected: PASS — every test in the package, race-clean.

- [ ] **Step 5: Commit**

```bash
git add internal/vaultapi/client.go internal/vaultapi/retry_test.go
git commit -S --gpg-sign=61D246B30285ED35 -m "feat(vaultapi): retry idempotent requests only, via RetryableHTTPClient

GET and HEAD go through retry.RetryableHTTPClient with the external-service
policy and a circuit breaker. Mutations are attempted exactly once, for two
reasons: RetryableHTTPClient re-issues the same request without rewinding the
body, and retrying a lost-response POST would duplicate the resource."
```

---

## Verification

```bash
go build ./...
go test ./internal/vaultapi/ -race -v
go vet ./internal/vaultapi/
```

Expected: all tests pass, no vet findings, no data races.

Manual confidence check that errors carry no body — this should print a hint and no secret material:

```bash
cat > /tmp/vaultapi_hint_check_test.go <<'EOF'
// Throwaway. Delete after running.
EOF
go test ./internal/vaultapi/ -run TestAPIError_NeverLeaksResponseBody -v
```

## Notes for the next plan

Plan 02 implements `TokenSource` for service accounts. It uses the `TokenSource`
interface declared here and does **not** modify `client.go`.

An upstream limitation was found while writing this plan and is worth recording
separately: `retry.RetryableHTTPClient.Do` never rewinds request bodies across
attempts, so any future caller that retries a POST through it will silently send
an empty body. This plan sidesteps it rather than fixing it, since the fix
touches shared code with other consumers. Consider filing it in
`.claude/known-bugs.md`.
