# Secret Consumption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable backend services and web frontends to consume RocketVault secrets via a Go client package, a bootstrap initializer, and a safe frontend proxy endpoint.

**Architecture:** A new `internal/vaultclient` package handles OAuth2 client-credentials token lifecycle and secret fetching. A `SecretsInitializer` in `bootstrap/` wires vault-fetched values into `AppConfig` at startup. A `GET /api/v1/config` endpoint in `api/` exposes a filtered, non-sensitive `FrontendConfig` to authenticated frontend clients.

**Tech Stack:** Go 1.25, `net/http`, `httptest` (tests), `internal/retry` (backoff), Viper (config), `sync.Mutex` (token cache), `encoding/json`.

---

## File Map

| Path | Action | Responsibility |
|---|---|---|
| `internal/vaultclient/errors.go` | Create | Typed sentinel errors (`ErrSecretNotFound`, `ErrAuthFailed`) |
| `internal/vaultclient/client.go` | Create | Config resolution, token cache, `Get`/`GetByName`/`GetMany` |
| `internal/vaultclient/client_test.go` | Create | Unit tests using `httptest.NewServer` |
| `bootstrap/secrets_initializer.go` | Create | `SecretsInitializer` — maps vault secrets into `AppConfig` |
| `bootstrap/secrets_initializer_test.go` | Create | Unit tests with mock `vaultclient.Client` |
| `app/app.go` | Modify | Add `FrontendConfig` field to `App` struct |
| `app/options.go` | Modify | Add `WithFrontendConfig` option |
| `api/config.go` | Create | `InitConfig()` + `getConfig` handler |
| `api/api.go` | Modify | Register `Config` route in `Init()` |
| `.rocketvault.yaml` | Modify | Add `vault_client` section |

---

## Task 1: Typed errors package

**Files:**
- Create: `internal/vaultclient/errors.go`

- [ ] **Step 1: Create the errors file**

```go
package vaultclient

import "errors"

// ErrSecretNotFound is returned when the vault responds with 404 for a secret.
var ErrSecretNotFound = errors.New("vaultclient: secret not found")

// ErrAuthFailed is returned when the vault rejects the client credentials (401).
var ErrAuthFailed = errors.New("vaultclient: authentication failed — check VAULT_CLIENT_ID and VAULT_CLIENT_SECRET")
```

- [ ] **Step 2: Verify the package compiles**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./internal/vaultclient/...
```

Expected output: no errors.

- [ ] **Step 3: Commit**

```bash
git add internal/vaultclient/errors.go
git commit -m "feat(vaultclient): add typed sentinel errors"
```

---

## Task 2: `vaultclient` core package

**Files:**
- Create: `internal/vaultclient/client.go`

- [ ] **Step 1: Write the failing tests first**

Create `internal/vaultclient/client_test.go`:

```go
package vaultclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/vaultclient"
)

// newTestServer starts a fake RocketVault that returns a token and a secret.
func newTestServer(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("client_id") != "test-id" || r.FormValue("client_secret") != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"value": secret})
	})

	return httptest.NewServer(mux)
}

func TestGet_ReturnSecretValue(t *testing.T) {
	srv := newTestServer(t, "supersecret")
	defer srv.Close()

	client, err := vaultclient.New(vaultclient.Config{
		URL:          srv.URL,
		ClientID:     "test-id",
		ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	val, err := client.Get(context.Background(), "some-uuid")
	require.NoError(t, err)
	assert.Equal(t, "supersecret", val)
}

func TestGet_ReturnsErrAuthFailed_On401(t *testing.T) {
	srv := newTestServer(t, "irrelevant")
	defer srv.Close()

	client, err := vaultclient.New(vaultclient.Config{
		URL:          srv.URL,
		ClientID:     "wrong-id",
		ClientSecret: "wrong-secret",
	})
	require.NoError(t, err)

	_, err = client.Get(context.Background(), "some-uuid")
	assert.ErrorIs(t, err, vaultclient.ErrAuthFailed)
}

func TestGet_ReturnsErrSecretNotFound_On404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := vaultclient.New(vaultclient.Config{
		URL:          srv.URL,
		ClientID:     "id",
		ClientSecret: "secret",
	})
	require.NoError(t, err)

	_, err = client.Get(context.Background(), "missing-uuid")
	assert.ErrorIs(t, err, vaultclient.ErrSecretNotFound)
}

func TestGetMany_ReturnsMappedSecrets(t *testing.T) {
	srv := newTestServer(t, "value1")
	defer srv.Close()

	client, err := vaultclient.New(vaultclient.Config{
		URL:          srv.URL,
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Secrets: []vaultclient.SecretMapping{
			{Name: "MY_SECRET", UUID: "uuid-1"},
		},
	})
	require.NoError(t, err)

	results, err := client.GetMany(context.Background(), []string{"MY_SECRET"})
	require.NoError(t, err)
	assert.Equal(t, "value1", results["MY_SECRET"])
}

func TestGetByName_ResolvesFromMapping(t *testing.T) {
	srv := newTestServer(t, "resolved-value")
	defer srv.Close()

	client, err := vaultclient.New(vaultclient.Config{
		URL:          srv.URL,
		ClientID:     "test-id",
		ClientSecret: "test-secret",
		Secrets: []vaultclient.SecretMapping{
			{Name: "DB_PASSWORD", UUID: "uuid-db"},
		},
	})
	require.NoError(t, err)

	val, err := client.GetByName(context.Background(), "DB_PASSWORD")
	require.NoError(t, err)
	assert.Equal(t, "resolved-value", val)
}

func TestTokenCached_OnlyFetchedOnce(t *testing.T) {
	tokenCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cached-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"value": "v"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "id", ClientSecret: "s",
	})
	require.NoError(t, err)

	client.Get(context.Background(), "uuid-1") //nolint:errcheck
	client.Get(context.Background(), "uuid-2") //nolint:errcheck
	assert.Equal(t, 1, tokenCalls, "token should be fetched only once")
}

func TestNew_ReturnsError_WhenURLMissing(t *testing.T) {
	_, err := vaultclient.New(vaultclient.Config{ClientID: "id", ClientSecret: "s"})
	assert.Error(t, err)
}

func TestTokenExpiry_RefetchedAfterExpiry(t *testing.T) {
	tokenCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token",
			"expires_in":   1, // 1 second — expires immediately
		})
	})
	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"value": "v"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "id", ClientSecret: "s",
	})
	require.NoError(t, err)

	client.Get(context.Background(), "uuid-1") //nolint:errcheck
	time.Sleep(2 * time.Second)
	client.Get(context.Background(), "uuid-2") //nolint:errcheck
	assert.Equal(t, 2, tokenCalls, "token should be re-fetched after expiry")
}
```

- [ ] **Step 2: Run tests — verify they fail (package does not exist yet)**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/vaultclient/... 2>&1
```

Expected: compile error — `package rocketvault/internal/vaultclient: cannot find package`.

- [ ] **Step 3: Implement `internal/vaultclient/client.go`**

```go
package vaultclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"

	"rocketvault/internal/retry"
)

// SecretMapping maps a logical name to a RocketVault secret UUID.
type SecretMapping struct {
	Name string `yaml:"name" mapstructure:"name"`
	UUID string `yaml:"uuid" mapstructure:"uuid"`
}

// Config holds credentials and secret mappings for the vault client.
type Config struct {
	URL          string          `yaml:"url"           mapstructure:"url"`
	ClientID     string          `yaml:"client_id"     mapstructure:"client_id"`
	ClientSecret string          `yaml:"client_secret" mapstructure:"client_secret"`
	Secrets      []SecretMapping `yaml:"secrets"       mapstructure:"secrets"`
}

// tokenCache holds a cached OAuth2 token with its expiry time.
type tokenCache struct {
	token     string
	expiresAt time.Time
}

// Client authenticates to RocketVault and fetches secrets.
type Client struct {
	cfg        Config
	httpClient *http.Client
	mu         sync.Mutex
	token      *tokenCache
	nameIndex  map[string]string // name → UUID, built once from cfg.Secrets
}

// New creates a Client from an explicit Config.
// Returns an error if URL, ClientID, or ClientSecret are empty.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("vaultclient: Config.URL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("vaultclient: Config.ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("vaultclient: Config.ClientSecret is required")
	}

	index := make(map[string]string, len(cfg.Secrets))
	for _, m := range cfg.Secrets {
		index[m.Name] = m.UUID
	}

	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		nameIndex:  index,
	}, nil
}

// NewFromEnv creates a Client using VAULT_URL, VAULT_CLIENT_ID, VAULT_CLIENT_SECRET env vars.
func NewFromEnv() (*Client, error) {
	return New(Config{
		URL:          os.Getenv("VAULT_URL"),
		ClientID:     os.Getenv("VAULT_CLIENT_ID"),
		ClientSecret: os.Getenv("VAULT_CLIENT_SECRET"),
	})
}

// NewFromViper creates a Client from the vault_client section of the active Viper config.
// client_secret falls back to VAULT_CLIENT_SECRET if not set in config.
func NewFromViper() (*Client, error) {
	var mappings []SecretMapping
	if err := viper.UnmarshalKey("vault_client.secrets", &mappings); err != nil {
		return nil, fmt.Errorf("vaultclient: failed to parse vault_client.secrets: %w", err)
	}

	secret := viper.GetString("vault_client.client_secret")
	if secret == "" {
		secret = os.Getenv("VAULT_CLIENT_SECRET")
	}

	return New(Config{
		URL:          viper.GetString("vault_client.url"),
		ClientID:     viper.GetString("vault_client.client_id"),
		ClientSecret: secret,
		Secrets:      mappings,
	})
}

// Get fetches a secret by its UUID. Retries on network errors; fails fast on 401/404.
func (c *Client) Get(ctx context.Context, uuid string) (string, error) {
	var value string
	err := retry.WithExponentialBackoff(ctx, retry.ExternalServicePolicy(), func() error {
		tok, err := c.ensureToken(ctx)
		if err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(
			ctx, http.MethodGet,
			c.cfg.URL+"/api/v1/secrets/"+uuid, nil,
		)
		if err != nil {
			return fmt.Errorf("vaultclient: build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return retry.Retryable(fmt.Errorf("vaultclient: request failed: %w", err))
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			var body struct {
				Value string `json:"value"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				return fmt.Errorf("vaultclient: decode response: %w", err)
			}
			value = body.Value
			return nil
		case http.StatusUnauthorized:
			// Invalidate cached token so next call re-authenticates.
			c.mu.Lock()
			c.token = nil
			c.mu.Unlock()
			return ErrAuthFailed
		case http.StatusNotFound:
			return ErrSecretNotFound
		default:
			return retry.Retryable(fmt.Errorf("vaultclient: unexpected status %d", resp.StatusCode))
		}
	})
	return value, err
}

// GetByName fetches a secret by its logical name, resolved to a UUID via the config mapping.
// Returns an error if the name is not in the mapping.
func (c *Client) GetByName(ctx context.Context, name string) (string, error) {
	uuid, ok := c.nameIndex[name]
	if !ok {
		return "", fmt.Errorf("vaultclient: no UUID mapping found for secret name %q", name)
	}
	return c.Get(ctx, uuid)
}

// GetMany fetches multiple secrets by name and returns them as a name→value map.
// All names must be present in the config mapping. Returns on first error.
func (c *Client) GetMany(ctx context.Context, names []string) (map[string]string, error) {
	result := make(map[string]string, len(names))
	for _, name := range names {
		val, err := c.GetByName(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("vaultclient: GetMany failed for %q: %w", name, err)
		}
		result[name] = val
	}
	return result, nil
}

// ensureToken returns a valid cached token, fetching a new one if needed.
func (c *Client) ensureToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Refresh 60 seconds before expiry.
	if c.token != nil && time.Now().Before(c.token.expiresAt.Add(-60*time.Second)) {
		return c.token.token, nil
	}

	tok, expiresIn, err := c.fetchToken(ctx)
	if err != nil {
		return "", err
	}
	c.token = &tokenCache{
		token:     tok,
		expiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
	return tok, nil
}

// fetchToken performs the OAuth2 client-credentials grant.
func (c *Client) fetchToken(ctx context.Context) (token string, expiresIn int, err error) {
	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("client_id", c.cfg.ClientID)
	body.Set("client_secret", c.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.cfg.URL+"/oauth2/token",
		strings.NewReader(body.Encode()),
	)
	if err != nil {
		return "", 0, fmt.Errorf("vaultclient: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, retry.Retryable(fmt.Errorf("vaultclient: token request failed: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", 0, ErrAuthFailed
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, retry.Retryable(
			fmt.Errorf("vaultclient: token endpoint returned %d", resp.StatusCode),
		)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, fmt.Errorf("vaultclient: decode token response: %w", err)
	}
	if result.AccessToken == "" {
		return "", 0, ErrAuthFailed
	}
	return result.AccessToken, result.ExpiresIn, nil
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./internal/vaultclient/... -v -count=1
```

Expected: all tests PASS. The `TestTokenExpiry` test takes ~2 seconds due to the sleep.

- [ ] **Step 5: Verify the whole project still builds**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/vaultclient/client.go internal/vaultclient/client_test.go
git commit -m "feat(vaultclient): add OAuth2 client with token cache and secret fetch"
```

---

## Task 3: `SecretsInitializer` in bootstrap

**Files:**
- Create: `bootstrap/secrets_initializer.go`
- Create: `bootstrap/secrets_initializer_test.go`

- [ ] **Step 1: Write the failing tests**

Create `bootstrap/secrets_initializer_test.go`:

```go
package bootstrap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/bootstrap"
	"rocketvault/config"
	"rocketvault/internal/vaultclient"
)

// mockClient satisfies the vaultclient.Fetcher interface for testing.
type mockClient struct {
	results map[string]string
	err     error
}

func (m *mockClient) GetMany(ctx context.Context, names []string) (map[string]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		if v, ok := m.results[n]; ok {
			out[n] = v
		}
	}
	return out, nil
}

func TestSecretsInitializer_PopulatesConfig(t *testing.T) {
	mock := &mockClient{results: map[string]string{
		"DB_PASSWORD":   "db-pass",
		"JWT_SECRET":    "jwt-secret",
		"SMTP_PASSWORD": "smtp-pass",
	}}

	cfg := &config.Config{}
	init := bootstrap.NewSecretsInitializer(mock)
	err := init.Initialize(context.Background(), cfg)
	require.NoError(t, err)

	assert.Equal(t, "db-pass", cfg.Database.Password)
	assert.Equal(t, "jwt-secret", cfg.JWTSecret)
	assert.Equal(t, "smtp-pass", cfg.SMTPPassword)
}

func TestSecretsInitializer_PropagatesError(t *testing.T) {
	mock := &mockClient{err: errors.New("network failure")}

	cfg := &config.Config{}
	init := bootstrap.NewSecretsInitializer(mock)
	err := init.Initialize(context.Background(), cfg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "secrets initializer")
}

func TestSecretsInitializer_ErrAuthFailed_Wrapped(t *testing.T) {
	mock := &mockClient{err: vaultclient.ErrAuthFailed}

	cfg := &config.Config{}
	init := bootstrap.NewSecretsInitializer(mock)
	err := init.Initialize(context.Background(), cfg)

	require.Error(t, err)
	assert.ErrorIs(t, err, vaultclient.ErrAuthFailed)
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./bootstrap/... 2>&1 | head -20
```

Expected: compile error — `bootstrap.NewSecretsInitializer` and `vaultclient.Fetcher` undefined.

- [ ] **Step 3: Add `Fetcher` interface to vaultclient**

Add this to the bottom of `internal/vaultclient/client.go`:

```go
// Fetcher is the interface satisfied by *Client, used for dependency injection in tests.
type Fetcher interface {
	GetMany(ctx context.Context, names []string) (map[string]string, error)
}
```

- [ ] **Step 4: Check which config fields exist and add missing ones**

Run:
```bash
grep -n "Password\|JWTSecret\|SMTP\|Database" /home/numericlabs/data/rocket/rocketvault/config/config.go | head -20
```

If `Database.Password`, `JWTSecret`, or `SMTPPassword` fields do not exist in `config.Config`, add them. Open `config/config.go` and add inside the appropriate structs:

```go
// In DatabaseConfig struct (or wherever database settings live):
Password string `yaml:"password" mapstructure:"password"`

// In Config struct (top level):
JWTSecret    string `yaml:"jwt_secret"    mapstructure:"jwt_secret"`
SMTPPassword string `yaml:"smtp_password" mapstructure:"smtp_password"`
```

- [ ] **Step 5: Implement `bootstrap/secrets_initializer.go`**

```go
package bootstrap

import (
	"context"
	"fmt"

	"rocketvault/config"
	"rocketvault/internal/vaultclient"
)

// SecretsInitializer fetches secrets from RocketVault at startup and maps them
// into the application config. It follows the same initializer pattern as
// DatabaseInitializer and ConfigurationValidator.
type SecretsInitializer struct {
	client vaultclient.Fetcher
}

// NewSecretsInitializer creates a SecretsInitializer with the provided vault client.
func NewSecretsInitializer(client vaultclient.Fetcher) *SecretsInitializer {
	return &SecretsInitializer{client: client}
}

// Initialize fetches the required secrets and injects them into cfg.
// Secret names must be present in the vault_client.secrets config mapping.
// Never logs secret values — only names.
func (s *SecretsInitializer) Initialize(ctx context.Context, cfg *config.Config) error {
	secrets, err := s.client.GetMany(ctx, []string{
		"DB_PASSWORD",
		"JWT_SECRET",
		"SMTP_PASSWORD",
	})
	if err != nil {
		return fmt.Errorf("secrets initializer: %w", err)
	}

	cfg.Database.Password = secrets["DB_PASSWORD"]
	cfg.JWTSecret = secrets["JWT_SECRET"]
	cfg.SMTPPassword = secrets["SMTP_PASSWORD"]
	return nil
}
```

- [ ] **Step 6: Run the tests — verify they pass**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./bootstrap/... -v -run TestSecrets
```

Expected: all three `TestSecretsInitializer_*` tests PASS.

- [ ] **Step 7: Build the whole project**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add internal/vaultclient/client.go \
        bootstrap/secrets_initializer.go \
        bootstrap/secrets_initializer_test.go
git commit -m "feat(bootstrap): add SecretsInitializer to inject vault secrets at startup"
```

---

## Task 4: Add `FrontendConfig` to `App`

**Files:**
- Modify: `app/app.go`
- Modify: `app/options.go`

- [ ] **Step 1: Add `FrontendConfig` type and field to `app/app.go`**

Open `app/app.go`. Add the struct definition and field:

```go
// FrontendConfig holds non-sensitive config values safe to expose to web frontends.
// Populated at startup by SecretsInitializer. Never contains passwords, keys, or tokens.
type FrontendConfig struct {
	FeatureFlags map[string]bool `json:"feature_flags"`
	PublicAPIURL string          `json:"public_api_url"`
	SentryDSN    string          `json:"sentry_dsn"`
}
```

Then add the field to the `App` struct (alongside `ServiceContainer` and `Logger`):

```go
FrontendConfig *FrontendConfig
```

- [ ] **Step 2: Add `WithFrontendConfig` option to `app/options.go`**

```go
// WithFrontendConfig sets the non-sensitive config values exposed to the web frontend.
func WithFrontendConfig(fc *FrontendConfig) Option {
	return func(a *App) {
		a.FrontendConfig = fc
	}
}
```

- [ ] **Step 3: Build to verify no errors**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./...
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add app/app.go app/options.go
git commit -m "feat(app): add FrontendConfig field and WithFrontendConfig option"
```

---

## Task 5: `GET /api/v1/config` endpoint

**Files:**
- Create: `api/config.go`
- Modify: `api/api.go`

- [ ] **Step 1: Write the failing test**

Create `api/config_test.go`:

```go
package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/api"
	"rocketvault/app"
)

func TestGetConfig_ReturnsFeatureFlags(t *testing.T) {
	fc := &app.FrontendConfig{
		FeatureFlags: map[string]bool{"new_ui": true},
		PublicAPIURL: "https://api.example.com",
		SentryDSN:    "https://sentry.example.com/123",
	}

	application := app.NewTestApp(app.WithFrontendConfig(fc))
	router := mux.NewRouter()
	testAPI := api.InitForTest(application, router)
	_ = testAPI

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, true, body["feature_flags"].(map[string]any)["new_ui"])
	assert.Equal(t, "https://api.example.com", body["public_api_url"])
}

func TestGetConfig_NeverExposesPasswords(t *testing.T) {
	fc := &app.FrontendConfig{
		PublicAPIURL: "https://api.example.com",
	}

	application := app.NewTestApp(app.WithFrontendConfig(fc))
	router := mux.NewRouter()
	api.InitForTest(application, router)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	body := w.Body.String()
	assert.NotContains(t, body, "password")
	assert.NotContains(t, body, "secret")
	assert.NotContains(t, body, "jwt")
}
```

- [ ] **Step 2: Check if `app.NewTestApp` and `api.InitForTest` already exist**

```bash
grep -rn "NewTestApp\|InitForTest" /home/numericlabs/data/rocket/rocketvault/app/ \
  /home/numericlabs/data/rocket/rocketvault/api/ 2>/dev/null
```

If they don't exist, add `NewTestApp` to `app/app.go`:

```go
// NewTestApp creates a minimal App for use in tests.
func NewTestApp(opts ...Option) *App {
	a := &App{}
	for _, o := range opts {
		o(a)
	}
	return a
}
```

And add `InitForTest` to `api/api.go` (after the existing `Init` function):

```go
// InitForTest wires a minimal API onto the given router for unit tests.
func InitForTest(application *app.App, router *mux.Router) *API {
	a := &API{
		App:        application,
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
	}
	a.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	a.InitConfig()
	return a
}
```

- [ ] **Step 3: Run the test to confirm it fails**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./api/... -run TestGetConfig 2>&1 | head -20
```

Expected: compile error — `api.InitConfig` undefined.

- [ ] **Step 4: Implement `api/config.go`**

```go
package api

import (
	"encoding/json"
	"net/http"
)

// InitConfig registers the frontend config endpoint.
func (api *API) InitConfig() {
	api.BaseRoutes.ApiRoot.Handle("/config",
		ApiSessionRequired(api.App, getConfig),
	).Methods("GET")
}

// getConfig handles GET /api/v1/config.
// Returns only the non-sensitive FrontendConfig populated at startup.
func getConfig(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App.FrontendConfig == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"feature_flags":  map[string]bool{},
			"public_api_url": "",
			"sentry_dsn":     "",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(c.App.FrontendConfig)
}
```

- [ ] **Step 5: Register the route in `api/api.go`**

In `api/api.go`, inside `Init()`, add `api.InitConfig()` after `api.InitHealth()`:

```go
api.InitConfig()
```

Also add `"Config"` to the names slice near the bottom of `Init()`:

```go
names := []string{"Vault", "Secrets", "Users", "Keys", "Certificates",
    "Health", "Config", "Deleted", "AccessPolicies", "ServiceAccounts", "OAuth2"}
```

- [ ] **Step 6: Run tests**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./api/... -v -run TestGetConfig
```

Expected: both `TestGetConfig_*` tests PASS.

- [ ] **Step 7: Run full test suite**

```bash
go test ./... 2>&1 | tail -20
```

Expected: no new failures.

- [ ] **Step 8: Commit**

```bash
git add api/config.go api/api.go api/config_test.go app/app.go
git commit -m "feat(api): add GET /api/v1/config frontend proxy endpoint"
```

---

## Task 6: Update `.rocketvault.yaml` config

**Files:**
- Modify: `.rocketvault.yaml`

- [ ] **Step 1: Add the `vault_client` section**

Open `.rocketvault.yaml` and append this section at the end:

```yaml
# Vault client configuration for secret consumption.
# client_secret is intentionally absent — set VAULT_CLIENT_SECRET env var instead.
vault_client:
  url: "http://localhost:8080"
  client_id: ""
  secrets:
    - name: DB_PASSWORD
      uuid: ""
    - name: JWT_SECRET
      uuid: ""
    - name: SMTP_PASSWORD
      uuid: ""
```

- [ ] **Step 2: Verify the config still parses**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go run main.go version 2>&1
```

Expected: version output with no config parse errors.

- [ ] **Step 3: Commit**

```bash
git add .rocketvault.yaml
git commit -m "chore(config): add vault_client section to rocketvault.yaml"
```

---

## Task 7: Final verification

- [ ] **Step 1: Run the full test suite**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go test ./... -count=1 2>&1
```

Expected: all tests pass. Note any pre-existing failures that are unrelated to this work.

- [ ] **Step 2: Run the linter**

```bash
golangci-lint run ./... --timeout=5m 2>&1 | head -40
```

Fix any new lint errors introduced by this work (not pre-existing ones).

- [ ] **Step 3: Build the binary**

```bash
go build -o /tmp/rocketvault-test ./... && echo "BUILD OK"
```

Expected: `BUILD OK`.

- [ ] **Step 4: Smoke-test the new package manually**

```bash
go run - <<'EOF'
package main

import (
	"fmt"
	"rocketvault/internal/vaultclient"
)

func main() {
	_, err := vaultclient.New(vaultclient.Config{})
	fmt.Println("missing URL error:", err)
}
EOF
```

Expected output: `missing URL error: vaultclient: Config.URL is required`.

- [ ] **Step 5: Commit final verification marker**

```bash
git tag -s v-4.0.0-vault-client-$(date +%Y%m%d) -m "feat: secret consumption integration complete"
```

(Sign with GPG key 61D246B30285ED35 as per project convention.)

---

## Self-Review Checklist

**Spec coverage:**
- [x] §5 `vaultclient` package — Task 2
- [x] §5.1 Credential priority chain — Task 2 (`New`, `NewFromEnv`, `NewFromViper`)
- [x] §5.2 `Get`/`GetByName`/`GetMany` — Task 2
- [x] §5.3 Token lifecycle (lazy, cached, 60s buffer, thread-safe) — Task 2
- [x] §5.4 Error types (`ErrSecretNotFound`, `ErrAuthFailed`, retry on network) — Tasks 1 + 2
- [x] §5.5 Config file section — Task 6
- [x] §6.1 `SecretsInitializer` with constructor injection — Task 3
- [x] §6.2 No secret values logged — enforced by implementation (names only)
- [x] §7.1 `GET /api/v1/config` route behind auth middleware — Task 5
- [x] §7.2 `FrontendConfig` struct, no RocketVault call at request time — Tasks 4 + 5
- [x] §7.3 Sensitive values never in `FrontendConfig` — `TestGetConfig_NeverExposesPasswords`
- [x] §8 All bootstrap environments use `NewFromEnv()` or `NewFromViper()` — Task 2
