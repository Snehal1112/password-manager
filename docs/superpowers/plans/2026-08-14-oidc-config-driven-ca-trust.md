# Config-Driven CA Trust for OIDC — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `SSL_CERT_FILE` environment variable workaround (needed today so Go trusts an OIDC issuer signed by a private/internal CA) with a first-class `oidc.ca_cert_path` config option in `.rocketvault.yaml`. `SSL_CERT_FILE` is process-wide, invisible in the config file, and easy to forget on restart — this bit twice during manual OIDC testing on 2026-08-13 (the server started successfully but with OIDC silently unavailable both times `SSL_CERT_FILE` was omitted).

**Architecture:** `go-oidc`/`oauth2` both read a custom `*http.Client` from the request context via a shared context key — `oidc.ClientContext(ctx, client)` sets it, and `oauth2.Config.Exchange`/`oidc.Provider.UserInfo` both read it back automatically, since `oidc.ClientContext` is documented as "sets the same context key used by the golang.org/x/oauth2 package." `OIDCConfig` gains an optional `CACertPath` field; when set, `NewOIDCService` builds an `*http.Client` whose TLS trust pool is the system pool plus that PEM file, wraps the discovery-fetch context with it, and stores the client on `oidcService` so `HandleCallback`'s token-exchange and userinfo calls use the same trust pool. Empty `CACertPath` (the default) is byte-for-byte the existing behavior — this is purely additive.

**Tech Stack:** Go, `github.com/coreos/go-oidc/v3` (already a dependency, confirmed `oidc.ClientContext` exists via `go doc`), `crypto/x509`, `crypto/tls`, `net/http/httptest` for tests.

## Global Constraints

- `go build ./...` and `go vet ./...` must pass after every task.
- Empty `CACertPath` must produce byte-identical behavior to before this plan — no behavior change for deployments that don't set `oidc.ca_cert_path`. Every existing `oidc_service_test.go` test must keep passing unchanged.
- Do not touch the system CA trust store or suggest `sudo update-ca-certificates` as part of this plan — the whole point is a config-driven, no-sudo alternative that works per-deployment.
- Model tiering per the user's request: Task 1 (TLS/cert-pool code + tests) needs real design judgment, so its plan text below contains complete, ready-to-transcribe code — this turns the implementer's job into "transcribe and verify" so a cheap model suffices there too, matching how tasks were tiered in the previous CLAUDE.md-update plan in this same session. Task 2 (one struct-literal line, container wiring) and Task 3 (one YAML edit + a manual server restart) are mechanical — cheapest tier. No task in this plan needs a highly capable model; escalate only if the fix loop requires it (subagent-driven-development's Model Selection section covers this — rounds 4-5 escalate a tier).

---

### Task 1: Add `CACertPath` to `OIDCConfig`, wire a custom-CA HTTP client through `NewOIDCService` and `HandleCallback`

**Files:**
- Modify: `internal/services/auth/oidc_service.go`
- Test: `internal/services/auth/oidc_service_test.go`

**Interfaces:**
- Consumes: `oidc.ClientContext(ctx, client) context.Context` (`github.com/coreos/go-oidc/v3/oidc`, confirmed present via `go doc github.com/coreos/go-oidc/v3/oidc ClientContext`), `x509.SystemCertPool()`, `x509.CertPool.AppendCertsFromPEM`.
- Produces: `OIDCConfig.CACertPath string` — consumed by Task 2's container wiring.

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/auth/oidc_service_test.go` (add `"crypto/x509"`, `"encoding/pem"`, `"os"`, `"path/filepath"` to the import block):

```go
// caCertPathFromServer writes srv's own leaf certificate to a temp PEM file
// and returns the path. httptest.NewTLSServer's certificate is self-signed,
// so it is its own trust anchor for these tests — exactly analogous to a
// private CA's root certificate in production.
func caCertPathFromServer(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	path := filepath.Join(t.TempDir(), "test-ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))
	return path
}

func TestNewOIDCService_CustomCACert_TrustsSelfSignedIssuer(t *testing.T) {
	srv, _ := newTestOIDCTLSProvider(t)
	caPath := caCertPathFromServer(t, srv)

	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		CACertPath: caPath,
	})
	require.NoError(t, err)
}

func TestNewOIDCService_WithoutCACertPath_RejectsUntrustedTLSIssuer(t *testing.T) {
	srv, _ := newTestOIDCTLSProvider(t)

	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		// CACertPath deliberately empty.
	})
	require.Error(t, err, "a self-signed issuer must be rejected without an explicit CACertPath")
}

func TestNewOIDCService_InvalidCACertPath_ReturnsClearError(t *testing.T) {
	srv, _ := newTestOIDCProvider(t) // plain HTTP is fine here; discovery never happens

	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
		CACertPath: "/nonexistent/path/does-not-exist.pem",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "ca_cert_path")
}

// newTestOIDCTLSProvider is newTestOIDCProvider's TLS counterpart, needed to
// test CA trust — a plain-HTTP test server can't exercise TLS verification
// at all. Duplicated rather than parameterizing newTestOIDCProvider because
// httptest.NewServer and httptest.NewTLSServer return incompatible startup
// sequences (TLS needs the server started before its URL is known, to read
// back its own certificate).
func newTestOIDCTLSProvider(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                               issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": jwtBase64URLEncode(key.N.Bytes()),
				"e": jwtBase64URLEncode([]byte{1, 0, 1}),
			}},
		})
	})
	srv := httptest.NewTLSServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return srv, key
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/services/auth/... -run 'TestNewOIDCService_CustomCACert|TestNewOIDCService_WithoutCACertPath|TestNewOIDCService_InvalidCACertPath' -v`

Expected: `TestNewOIDCService_CustomCACert_TrustsSelfSignedIssuer` FAILs — compile error (`CACertPath` field doesn't exist yet) or, once that's stubbed in without the real logic, a TLS trust failure, since nothing reads the field yet. `TestNewOIDCService_WithoutCACertPath_RejectsUntrustedTLSIssuer` already passes today (a self-signed server is rejected with no code change) — that's expected, it's a regression guard for the next step, not a red test being driven green.

- [ ] **Step 3: Implement `CACertPath` and the custom-CA HTTP client**

In `internal/services/auth/oidc_service.go`, add `"crypto/tls"`, `"crypto/x509"`, `"net/http"`, `"os"` to the import block.

Change:

```go
// OIDCConfig holds OIDCService's configuration.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}
```

to:

```go
// OIDCConfig holds OIDCService's configuration.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// CACertPath, if set, is the path to a PEM-encoded CA certificate added
	// to the system trust pool for every outbound HTTPS call this service
	// makes to the issuer (discovery, token exchange, userinfo). Needed when
	// the issuer's TLS certificate is signed by a private CA the OS doesn't
	// already trust. This is the config-driven alternative to setting the
	// SSL_CERT_FILE environment variable process-wide before starting
	// RocketVault — SSL_CERT_FILE is invisible in .rocketvault.yaml and easy
	// to forget on restart, silently leaving OIDC unavailable. Empty (the
	// default) means use the system trust store only, unchanged from before
	// this field existed.
	CACertPath string
}
```

Change:

```go
type oidcService struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

// NewOIDCService fetches the provider's discovery document (a network round
// trip to issuerURL) and returns a ready-to-use OIDCService, or an error if
// the issuer is unreachable or malformed.
func NewOIDCService(ctx context.Context, cfg OIDCConfig) (OIDCService, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to discover issuer %q: %w", cfg.IssuerURL, err)
	}

	return &oidcService{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
	}, nil
}
```

to:

```go
type oidcService struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	// httpClient is nil unless OIDCConfig.CACertPath was set. When non-nil,
	// HandleCallback must wrap its context with it too (oidc.ClientContext),
	// so the token-exchange and userinfo calls trust the same CA pool
	// discovery used.
	httpClient *http.Client
}

// NewOIDCService fetches the provider's discovery document (a network round
// trip to issuerURL) and returns a ready-to-use OIDCService, or an error if
// the issuer is unreachable or malformed.
func NewOIDCService(ctx context.Context, cfg OIDCConfig) (OIDCService, error) {
	var httpClient *http.Client
	if cfg.CACertPath != "" {
		client, err := httpClientWithExtraCA(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("oidc: failed to load oidc.ca_cert_path %q: %w", cfg.CACertPath, err)
		}
		httpClient = client
		ctx = oidc.ClientContext(ctx, httpClient)
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to discover issuer %q: %w", cfg.IssuerURL, err)
	}

	return &oidcService{
		provider:   provider,
		verifier:   provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		httpClient: httpClient,
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
	}, nil
}

// httpClientWithExtraCA returns an *http.Client whose TLS trust pool is the
// system pool plus the PEM-encoded certificate at path. Falls back to a
// fresh empty pool if the system pool is unavailable (x509.SystemCertPool
// can return an error on some platforms), matching the standard library's
// own documented fallback pattern for this case.
func httpClientWithExtraCA(path string) (*http.Client, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA cert file: %w", err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no valid PEM certificate found in %q", path)
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}, nil
}
```

Change `HandleCallback`'s opening:

```go
// HandleCallback exchanges code for tokens, verifies the ID token's
// signature and claims (including that its nonce matches expectedNonce), and
// returns the caller's identity.
func (s *oidcService) HandleCallback(ctx context.Context, code, expectedNonce string) (*OIDCIdentity, error) {
	token, err := s.oauth2Config.Exchange(ctx, code)
```

to:

```go
// HandleCallback exchanges code for tokens, verifies the ID token's
// signature and claims (including that its nonce matches expectedNonce), and
// returns the caller's identity.
func (s *oidcService) HandleCallback(ctx context.Context, code, expectedNonce string) (*OIDCIdentity, error) {
	if s.httpClient != nil {
		ctx = oidc.ClientContext(ctx, s.httpClient)
	}

	token, err := s.oauth2Config.Exchange(ctx, code)
```

(`s.provider.UserInfo(ctx, ...)` later in the same function already receives this same, now-wrapped `ctx` — no separate change needed there.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go build ./... && go vet ./... && go test ./internal/services/auth/... -v 2>&1 | tail -60`

Expected: all pass, including the three new tests and every pre-existing test in this file (`TestOIDCService_AuthCodeURL_IncludesStateAndNonce`, `TestNewOIDCService_UnreachableIssuer_ReturnsError`) unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/services/auth/oidc_service.go internal/services/auth/oidc_service_test.go
git commit -m "feat(auth): add oidc.ca_cert_path — config-driven CA trust for private-CA issuers"
```

---

### Task 2: Wire `oidc.ca_cert_path` through the service container

**Files:**
- Modify: `internal/container/service_container.go`

**Interfaces:**
- Consumes: `authServices.OIDCConfig.CACertPath` (Task 1).
- Produces: no new exported symbols — purely connects an existing viper key to the new field.

- [ ] **Step 1: Verify the current wiring block matches this plan's assumption**

Run: `grep -n "oidc.ca_cert_path\|OIDCConfig{" internal/container/service_container.go`

Expected: `OIDCConfig{` found once, `oidc.ca_cert_path` not found at all (confirms the key isn't wired yet, and that this task's anchor text below is still accurate — re-check against the live file before editing, not just this plan's memory of it).

- [ ] **Step 2: Add the field**

In `internal/container/service_container.go`, change:

```go
	if viperCfg.GetBool("oidc.enabled") {
		oidcCfg := authServices.OIDCConfig{
			IssuerURL:    viperCfg.GetString("oidc.issuer_url"),
			ClientID:     viperCfg.GetString("oidc.client_id"),
			ClientSecret: viperCfg.GetString("oidc.client_secret"),
			RedirectURL:  viperCfg.GetString("oidc.redirect_url"),
			Scopes:       viperCfg.GetStringSlice("oidc.scopes"),
		}
```

to:

```go
	if viperCfg.GetBool("oidc.enabled") {
		oidcCfg := authServices.OIDCConfig{
			IssuerURL:    viperCfg.GetString("oidc.issuer_url"),
			ClientID:     viperCfg.GetString("oidc.client_id"),
			ClientSecret: viperCfg.GetString("oidc.client_secret"),
			RedirectURL:  viperCfg.GetString("oidc.redirect_url"),
			Scopes:       viperCfg.GetStringSlice("oidc.scopes"),
			CACertPath:   viperCfg.GetString("oidc.ca_cert_path"),
		}
```

- [ ] **Step 3: Build and run the container's existing tests**

Run: `go build ./... && go vet ./... && go test ./internal/container/... -v 2>&1 | tail -40`

Expected: clean build, all existing container tests pass unchanged (this is a pure additive field read — `viperCfg.GetString` on an unset key returns `""`, which is `OIDCConfig`'s documented empty/default value from Task 1, so no existing test's OIDC behavior changes).

- [ ] **Step 4: Commit**

```bash
git add internal/container/service_container.go
git commit -m "feat(container): wire oidc.ca_cert_path config key into OIDCConfig"
```

---

### Task 3: Update `.rocketvault.yaml`, verify manually without `SSL_CERT_FILE`

**Files:**
- Modify: `.rocketvault.yaml`

**Interfaces:**
- Consumes: `oidc.ca_cert_path` (Tasks 1-2).
- Produces: none — this task is config + manual verification only, no code.

- [ ] **Step 1: Add `ca_cert_path` to this repo's `oidc:` block**

Run: `grep -n "^oidc:" -A 6 .rocketvault.yaml` to confirm the block still looks like this plan expects before editing (re-check live values, don't assume):

```yaml
oidc:
  enabled: true
  issuer_url: "https://exchange4all.local:8443/"
  client_id: "numericlabs"
  client_secret: ""
  redirect_url: "https://numericlabs.lxd/api/v1/oidc/callback"
  scopes: ["openid", "profile", "email", "E4A.App"]
```

Change it to:

```yaml
oidc:
  enabled: true
  issuer_url: "https://exchange4all.local:8443/"
  client_id: "numericlabs"
  client_secret: ""
  redirect_url: "https://numericlabs.lxd/api/v1/oidc/callback"
  scopes: ["openid", "profile", "email", "E4A.App"]
  ca_cert_path: "/home/numericlabs/Downloads/root-ca-e4a.crt"
```

(This keeps pointing at the same CA file used in yesterday's manual test session — relocating that file out of `~/Downloads/` into a more permanent location is a separate decision the plan author is not making unilaterally; flag it to the user as a follow-up suggestion rather than doing it here.)

- [ ] **Step 2: Build the binary**

Run: `go build -o rocketvault .`

Expected: clean build.

- [ ] **Step 3: Start the server WITHOUT `SSL_CERT_FILE` and confirm OIDC still initializes**

Run: `./rocketvault serve > /tmp claude-scratch-oidc-verify.log 2>&1 &` (adjust the log path to this session's actual scratchpad directory), wait ~2 seconds, then:

Run: `grep -i oidc /tmp/claude-scratch-oidc-verify.log`

Expected: `"OIDC service initialised"` appears — with no `SSL_CERT_FILE` set in the environment this time. If instead `"Failed to initialise OIDC service"` appears, the fix did not take effect; stop and re-check Task 1/2 rather than proceeding.

- [ ] **Step 4: Confirm the login redirect still works and reaches the real issuer**

Run: `curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8774/api/v1/oidc/login`

Expected: `302`.

Run (using a real state/nonce from the redirect, same pattern as prior manual testing — see the curl examples given earlier in this session):
```bash
curl -sv -c /tmp/claude-scratch-oidc-cookies.txt http://localhost:8774/api/v1/oidc/login >/dev/null 2>&1
STATE=$(grep oidc_state /tmp/claude-scratch-oidc-cookies.txt | awk '{print $7}')
NONCE=$(grep oidc_nonce /tmp/claude-scratch-oidc-cookies.txt | awk '{print $7}')
curl -s -w "\nHTTP %{http_code}\n" -b /tmp/claude-scratch-oidc-cookies.txt \
  "http://localhost:8774/api/v1/oidc/callback?state=$STATE&code=bogus-code-confirms-real-token-endpoint-reached"
```

Expected: a real `invalid_grant`-style rejection from the live token endpoint (same shape as the test done earlier this session) and `401` — proving the custom-CA client is actually being used for the token-exchange call too, not just the discovery fetch at startup.

- [ ] **Step 5: Stop the test server**

Run: `pkill -f "./rocketvault serve"` (or the equivalent for however it was started).

- [ ] **Step 6: Commit**

```bash
git add .rocketvault.yaml
git commit -m "feat(config): use oidc.ca_cert_path instead of SSL_CERT_FILE for the private-CA test issuer"
```

---

## Self-Review Notes (from plan authoring)

- **Spec coverage:** the user's ask — "find a different way to use SSL_CERT_FILE... which seems wrong" — maps to all three tasks: Task 1 builds the mechanism, Task 2 wires config through, Task 3 proves `SSL_CERT_FILE` is no longer needed by actually omitting it in a live test. Nothing in the ask is left uncovered.
- **Placeholder scan:** no TBD/TODO; every code block is complete, copy-pasteable Go or YAML.
- **Type/name consistency:** `OIDCConfig.CACertPath` (Task 1) → `oidcCfg.CACertPath` / `viperCfg.GetString("oidc.ca_cert_path")` (Task 2) — same field name throughout. `oidcService.httpClient` used consistently in both `NewOIDCService` and `HandleCallback`.
- **Verified against source, not assumed:** `oidc.ClientContext`'s existence and behavior confirmed via `go doc github.com/coreos/go-oidc/v3/oidc ClientContext` during planning (this session) — its doc comment explicitly states it shares oauth2's context key, which is the load-bearing fact this whole plan depends on. The two CA files in this environment were also compared by fingerprint during planning: `~/Downloads/root-ca-e4a.crt` (signs `exchange4all.local`, the OIDC issuer — what this plan's `ca_cert_path` needs) is a **different** CA than `/home/numericlabs/data/tls/root_ca-numericlabs.crt` (the "camanager" CA, signs `numericlabs.lxd`'s browser-facing cert via Caddy) — Task 3 points at the correct one for this specific fix; the browser-trust concern is unrelated and untouched by this plan.
