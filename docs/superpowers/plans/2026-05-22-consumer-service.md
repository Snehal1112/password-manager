# Consumer Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a minimal Go HTTP service at `examples/consumer-service/` that fetches secrets from a running RocketVault instance at startup and exposes `/healthz` and `/status` endpoints to prove the integration works.

**Architecture:** Four files in `examples/consumer-service/` as part of the `rocketvault` module. `config.go` loads Viper config + env overrides, `main.go` orchestrates startup (build client, fetch secrets, fetch frontend config, start server), `server.go` serves two endpoints from in-memory state. No vault calls at request time.

**Tech Stack:** Go 1.25, `net/http`, `github.com/spf13/viper`, `rocketvault/internal/vaultclient`, `encoding/json`.

---

## File Map

| Path | Action | Responsibility |
|---|---|---|
| `examples/consumer-service/config.go` | Create | Viper loading, env overrides, `AppConfig` struct |
| `examples/consumer-service/main.go` | Create | Startup orchestration: build client, fetch secrets, start server |
| `examples/consumer-service/server.go` | Create | `/healthz` and `/status` HTTP handlers |
| `examples/consumer-service/config.yaml` | Create | Example config with safe placeholder values |

---

## Task 1: Config loader

**Files:**
- Create: `examples/consumer-service/config.go`
- Create: `examples/consumer-service/config.yaml`

- [ ] **Step 1: Create the config.yaml placeholder**

```bash
mkdir -p /home/numericlabs/data/rocket/rocketvault/examples/consumer-service
```

Create `examples/consumer-service/config.yaml`:

```yaml
vault:
  url: "http://localhost:8774"
  client_id: ""      # set here or via VAULT_CLIENT_ID env var
  secrets:
    - name: DB_PASSWORD
      uuid: ""       # fill in UUID from RocketVault
    - name: API_KEY
      uuid: ""

server:
  listen: ":9000"
```

- [ ] **Step 2: Create `examples/consumer-service/config.go`**

```go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/viper"

	"rocketvault/internal/vaultclient"
)

// AppConfig holds all configuration for the consumer service.
type AppConfig struct {
	VaultURL     string
	ClientID     string
	ClientSecret string
	Secrets      []vaultclient.SecretMapping
	Listen       string
}

// loadConfig reads config.yaml from the same directory as the binary,
// then applies VAULT_URL, VAULT_CLIENT_ID, VAULT_CLIENT_SECRET env var overrides.
func loadConfig() (*AppConfig, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./examples/consumer-service")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("loadConfig: %w", err)
	}

	// Env vars override config file values.
	url := v.GetString("vault.url")
	if env := os.Getenv("VAULT_URL"); env != "" {
		url = env
	}

	clientID := v.GetString("vault.client_id")
	if env := os.Getenv("VAULT_CLIENT_ID"); env != "" {
		clientID = env
	}

	// client_secret is env-only — never stored in config file.
	clientSecret := os.Getenv("VAULT_CLIENT_SECRET")

	var secrets []vaultclient.SecretMapping
	if err := v.UnmarshalKey("vault.secrets", &secrets); err != nil {
		return nil, fmt.Errorf("loadConfig: vault.secrets: %w", err)
	}

	listen := v.GetString("server.listen")
	if listen == "" {
		listen = ":9000"
	}

	return &AppConfig{
		VaultURL:     url,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Secrets:      secrets,
		Listen:       listen,
	}, nil
}
```

- [ ] **Step 3: Verify the package compiles**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./examples/consumer-service/... 2>&1
```

Expected: compile error — `main.go` missing. That is fine at this step; if it says `no Go files` or similar, the config.go syntax is correct. If it says a type error in config.go itself, fix that first.

- [ ] **Step 4: Commit**

```bash
git add examples/consumer-service/config.go examples/consumer-service/config.yaml
git commit -m "feat(examples): add consumer service config loader"
```

GPG-signed (key 61D246B30285ED35). Do NOT use --no-verify.

---

## Task 2: HTTP server

**Files:**
- Create: `examples/consumer-service/server.go`

- [ ] **Step 1: Create `examples/consumer-service/server.go`**

```go
package main

import (
	"encoding/json"
	"net/http"
)

// SecretStatus records whether a secret was successfully loaded at startup.
type SecretStatus struct {
	Loaded bool   `json:"loaded"`
	Masked string `json:"masked,omitempty"`
	Error  string `json:"error,omitempty"`
}

// StatusResponse is the payload returned by GET /status.
type StatusResponse struct {
	VaultURL            string                  `json:"vault_url"`
	ClientID            string                  `json:"client_id"`
	Secrets             map[string]SecretStatus `json:"secrets"`
	FrontendConfig      map[string]any          `json:"frontend_config"`
	FrontendConfigError string                  `json:"frontend_config_error,omitempty"`
	StartupError        string                  `json:"startup_error,omitempty"`
}

// Server holds the in-memory state populated at startup.
type Server struct {
	status StatusResponse
	listen string
}

// NewServer creates a Server with the given startup state.
func NewServer(status StatusResponse, listen string) *Server {
	return &Server{status: status, listen: listen}
}

// Start registers routes and blocks serving HTTP.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/status", s.handleStatus)
	return http.ListenAndServe(s.listen, mux)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.status) //nolint:errcheck
}

// maskSecret applies the masking rule:
// empty → "(empty)", len ≤ 4 → "***", len > 4 → first 4 chars + "***"
func maskSecret(v string) string {
	if v == "" {
		return "(empty)"
	}
	if len(v) <= 4 {
		return "***"
	}
	return v[:4] + "***"
}
```

- [ ] **Step 2: Verify the package still compiles (syntax check)**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go vet ./examples/consumer-service/... 2>&1
```

Expected: error about missing `main` function — that is fine. Any other error means a syntax problem in server.go.

- [ ] **Step 3: Commit**

```bash
git add examples/consumer-service/server.go
git commit -m "feat(examples): add consumer service HTTP server"
```

GPG-signed. Do NOT use --no-verify.

---

## Task 3: Main entrypoint

**Files:**
- Create: `examples/consumer-service/main.go`

- [ ] **Step 1: Create `examples/consumer-service/main.go`**

```go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"rocketvault/internal/vaultclient"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// Build vault client — fatal if credentials are missing or auth fails.
	client, err := vaultclient.New(vaultclient.Config{
		URL:          cfg.VaultURL,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Probe auth with a token fetch by trying the first secret.
	// If ErrAuthFailed, exit immediately.
	secretStatuses := make(map[string]SecretStatus, len(cfg.Secrets))
	for _, s := range cfg.Secrets {
		if s.UUID == "" {
			secretStatuses[s.Name] = SecretStatus{
				Loaded: false,
				Error:  "uuid not configured",
			}
			continue
		}

		val, fetchErr := client.Get(ctx, s.UUID)
		if fetchErr != nil {
			if errors.Is(fetchErr, vaultclient.ErrAuthFailed) {
				fmt.Fprintf(os.Stderr, "vault auth failed: %v\n", fetchErr)
				os.Exit(1)
			}
			secretStatuses[s.Name] = SecretStatus{
				Loaded: false,
				Error:  fetchErr.Error(),
			}
			continue
		}

		secretStatuses[s.Name] = SecretStatus{
			Loaded: true,
			Masked: maskSecret(val),
		}
	}

	// Fetch frontend config from RocketVault — non-fatal.
	frontendCfg, frontendErr := fetchFrontendConfig(cfg.VaultURL)

	status := StatusResponse{
		VaultURL: cfg.VaultURL,
		ClientID: cfg.ClientID,
		Secrets:  secretStatuses,
		FrontendConfig: frontendCfg,
	}
	if frontendErr != nil {
		status.FrontendConfigError = frontendErr.Error()
	}

	srv := NewServer(status, cfg.Listen)
	fmt.Printf("consumer service listening on %s\n", cfg.Listen)
	fmt.Printf("  vault: %s (client_id: %s)\n", cfg.VaultURL, cfg.ClientID)
	fmt.Printf("  GET %s/status  — secret load results\n", cfg.Listen)
	fmt.Printf("  GET %s/healthz — liveness check\n", cfg.Listen)

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// fetchFrontendConfig calls GET /api/v1/config on RocketVault.
func fetchFrontendConfig(vaultURL string) (map[string]any, error) {
	resp, err := http.Get(vaultURL + "/api/v1/config") //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("GET /api/v1/config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /api/v1/config: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GET /api/v1/config: read body: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("GET /api/v1/config: decode: %w", err)
	}
	return result, nil
}
```

- [ ] **Step 2: Build the complete package**

```bash
cd /home/numericlabs/data/rocket/rocketvault
go build ./examples/consumer-service/... 2>&1
```

Expected: no errors. A binary is produced (discarded — we use `go run`).

- [ ] **Step 3: Build the entire repo to check for regressions**

```bash
go build ./... 2>&1
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add examples/consumer-service/main.go
git commit -m "feat(examples): add consumer service main entrypoint"
```

GPG-signed. Do NOT use --no-verify.

---

## Task 4: End-to-end smoke test

This task requires a running RocketVault instance. Follow each step in order.

**Pre-requisite:** RocketVault binary is built (`go build -o ./rocketvault .`).

- [ ] **Step 1: Start RocketVault in the background**

```bash
cd /home/numericlabs/data/rocket/rocketvault
./rocketvault serve &
VAULT_PID=$!
sleep 1
echo "RocketVault PID: $VAULT_PID"
```

Expected: server logs appear, ending with `Server ready to handle requests`.

- [ ] **Step 2: Create an admin user (if not already created)**

```bash
./rocketvault users admin \
  --admin-username=admin \
  --admin-password=admin123 \
  --bootstrap-token=***SECRET-REMOVED-2026-08-17***
```

Expected: `Admin user created successfully` or `user already exists`.

- [ ] **Step 3: Get an admin JWT (requires TOTP — use your authenticator app)**

```bash
ADMIN_JWT=$(curl -s -X POST http://localhost:8774/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","totp_code":"<6-digit-code>"}' \
  | jq -r '.token')
echo "JWT: ${ADMIN_JWT:0:20}..."
```

Replace `<6-digit-code>` with the current TOTP code from your authenticator.
Expected: a JWT string starting with `eyJ`.

- [ ] **Step 4: Create a service account**

```bash
SA_RESPONSE=$(curl -s -X POST http://localhost:8774/api/v1/service-accounts \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"consumer-test","description":"consumer service smoke test"}')

SA_CLIENT_ID=$(echo $SA_RESPONSE | jq -r '.client_id')
SA_CLIENT_SECRET=$(echo $SA_RESPONSE | jq -r '.client_secret')

echo "client_id:     $SA_CLIENT_ID"
echo "client_secret: ${SA_CLIENT_SECRET:0:8}..."
```

Expected: both values are non-empty strings.

- [ ] **Step 5: Create a test secret**

```bash
SECRET_RESPONSE=$(curl -s -X POST http://localhost:8774/api/v1/secrets \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"DB_PASSWORD","value":"super-secret-db-pass","description":"test secret"}')

SECRET_UUID=$(echo $SECRET_RESPONSE | jq -r '.id')
echo "secret UUID: $SECRET_UUID"
```

Expected: a UUID string like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.

- [ ] **Step 6: Update `examples/consumer-service/config.yaml` with real values**

Edit `examples/consumer-service/config.yaml`:

```yaml
vault:
  url: "http://localhost:8774"
  client_id: "<paste SA_CLIENT_ID here>"
  secrets:
    - name: DB_PASSWORD
      uuid: "<paste SECRET_UUID here>"
    - name: API_KEY
      uuid: ""

server:
  listen: ":9000"
```

- [ ] **Step 7: Run the consumer service**

```bash
export VAULT_CLIENT_SECRET="$SA_CLIENT_SECRET"
go run ./examples/consumer-service/ &
CONSUMER_PID=$!
sleep 1
```

Expected startup output:
```
consumer service listening on :9000
  vault: http://localhost:8774 (client_id: consumer-test)
  GET :9000/status  — secret load results
  GET :9000/healthz — liveness check
```

- [ ] **Step 8: Test /healthz**

```bash
curl -s http://localhost:9000/healthz | jq .
```

Expected:
```json
{"status": "ok"}
```

- [ ] **Step 9: Test /status**

```bash
curl -s http://localhost:9000/status | jq .
```

Expected (DB_PASSWORD loaded, API_KEY not configured):
```json
{
  "vault_url": "http://localhost:8774",
  "client_id": "consumer-test",
  "secrets": {
    "DB_PASSWORD": {"loaded": true, "masked": "supe***"},
    "API_KEY":     {"loaded": false, "error": "uuid not configured"}
  },
  "frontend_config": {
    "feature_flags": {},
    "public_api_url": "http://localhost:8774",
    "sentry_dsn": ""
  }
}
```

- [ ] **Step 10: Stop both services**

```bash
kill $CONSUMER_PID $VAULT_PID 2>/dev/null
wait $CONSUMER_PID $VAULT_PID 2>/dev/null
echo "done"
```

- [ ] **Step 11: Commit the final config.yaml with placeholders restored**

After testing, restore `config.yaml` to safe placeholder values (no real UUIDs or client IDs committed):

```yaml
vault:
  url: "http://localhost:8774"
  client_id: ""
  secrets:
    - name: DB_PASSWORD
      uuid: ""
    - name: API_KEY
      uuid: ""

server:
  listen: ":9000"
```

```bash
git add examples/consumer-service/config.yaml
git commit -m "chore(examples): restore consumer service config to safe placeholders"
```

GPG-signed. Do NOT use --no-verify.

---

## Self-Review Checklist

**Spec coverage:**
- [x] §2 Location — `examples/consumer-service/` in `rocketvault` module — Task 1
- [x] §3 File structure — 4 files across Tasks 1-3
- [x] §4.1 config.yaml — Task 1
- [x] §4.2 Env var overrides — Task 1 (`config.go` priority chain)
- [x] §5 Startup flow — Task 3 (`main.go` orchestration)
- [x] §6 `/healthz` endpoint — Task 2 (`server.go`)
- [x] §6 `/status` endpoint — Task 2 (`server.go`) + Task 3 (`StatusResponse`)
- [x] §7 Masking rule — Task 2 (`maskSecret` function)
- [x] §8 Fatal on missing credentials / ErrAuthFailed — Task 3 (`main.go`)
- [x] §8 Non-fatal on ErrSecretNotFound / network error — Task 3 (`main.go`)
- [x] §8 Non-fatal on frontend_config fetch failure — Task 3 (`fetchFrontendConfig`)
- [x] §10 Usage — Task 4 (end-to-end smoke test steps)
