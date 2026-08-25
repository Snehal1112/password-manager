//go:build integration

// The MCP integration suite runs the server against a real RocketVault
// instance -- real handlers, real middleware, real authorization, real
// database. Run with:
//
//	go test -tags=integration ./internal/mcpserver/...
//
// It builds the rocketvault binary and boots `serve` against a scratch
// SQLite database on a free port. A plain `go test ./...` skips this file.
//
// These tests exist to catch what the unit suite structurally cannot: every
// fake response there was written by the same person who wrote the code
// reading it, so a misread wrapper key or field name is invisible. Here the
// real server supplies the shapes.
package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rocketvault/config"
	"rocketvault/internal/vaultapi"
)

// liveVault is a running RocketVault instance for one test suite.
type liveVault struct {
	BaseURL string
	// Token is an admin session token, for provisioning fixtures.
	Token string
	// TOTPSecret is the provisioned admin's base32 TOTP secret, so a test
	// can generate a fresh code and call the login tool as this same user.
	TOTPSecret string
}

// freePort asks the OS for an unused port.
//
// A hardcoded port would collide with the developer's own server, and the
// resulting failure looks like an authorization error rather than a clash.
func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close() //nolint:errcheck

	return listener.Addr().(*net.TCPAddr).Port
}

// randomSecret generates a base64 key for the scratch config.
func randomSecret(t *testing.T) string {
	t.Helper()

	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(buf)
}

// buildBinary compiles rocketvault into dir and returns its path.
func buildBinary(t *testing.T, dir string) string {
	t.Helper()

	binary := filepath.Join(dir, "rocketvault")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = repoRoot(t)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "build rocketvault: %s", output)
	return binary
}

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root")
	return ""
}

// startLiveVault boots a RocketVault server and provisions an admin.
func startLiveVault(t *testing.T) *liveVault {
	t.Helper()

	dir := t.TempDir()
	binary := buildBinary(t, dir)
	port := freePort(t)

	configPath := filepath.Join(dir, ".rocketvault.yaml")
	bootstrapToken := randomSecret(t)
	writeScratchConfig(t, configPath, dir, port, bootstrapToken)

	// Start the server. Output goes to the test log, so a startup failure is
	// diagnosable rather than silent.
	serve := exec.Command(binary, "serve", "--config", configPath)
	serve.Dir = dir
	serve.Stdout = &testLogWriter{t: t, prefix: "serve out"}
	serve.Stderr = &testLogWriter{t: t, prefix: "serve err"}
	require.NoError(t, serve.Start())

	// Teardown runs even on panic, so a failed run never leaves a server
	// holding the port.
	t.Cleanup(func() {
		if serve.Process != nil {
			_ = serve.Process.Kill()
			_, _ = serve.Process.Wait()
		}
	})

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForHealth(t, baseURL)

	// Provision an admin using the bootstrap token. The command prints an
	// otpauth:// URL for the new account's TOTP secret; login always
	// requires a code, so the harness must extract and use it.
	admin := exec.Command(binary, "users", "admin",
		"--config", configPath,
		"--admin-username", "itadmin",
		"--admin-password", "Integration-Test-Pass-1",
		"--bootstrap-token", bootstrapToken)
	admin.Dir = dir
	output, err := admin.CombinedOutput()
	require.NoError(t, err, "create admin: %s", output)

	totpSecret := parseTOTPSecret(t, string(output))
	live := &liveVault{
		BaseURL:    baseURL,
		Token:      loginToken(t, baseURL, totpSecret),
		TOTPSecret: totpSecret,
	}

	// Vault data-plane routes are deny-by-default (CLAUDE.md), with no
	// bypass for the global admin role -- the same way vault purge has none.
	// The provisioned admin can manage role assignments (that check does
	// have an admin bypass), but reading or writing a secret still needs an
	// explicit grant on the vault, or every write/read/crypto test below
	// would fail with 403 before reaching the behavior under test.
	live.grantVaultRole(t, "default", "itadmin", "Key Vault Administrator")
	return live
}

// grantVaultRole calls the role-assignment API directly with the harness's
// admin token, rather than going through the CLI: the CLI's session cache
// is a separate concern from this harness's raw-token auth, and a direct
// call is one fewer thing that can be wrong.
func (l *liveVault) grantVaultRole(t *testing.T, vault, principal, role string) {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"principal": principal,
		"role":      role,
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, //nolint:noctx
		l.BaseURL+"/api/v1/vaults/"+vault+"/role-assignments", strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+l.Token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"grant %q to %q in vault %q: %s", role, principal, vault, respBody)
}

// writeScratchConfig writes a minimal config for the scratch instance.
//
// It is generated per run rather than copied from the repo, so no test can
// touch real data or a real master key. jwt.key_source is self_pki rather
// than the default os_store, since os_store searches the OS certificate
// store for a CN -- a dependency a CI runner or sandboxed test process
// should not need. self_pki derives its key from the vault's own crypto
// service, which the scratch master_key already provides.
func writeScratchConfig(t *testing.T, path, dir string, port int, bootstrapToken string) {
	t.Helper()

	contents := fmt.Sprintf(`
master_key: %q
bootstrap_token: %q

server:
  listen_addr: ":%d"
  read_timeout: "30s"
  write_timeout: "30s"

database:
  driver: "sqlite3"
  connection: %q

jwt:
  key_source: "self_pki"
  expiry: "15m"

oidc:
  enabled: false

monitoring:
  enable_metrics: false
`,
		randomSecret(t), bootstrapToken, port,
		filepath.Join(dir, "test.db"),
	)
	require.NoError(t, os.WriteFile(path, []byte(strings.TrimSpace(contents)), 0o600))
}

// waitForHealth polls until the server answers, rather than sleeping.
//
// A fixed sleep is either slow or flaky, and usually both across machines.
func waitForHealth(t *testing.T, baseURL string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/api/v1/health") //nolint:gosec,noctx
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < http.StatusInternalServerError {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become healthy within 30s", baseURL)
}

// parseTOTPSecret extracts the base32 secret from the otpauth:// URL that
// `users admin` prints, so the harness can generate a valid code for login.
func parseTOTPSecret(t *testing.T, output string) string {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		const prefix = "TOTP Secret: "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		parsed, err := url.Parse(raw)
		require.NoError(t, err, "parse TOTP otpauth URL")
		secret := parsed.Query().Get("secret")
		require.NotEmpty(t, secret, "otpauth URL had no secret parameter")
		return secret
	}
	t.Fatalf("admin command output had no TOTP Secret line:\n%s", output)
	return ""
}

// totpCode generates the current 6-digit code for secret via oathtool, the
// same tool used for manual live verification during this project's earlier
// plans -- avoiding a dependency on any particular Go TOTP library matching
// the server's.
func totpCode(t *testing.T, secret string) string {
	t.Helper()

	out, err := exec.Command("oathtool", "--totp", "-b", secret).Output()
	require.NoError(t, err, "generate TOTP code")
	return strings.TrimSpace(string(out))
}

// loginToken authenticates as the provisioned admin and returns its token.
func loginToken(t *testing.T, baseURL, totpSecret string) string {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"username":  "itadmin",
		"password":  "Integration-Test-Pass-1",
		"totp_code": totpCode(t, totpSecret),
	})
	require.NoError(t, err)

	resp, err := http.Post(baseURL+"/api/v1/users/login", //nolint:gosec,noctx
		"application/json", strings.NewReader(string(body)))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "admin login should succeed: %s", respBody)

	var decoded struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(respBody, &decoded))
	require.NotEmpty(t, decoded.Token)
	return decoded.Token
}

// staticLiveToken is a TokenSource returning the harness's admin token.
type staticLiveToken string

func (s staticLiveToken) Token(context.Context) (string, error) { return string(s), nil }

// mcpServer builds an MCP server pointed at this live instance.
func (l *liveVault) mcpServer(t *testing.T, cfg config.MCPConfig) *Server {
	t.Helper()

	swappable := vaultapi.NewSwappableSource(staticLiveToken(l.Token))
	client, err := vaultapi.New(vaultapi.Config{
		BaseURL:    l.BaseURL,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		Tokens:     swappable,
	})
	require.NoError(t, err)

	s, err := New(Deps{
		Client: client, Config: cfg, Logger: discardLogger(), Version: "integration",
		Identity: swappable,
	})
	require.NoError(t, err)
	RegisterAllTools(s)
	return s
}

// testLogWriter routes subprocess output into the test log.
type testLogWriter struct {
	t      *testing.T
	prefix string
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("[%s] %s", w.prefix, strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func TestHarness_BootsAndAuthenticates(t *testing.T) {
	live := startLiveVault(t)

	require.NotEmpty(t, live.BaseURL)
	require.NotEmpty(t, live.Token, "the harness must produce a usable admin session")
}

func TestHarness_ServerAnswersHealth(t *testing.T) {
	live := startLiveVault(t)

	resp, err := http.Get(live.BaseURL + "/api/v1/health") //nolint:gosec,noctx
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Less(t, resp.StatusCode, http.StatusInternalServerError)
}
