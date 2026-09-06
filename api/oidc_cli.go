package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"rocketvault/model"
)

const cliExchangeCodeTTL = 60 * time.Second

// validateCLIRedirectURI restricts cli_redirect_uri to
// http://127.0.0.1:<port> or http://localhost:<port>, with no other
// scheme or host accepted. This is the one new externally reachable input
// on the OIDC login route, so it is intentionally an allow-list.
// An empty raw value is treated as "no CLI redirect requested" and is not
// an error — that is the existing browser-login behavior.
func validateCLIRedirectURI(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid cli_redirect_uri")
	}
	if u.Scheme != "http" {
		return "", fmt.Errorf("cli_redirect_uri must use http")
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" {
		return "", fmt.Errorf("cli_redirect_uri must target 127.0.0.1 or localhost")
	}
	if u.Port() == "" {
		return "", fmt.Errorf("cli_redirect_uri must include a port")
	}
	return raw, nil
}

// cliExchangeStore holds short-lived, single-use exchange codes that stand
// in for a LoginResponse during the CLI loopback flow, so the access/
// refresh token itself never appears in a URL. Pure in-memory — losing the
// map on server restart just means the user retries
// `rocketvault users login --oidc`.
type cliExchangeStore struct {
	mu      sync.Mutex
	entries map[string]cliExchangeEntry
}

type cliExchangeEntry struct {
	response  model.LoginResponse
	expiresAt time.Time
}

func newCLIExchangeStore() *cliExchangeStore {
	return &cliExchangeStore{entries: make(map[string]cliExchangeEntry)}
}

// put stores response under a newly generated code and returns the code.
func (s *cliExchangeStore) put(response model.LoginResponse) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Self-clean on every new login attempt: a code that's minted but never
	// consumed (browser closed, CLI killed, network drop) would otherwise
	// sit in the map forever holding a live access/refresh token pair.
	// There's no background goroutine — reclaiming expired entries here,
	// piggybacking on the next put, is enough to bound the map's size.
	now := time.Now()
	for c, entry := range s.entries {
		if now.After(entry.expiresAt) {
			delete(s.entries, c)
		}
	}

	s.entries[code] = cliExchangeEntry{response: response, expiresAt: now.Add(cliExchangeCodeTTL)}
	return code, nil
}

// consume returns and deletes the entry for code — single use. The second
// return value is false for an unknown, expired, or already-consumed code.
func (s *cliExchangeStore) consume(code string) (model.LoginResponse, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[code]
	if !ok {
		return model.LoginResponse{}, false
	}
	delete(s.entries, code)

	if time.Now().After(entry.expiresAt) {
		return model.LoginResponse{}, false
	}
	return entry.response, true
}

// cliExchangeRequest is the POST /oidc/cli/exchange request body.
type cliExchangeRequest struct {
	Code string `json:"code"`
}

// cliExchangeHandler handles POST /oidc/cli/exchange: redeems a one-time
// code minted by oidcCallbackHandler for the LoginResponse it stands in for.
func (api *API) cliExchangeHandler(w http.ResponseWriter, r *http.Request) {
	var req cliExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	response, ok := api.cliExchange.consume(req.Code)
	if !ok {
		http.Error(w, "unknown or expired code", http.StatusGone)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, response)
}
