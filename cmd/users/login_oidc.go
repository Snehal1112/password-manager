/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package users

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/common"
	"rocketvault/internal/container"
)

const (
	oidcLoginTimeout = 5 * time.Minute
	oidcBasePath     = "/api/v1"
)

// oidcExchangeResponse mirrors model.LoginResponse's JSON shape, returned
// by POST /oidc/cli/exchange. Duplicated rather than importing the api
// package (an HTTP server package) into the CLI's dependency graph for one
// struct shape.
type oidcExchangeResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
}

// startLoopbackListener starts an HTTP server on 127.0.0.1:<random port>
// that waits for exactly one GET request to a per-login callback path. The
// path is suffixed with a random state token so that the redirect URI
// itself binds this specific login attempt: an attacker who drives their
// own OIDC login against a guessed loopback port cannot deliver their
// exchange code into a victim's listener, because the state segment of the
// path won't match. Requests to any other path (wrong or missing state) are
// rejected without touching codeCh/errCh, so they can't race a legitimate
// callback that's still in flight.
func startLoopbackListener() (redirectURI string, wait func(timeout time.Duration) (string, error), err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("failed to start local callback listener: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	stateBytes := make([]byte, 32)
	if _, randErr := rand.Read(stateBytes); randErr != nil {
		listener.Close() //nolint:errcheck
		return "", nil, fmt.Errorf("failed to generate login state token: %w", randErr)
	}
	state := hex.EncodeToString(stateBytes)
	redirectURI = fmt.Sprintf("http://127.0.0.1:%d/callback/%s", port, state)

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	handler := http.NewServeMux()
	handler.HandleFunc("/callback/", func(w http.ResponseWriter, r *http.Request) {
		requestState := strings.TrimPrefix(r.URL.Path, "/callback/")
		if requestState != state {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Login failed: invalid state.") //nolint:errcheck
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "Login failed: missing code parameter.") //nolint:errcheck
			errCh <- fmt.Errorf("callback missing code parameter")
			return
		}
		fmt.Fprint(w, "Login successful — you can close this tab.") //nolint:errcheck
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		codeCh <- code
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(listener) //nolint:errcheck

	wait = func(timeout time.Duration) (string, error) {
		defer server.Close() //nolint:errcheck
		select {
		case code := <-codeCh:
			return code, nil
		case err := <-errCh:
			return "", err
		case <-time.After(timeout):
			return "", fmt.Errorf("timed out waiting for OIDC login to complete in the browser")
		}
	}
	return redirectURI, wait, nil
}

// exchangeOIDCCode redeems a one-time code from the loopback callback for a
// full session via POST {baseURL}/api/v1/oidc/cli/exchange.
func exchangeOIDCCode(ctx context.Context, baseURL, code string) (*common.SessionCache, error) {
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+oidcBasePath+"/oidc/cli/exchange", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exchange endpoint returned %s", resp.Status)
	}

	var exchanged oidcExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&exchanged); err != nil {
		return nil, fmt.Errorf("failed to decode exchange response: %w", err)
	}

	userID, err := uuid.Parse(exchanged.UserID)
	if err != nil {
		return nil, fmt.Errorf("exchange response has an invalid user_id: %w", err)
	}

	return &common.SessionCache{
		Token:        exchanged.Token,
		RefreshToken: exchanged.RefreshToken,
		UserID:       userID,
		Username:     exchanged.Username,
		Role:         exchanged.Role,
		ExpiresAt:    time.Now().Add(viper.GetDuration("jwt.expiry")),
	}, nil
}

// runOIDCLogin performs the browser-based OIDC login flow: starts a
// loopback HTTP listener, opens the system browser to the server's
// /oidc/login with a cli_redirect_uri pointing back at that listener,
// waits for the resulting one-time exchange code, redeems it for a
// session, and caches the session to disk.
func runOIDCLogin(cmd *cobra.Command, serviceContainer container.ServiceContainerInterface) error {
	baseURL := viper.GetString("frontend.public_api_url")
	if baseURL == "" {
		return fmt.Errorf("frontend.public_api_url is not configured — required for OIDC CLI login")
	}

	redirectURI, wait, err := startLoopbackListener()
	if err != nil {
		return err
	}

	loginURL := fmt.Sprintf("%s%s/oidc/login?cli_redirect_uri=%s", baseURL, oidcBasePath, redirectURI)
	if err := common.OpenBrowser(loginURL); err != nil {
		fmt.Printf("Could not open a browser automatically. Open this URL to log in:\n%s\n", loginURL)
	} else {
		fmt.Println("Opening browser to complete OIDC login...")
	}

	code, err := wait(oidcLoginTimeout)
	if err != nil {
		return err
	}

	session, err := exchangeOIDCCode(cmd.Context(), baseURL, code)
	if err != nil {
		return fmt.Errorf("login exchange failed, please try again: %w", err)
	}

	if err := common.SaveSession(session); err != nil {
		serviceContainer.GetLogger().WithError(err).Warn("failed to cache CLI session")
	}

	serviceContainer.GetLogger().LogAuditInfo(session.UserID.String(), "login", "success",
		fmt.Sprintf("user logged in via OIDC: %s", session.Username))
	fmt.Printf("Login successful as %s\n", session.Username)
	return nil
}
