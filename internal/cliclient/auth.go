package cliclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	authServices "rocketvault/internal/services/auth"
	"rocketvault/model"
)

// LoginRemote authenticates against target's POST /api/v1/users/login and
// returns the same result shape local login produces, so callers don't need
// a separate remote-specific type.
func LoginRemote(ctx context.Context, httpClient *http.Client, server, username, password, totpCode string) (*authServices.AuthenticationResult, error) {
	body, err := json.Marshal(model.LoginRequest{Username: username, Password: password, TOTPCode: totpCode})
	if err != nil {
		return nil, fmt.Errorf("cliclient: encode login request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v1/users/login", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cliclient: build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cliclient: login request to %s: %w", server, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, remoteAuthError("login", server, resp)
	}

	var lr model.LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, fmt.Errorf("cliclient: decode login response: %w", err)
	}
	userID, err := uuid.Parse(lr.UserID)
	if err != nil {
		return nil, fmt.Errorf("cliclient: login response has invalid user_id %q: %w", lr.UserID, err)
	}

	return &authServices.AuthenticationResult{
		Token:        lr.Token,
		RefreshToken: lr.RefreshToken,
		UserID:       userID,
		Username:     lr.Username,
		Roles:        lr.Roles,
	}, nil
}

// RefreshRemote exchanges a refresh token for a new access token against
// target's POST /api/v1/users/refresh. The route is registered on the users
// subrouter (api/users.go), not at the API root.
func RefreshRemote(ctx context.Context, httpClient *http.Client, server, refreshToken string) (*authServices.RefreshTokenResult, error) {
	body, err := json.Marshal(model.RefreshTokenRequest{RefreshToken: refreshToken})
	if err != nil {
		return nil, fmt.Errorf("cliclient: encode refresh request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v1/users/refresh", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cliclient: build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cliclient: refresh request to %s: %w", server, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, remoteAuthError("refresh", server, resp)
	}

	var rr model.RefreshTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return nil, fmt.Errorf("cliclient: decode refresh response: %w", err)
	}
	userID, err := uuid.Parse(rr.UserID)
	if err != nil {
		return nil, fmt.Errorf("cliclient: refresh response has invalid user_id %q: %w", rr.UserID, err)
	}

	return &authServices.RefreshTokenResult{
		Token:        rr.Token,
		RefreshToken: rr.RefreshToken,
		UserID:       userID,
		Username:     rr.Username,
		Roles:        rr.Roles,
		ExpiresAt:    rr.ExpiresAt,
	}, nil
}

func remoteAuthError(op, server string, resp *http.Response) error {
	return fmt.Errorf("cliclient: %s against %s failed: server returned %s", op, server, resp.Status)
}
