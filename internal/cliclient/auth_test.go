package cliclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestLoginRemote_Success(t *testing.T) {
	userID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/users/login", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		var req model.LoginRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "admin", req.Username)
		assert.Equal(t, "pass123", req.Password)
		assert.Equal(t, "123456", req.TOTPCode)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.LoginResponse{
			Token:        "access-tok",
			RefreshToken: "refresh-tok",
			UserID:       userID.String(),
			Username:     "admin",
			Roles:        []string{"admin"},
		})
	}))
	defer srv.Close()

	result, err := LoginRemote(context.Background(), srv.Client(), srv.URL, "admin", "pass123", "123456")
	require.NoError(t, err)
	assert.Equal(t, "access-tok", result.Token)
	assert.Equal(t, "refresh-tok", result.RefreshToken)
	assert.Equal(t, userID, result.UserID)
	assert.Equal(t, "admin", result.Username)
	assert.Equal(t, []string{"admin"}, result.Roles)
}

func TestLoginRemote_ServerRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := LoginRemote(context.Background(), srv.Client(), srv.URL, "admin", "wrong", "000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "login")
	assert.Contains(t, err.Error(), "401")
}

func TestRefreshRemote_Success(t *testing.T) {
	userID := uuid.New()
	expiresAt := time.Now().Add(15 * time.Minute).Truncate(time.Second).UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/users/refresh", r.URL.Path)
		var req model.RefreshTokenRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "refresh-tok", req.RefreshToken)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.RefreshTokenResponse{
			Token:        "new-access-tok",
			RefreshToken: "new-refresh-tok",
			UserID:       userID.String(),
			Username:     "admin",
			Roles:        []string{"admin"},
			ExpiresAt:    expiresAt,
		})
	}))
	defer srv.Close()

	result, err := RefreshRemote(context.Background(), srv.Client(), srv.URL, "refresh-tok")
	require.NoError(t, err)
	assert.Equal(t, "new-access-tok", result.Token)
	assert.Equal(t, "new-refresh-tok", result.RefreshToken)
	assert.Equal(t, userID, result.UserID)
	assert.True(t, expiresAt.Equal(result.ExpiresAt))
}

func TestRefreshRemote_ServerRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := RefreshRemote(context.Background(), srv.Client(), srv.URL, "expired-refresh-tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh")
}
