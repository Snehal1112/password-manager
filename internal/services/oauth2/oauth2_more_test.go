package oauth2_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	oauth2svc "rocketvault/internal/services/oauth2"
	"rocketvault/model"
)

// ---------------------------------------------------------------------------
// GetClient
// ---------------------------------------------------------------------------

func TestOAuth2Service_GetClient_Success(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	clientID := uuid.New()
	stored := &model.OAuth2Client{
		ID:           clientID,
		Name:         "my-svc",
		ClientSecret: "hashed-secret-that-should-be-redacted",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}
	repo.On("GetByID", mock.Anything, clientID).Return(stored, nil)

	got, err := svc.GetClient(context.Background(), clientID)
	require.NoError(t, err)
	assert.Equal(t, clientID, got.ID)
	assert.Equal(t, "my-svc", got.Name)
	// The secret hash must be redacted in the response.
	assert.Empty(t, got.ClientSecret, "client secret must never be returned from GetClient")
}

func TestOAuth2Service_GetClient_NotFound(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	clientID := uuid.New()
	repo.On("GetByID", mock.Anything, clientID).Return(nil, errors.New("not found"))

	_, err := svc.GetClient(context.Background(), clientID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client not found")
}

// ---------------------------------------------------------------------------
// ListClients
// ---------------------------------------------------------------------------

func TestOAuth2Service_ListClients_Success(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	clients := []*model.OAuth2Client{
		{ID: uuid.New(), Name: "svc-a", ClientSecret: "hash-a", Enabled: true, CreatedAt: time.Now().UTC()},
		{ID: uuid.New(), Name: "svc-b", ClientSecret: "hash-b", Enabled: true, CreatedAt: time.Now().UTC()},
	}
	repo.On("List", mock.Anything).Return(clients, nil)

	got, err := svc.ListClients(context.Background())
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, c := range got {
		assert.Empty(t, c.ClientSecret, "secrets must be redacted in list response")
	}
}

func TestOAuth2Service_ListClients_Empty(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	repo.On("List", mock.Anything).Return([]*model.OAuth2Client{}, nil)

	got, err := svc.ListClients(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestOAuth2Service_ListClients_RepoError(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	repo.On("List", mock.Anything).Return(nil, errors.New("db error"))

	_, err := svc.ListClients(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list clients")
}

// ---------------------------------------------------------------------------
// DeleteClient
// ---------------------------------------------------------------------------

func TestOAuth2Service_DeleteClient_Success(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	clientID := uuid.New()
	repo.On("Delete", mock.Anything, clientID).Return(nil)

	err := svc.DeleteClient(context.Background(), clientID)
	require.NoError(t, err)
	repo.AssertCalled(t, "Delete", mock.Anything, clientID)
}

func TestOAuth2Service_DeleteClient_RepoError(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	clientID := uuid.New()
	repo.On("Delete", mock.Anything, clientID).Return(errors.New("delete failed"))

	err := svc.DeleteClient(context.Background(), clientID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete client")
}

// ---------------------------------------------------------------------------
// CreateClient — error paths
// ---------------------------------------------------------------------------

func TestOAuth2Service_CreateClient_HashError(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	pw.On("HashPassword", mock.AnythingOfType("string")).Return("", errors.New("bcrypt error"))

	_, _, err := svc.CreateClient(context.Background(), "fail-app", "desc", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to hash client secret")
}

func TestOAuth2Service_CreateClient_RepoError(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	pw.On("HashPassword", mock.AnythingOfType("string")).Return("hashed", nil)
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.OAuth2Client")).Return(errors.New("db write error"))

	_, _, err := svc.CreateClient(context.Background(), "fail-app", "desc", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create client")
}

func TestOAuth2Service_CreateClient_WithExpiry(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	pw.On("HashPassword", mock.AnythingOfType("string")).Return("hashed", nil)
	repo.On("Create", mock.Anything, mock.AnythingOfType("*model.OAuth2Client")).Return(nil)

	expiry := time.Now().UTC().Add(24 * time.Hour)
	client, plain, err := svc.CreateClient(context.Background(), "expiring-app", "desc", &expiry)
	require.NoError(t, err)
	assert.NotEmpty(t, plain)
	require.NotNil(t, client.ExpiresAt)
	assert.WithinDuration(t, expiry, *client.ExpiresAt, time.Second)
}

// ---------------------------------------------------------------------------
// RotateSecret — error paths
// ---------------------------------------------------------------------------

func TestOAuth2Service_RotateSecret_ClientNotFound(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	clientID := uuid.New()
	repo.On("GetByID", mock.Anything, clientID).Return(nil, errors.New("not found"))

	_, err := svc.RotateSecret(context.Background(), clientID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client not found")
}

func TestOAuth2Service_RotateSecret_HashError(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	clientID := uuid.New()
	existing := &model.OAuth2Client{ID: clientID, Name: "svc", Enabled: true, CreatedAt: time.Now().UTC()}
	repo.On("GetByID", mock.Anything, clientID).Return(existing, nil)
	pw.On("HashPassword", mock.AnythingOfType("string")).Return("", errors.New("bcrypt failed"))

	_, err := svc.RotateSecret(context.Background(), clientID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to hash new secret")
}

func TestOAuth2Service_RotateSecret_UpdateError(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwt := &mockJWTService{}
	svc := buildService(repo, pw, jwt)

	clientID := uuid.New()
	existing := &model.OAuth2Client{ID: clientID, Name: "svc", Enabled: true, CreatedAt: time.Now().UTC()}
	repo.On("GetByID", mock.Anything, clientID).Return(existing, nil)
	pw.On("HashPassword", mock.AnythingOfType("string")).Return("new-hash", nil)
	repo.On("Update", mock.Anything, mock.AnythingOfType("*model.OAuth2Client")).Return(errors.New("update failed"))

	_, err := svc.RotateSecret(context.Background(), clientID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update client")
}

// ---------------------------------------------------------------------------
// IssueToken — JWTService error path
// ---------------------------------------------------------------------------

func TestOAuth2Service_IssueToken_JWTError(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwtMock := &mockJWTService{}
	svc := buildService(repo, pw, jwtMock)

	clientID := uuid.New()
	client := &model.OAuth2Client{ID: clientID, Name: "svc", Enabled: true, CreatedAt: time.Now().UTC()}
	repo.On("FindByName", mock.Anything, "svc").Return(client, nil)
	pw.On("ValidatePassword", "secret", client.ClientSecret).Return(nil)
	jwtMock.On("GenerateToken", clientID, "svc", []string{model.RoleServiceAccount}, clientID).Return("", errors.New("jwt failure"))

	_, err := svc.IssueToken(context.Background(), "svc", "secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to issue token")
}

// ---------------------------------------------------------------------------
// NewOAuth2Service — default token expiry when zero is given
// ---------------------------------------------------------------------------

func TestNewOAuth2Service_DefaultExpiry(t *testing.T) {
	repo := &mockOAuth2ClientRepo{}
	pw := &mockPasswordService{}
	jwtMock := &mockJWTService{}

	// TokenExpiry = 0 → should default to 30 minutes.
	svc := oauth2svc.NewOAuth2Service(oauth2svc.OAuth2Config{
		ClientRepo:      repo,
		PasswordService: pw,
		JWTService:      jwtMock,
		TokenExpiry:     0,
	})
	require.NotNil(t, svc)

	clientID := uuid.New()
	client := &model.OAuth2Client{ID: clientID, Name: "svc", Enabled: true, CreatedAt: time.Now().UTC()}
	repo.On("FindByName", mock.Anything, "svc").Return(client, nil)
	pw.On("ValidatePassword", "s", client.ClientSecret).Return(nil)
	jwtMock.On("GenerateToken", clientID, "svc", []string{model.RoleServiceAccount}, clientID).Return("tok", nil)

	resp, err := svc.IssueToken(context.Background(), "svc", "s")
	require.NoError(t, err)
	// Default 30 minutes = 1800 seconds.
	assert.Equal(t, 1800, resp.ExpiresIn)
}
