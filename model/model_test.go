package model

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// utils.go
// ---------------------------------------------------------------------------

func TestNewId_ReturnsValidUUID(t *testing.T) {
	id := NewId()
	require.NotEmpty(t, id)
	_, err := uuid.Parse(id)
	assert.NoError(t, err, "NewId should return a valid UUID string")
}

func TestNewId_UniqueOnEachCall(t *testing.T) {
	id1 := NewId()
	id2 := NewId()
	assert.NotEqual(t, id1, id2, "successive NewId calls should return different values")
}

func TestGetMillis_ReturnsPositiveNearNow(t *testing.T) {
	before := time.Now().UnixMilli()
	ms := GetMillis()
	after := time.Now().UnixMilli()
	assert.Greater(t, ms, int64(0))
	assert.GreaterOrEqual(t, ms, before)
	assert.LessOrEqual(t, ms, after)
}

// ---------------------------------------------------------------------------
// secret.go – state methods
// ---------------------------------------------------------------------------

func TestSecret_IsExpired_NilExpiresAt(t *testing.T) {
	s := &Secret{ExpiresAt: nil}
	assert.False(t, s.IsExpired(), "nil ExpiresAt should not be expired")
}

func TestSecret_IsExpired_FutureExpiry(t *testing.T) {
	future := time.Now().Add(time.Hour)
	s := &Secret{ExpiresAt: &future}
	assert.False(t, s.IsExpired(), "future ExpiresAt should not be expired")
}

func TestSecret_IsExpired_PastExpiry(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	s := &Secret{ExpiresAt: &past}
	assert.True(t, s.IsExpired(), "past ExpiresAt should be expired")
}

func TestSecret_IsActive_NilNotBefore(t *testing.T) {
	s := &Secret{NotBefore: nil}
	assert.True(t, s.IsActive(), "nil NotBefore should be active")
}

func TestSecret_IsActive_PastNotBefore(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	s := &Secret{NotBefore: &past}
	assert.True(t, s.IsActive(), "past NotBefore should be active")
}

func TestSecret_IsActive_FutureNotBefore(t *testing.T) {
	future := time.Now().Add(time.Hour)
	s := &Secret{NotBefore: &future}
	assert.False(t, s.IsActive(), "future NotBefore should not be active yet")
}

func TestSecret_IsAccessible_EnabledActiveNotExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	s := &Secret{Enabled: true, NotBefore: &past, ExpiresAt: &future}
	assert.True(t, s.IsAccessible())
}

func TestSecret_IsAccessible_Disabled(t *testing.T) {
	s := &Secret{Enabled: false}
	assert.False(t, s.IsAccessible(), "disabled secret should not be accessible")
}

func TestSecret_IsAccessible_Expired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	s := &Secret{Enabled: true, ExpiresAt: &past}
	assert.False(t, s.IsAccessible(), "expired secret should not be accessible")
}

func TestSecret_IsAccessible_NotYetActive(t *testing.T) {
	future := time.Now().Add(time.Hour)
	s := &Secret{Enabled: true, NotBefore: &future}
	assert.False(t, s.IsAccessible(), "secret before NotBefore should not be accessible")
}

func TestSecret_IsAccessible_NilWindowsEnabled(t *testing.T) {
	s := &Secret{Enabled: true}
	assert.True(t, s.IsAccessible(), "enabled secret with no time constraints should be accessible")
}

func TestSecret_DaysUntilExpiration_NilExpiresAt(t *testing.T) {
	s := &Secret{ExpiresAt: nil}
	assert.Equal(t, -1, s.DaysUntilExpiration())
}

func TestSecret_DaysUntilExpiration_AlreadyExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	s := &Secret{ExpiresAt: &past}
	assert.Equal(t, 0, s.DaysUntilExpiration())
}

func TestSecret_DaysUntilExpiration_FutureDate(t *testing.T) {
	future := time.Now().Add(48 * time.Hour)
	s := &Secret{ExpiresAt: &future}
	days := s.DaysUntilExpiration()
	assert.Greater(t, days, 0, "days until expiration should be positive for future date")
}

// ---------------------------------------------------------------------------
// secret.go – FromJson / ToJson
// ---------------------------------------------------------------------------

func TestCreateSecretRequestFromJson(t *testing.T) {
	body := `{"name":"db-pass","value":"s3cr3t","content_type":"text/plain"}`
	req, err := CreateSecretRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "db-pass", req.Name)
	assert.Equal(t, "s3cr3t", req.Value)
	assert.Equal(t, "text/plain", req.ContentType)
}

func TestCreateSecretRequestFromJson_InvalidJSON(t *testing.T) {
	_, err := CreateSecretRequestFromJson(strings.NewReader(`not-json`))
	assert.Error(t, err)
}

func TestUpdateSecretRequestFromJson(t *testing.T) {
	body := `{"name":"new-name","value":"new-val"}`
	req, err := UpdateSecretRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "new-name", req.Name)
	assert.Equal(t, "new-val", req.Value)
}

func TestGenerateSecretRequestFromJson(t *testing.T) {
	body := `{"length":32,"use_symbols":true,"name":"gen-secret"}`
	req, err := GenerateSecretRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, 32, req.Length)
	assert.True(t, req.UseSymbols)
	assert.Equal(t, "gen-secret", req.Name)
}

func TestExportSecretsRequestFromJson(t *testing.T) {
	body := `{"format":"json","encrypt":true,"include_tags":true}`
	req, err := ExportSecretsRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "json", req.Format)
	assert.True(t, req.Encrypt)
	assert.True(t, req.IncludeTags)
}

func TestSecretResponse_ToJson(t *testing.T) {
	r := &SecretResponse{ID: "sec-id", Name: "my-secret", Version: 2, Enabled: true}
	j := r.ToJson()
	assert.Contains(t, j, "sec-id")
	assert.Contains(t, j, "my-secret")
}

func TestListSecretsResponse_ToJson(t *testing.T) {
	r := &ListSecretsResponse{
		Secrets: []SecretResponse{{ID: "s1", Name: "first"}},
		Total:   1,
	}
	j := r.ToJson()
	assert.Contains(t, j, "first")
	assert.Contains(t, j, `"total":1`)
}

func TestExportResponse_ToJson(t *testing.T) {
	r := &ExportResponse{Success: true, Count: 5, Format: "json"}
	j := r.ToJson()
	assert.Contains(t, j, `"success":true`)
	assert.Contains(t, j, `"count":5`)
}

func TestImportResponse_ToJson(t *testing.T) {
	r := &ImportResponse{Success: true, ImportedCount: 3, TotalCount: 3, Format: "json"}
	j := r.ToJson()
	assert.Contains(t, j, `"success":true`)
	assert.Contains(t, j, `"imported_count":3`)
}

// ---------------------------------------------------------------------------
// key.go – IsAccessible
// ---------------------------------------------------------------------------

func TestKey_IsAccessible_EnabledNoConstraints(t *testing.T) {
	k := &Key{Enabled: true}
	assert.True(t, k.IsAccessible())
}

func TestKey_IsAccessible_Disabled(t *testing.T) {
	k := &Key{Enabled: false}
	assert.False(t, k.IsAccessible())
}

func TestKey_IsAccessible_BeforeNotBefore(t *testing.T) {
	future := time.Now().Add(time.Hour)
	k := &Key{Enabled: true, NotBefore: &future}
	assert.False(t, k.IsAccessible(), "key before NotBefore should not be accessible")
}

func TestKey_IsAccessible_AfterExpiresAt(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	k := &Key{Enabled: true, ExpiresAt: &past}
	assert.False(t, k.IsAccessible(), "expired key should not be accessible")
}

func TestKey_IsAccessible_WithinValidWindow(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	k := &Key{Enabled: true, NotBefore: &past, ExpiresAt: &future}
	assert.True(t, k.IsAccessible())
}

// ---------------------------------------------------------------------------
// key.go – FromJson / ToJson
// ---------------------------------------------------------------------------

func TestCreateKeyRequestFromJson(t *testing.T) {
	body := `{"name":"rsa-key","type":"RSA","bits":2048}`
	req, err := CreateKeyRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "rsa-key", req.Name)
	assert.Equal(t, "RSA", req.Type)
	assert.Equal(t, 2048, req.Bits)
}

func TestCreateKeyRequestFromJson_InvalidJSON(t *testing.T) {
	_, err := CreateKeyRequestFromJson(strings.NewReader(`{bad}`))
	assert.Error(t, err)
}

func TestUpdateKeyRequestFromJson(t *testing.T) {
	body := `{"revoked":true}`
	req, err := UpdateKeyRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	require.NotNil(t, req.Revoked)
	assert.True(t, *req.Revoked)
}

func TestKeyResponse_ToJson(t *testing.T) {
	id := uuid.New()
	r := &KeyResponse{ID: id, Name: "my-key", Type: "RSA", Enabled: true}
	j := r.ToJson()
	assert.Contains(t, j, "my-key")
	assert.Contains(t, j, "RSA")
}

func TestKeyListResponse_ToJson(t *testing.T) {
	r := &KeyListResponse{
		Keys: []KeyResponse{{Name: "k1", Type: "ECDSA"}},
	}
	j := r.ToJson()
	assert.Contains(t, j, "k1")
	assert.Contains(t, j, "ECDSA")
}

func TestWrapKeyRequestFromJson(t *testing.T) {
	body := `{"plaintext_key":"abc123","algorithm":"RSA-OAEP"}`
	req, err := WrapKeyRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "abc123", req.PlaintextKey)
	assert.Equal(t, "RSA-OAEP", req.Algorithm)
}

func TestWrapKeyResponse_ToJson(t *testing.T) {
	r := &WrapKeyResponse{WrappedKey: "enc-data", Algorithm: "RSA-OAEP"}
	j := r.ToJson()
	assert.Contains(t, j, "enc-data")
	assert.Contains(t, j, "RSA-OAEP")
}

func TestUnwrapKeyRequestFromJson(t *testing.T) {
	body := `{"wrapped_key":"enc-data","algorithm":"RSA-OAEP"}`
	req, err := UnwrapKeyRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "enc-data", req.WrappedKey)
	assert.Equal(t, "RSA-OAEP", req.Algorithm)
}

func TestUnwrapKeyResponse_ToJson(t *testing.T) {
	r := &UnwrapKeyResponse{PlaintextKey: "plain-key", Algorithm: "RSA-OAEP"}
	j := r.ToJson()
	assert.Contains(t, j, "plain-key")
}

// ---------------------------------------------------------------------------
// certificate.go – IsAccessible
// ---------------------------------------------------------------------------

func TestCertificate_IsAccessible_EnabledNoConstraints(t *testing.T) {
	c := &Certificate{Enabled: true}
	assert.True(t, c.IsAccessible())
}

func TestCertificate_IsAccessible_Disabled(t *testing.T) {
	c := &Certificate{Enabled: false}
	assert.False(t, c.IsAccessible())
}

func TestCertificate_IsAccessible_BeforeNotBefore(t *testing.T) {
	future := time.Now().Add(time.Hour)
	c := &Certificate{Enabled: true, NotBefore: &future}
	assert.False(t, c.IsAccessible())
}

func TestCertificate_IsAccessible_AfterExpiresAt(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	c := &Certificate{Enabled: true, ExpiresAt: &past}
	assert.False(t, c.IsAccessible())
}

func TestCertificate_IsAccessible_WithinValidWindow(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	c := &Certificate{Enabled: true, NotBefore: &past, ExpiresAt: &future}
	assert.True(t, c.IsAccessible())
}

// ---------------------------------------------------------------------------
// certificate.go – FromJson / ToJson
// ---------------------------------------------------------------------------

func TestCreateCertificateRequestFromJson(t *testing.T) {
	body := `{"name":"tls-cert","key_id":"key-123","validity_days":365,"auto_renew":true}`
	req, err := CreateCertificateRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "tls-cert", req.Name)
	assert.Equal(t, "key-123", req.KeyID)
	assert.Equal(t, 365, req.ValidityDays)
	assert.True(t, req.AutoRenew)
}

func TestCreateCertificateRequestFromJson_InvalidJSON(t *testing.T) {
	_, err := CreateCertificateRequestFromJson(strings.NewReader(`bad`))
	assert.Error(t, err)
}

func TestUpdateCertificateRequestFromJson(t *testing.T) {
	name := "updated-cert"
	autoRenew := false
	_ = name
	_ = autoRenew
	body := `{"name":"updated-cert","auto_renew":false}`
	req, err := UpdateCertificateRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	require.NotNil(t, req.Name)
	assert.Equal(t, "updated-cert", *req.Name)
	require.NotNil(t, req.AutoRenew)
	assert.False(t, *req.AutoRenew)
}

func TestCertificateResponse_ToJson(t *testing.T) {
	id := uuid.New()
	uid := uuid.New()
	r := &CertificateResponse{
		ID:     id,
		Name:   "my-cert",
		UserID: uid,
	}
	j := r.ToJson()
	assert.Contains(t, j, "my-cert")
	assert.Contains(t, j, id.String())
}

func TestCertificateListResponse_ToJson(t *testing.T) {
	r := &CertificateListResponse{
		Certificates: []CertificateResponse{{Name: "cert1"}},
	}
	j := r.ToJson()
	assert.Contains(t, j, "cert1")
}

// ---------------------------------------------------------------------------
// certificate_policy.go
// ---------------------------------------------------------------------------

func TestUpsertCertificatePolicyRequestFromJson(t *testing.T) {
	body := `{"validity_months":12,"key_type":"RSA","key_size":2048,"subject":"CN=example.com","auto_renew":true,"days_before_expiry":30}`
	req, err := UpsertCertificatePolicyRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, 12, req.ValidityMonths)
	assert.Equal(t, "RSA", req.KeyType)
	assert.Equal(t, 2048, req.KeySize)
	assert.Equal(t, "CN=example.com", req.Subject)
	assert.True(t, req.AutoRenew)
	assert.Equal(t, 30, req.DaysBeforeExpiry)
}

func TestUpsertCertificatePolicyRequestFromJson_InvalidJSON(t *testing.T) {
	_, err := UpsertCertificatePolicyRequestFromJson(strings.NewReader(`{bad`))
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// access_policy.go
// ---------------------------------------------------------------------------

func TestCreateAccessPolicyRequestFromJson(t *testing.T) {
	body := `{"principal_id":"user-abc","principal_type":"user","resource_type":"secrets","operation":"get","effect":"allow"}`
	req, err := CreateAccessPolicyRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "user-abc", req.PrincipalID)
	assert.Equal(t, "user", req.PrincipalType)
	assert.Equal(t, "secrets", req.ResourceType)
	assert.Equal(t, "get", req.Operation)
	assert.Equal(t, "allow", req.Effect)
}

func TestCreateAccessPolicyRequestFromJson_InvalidJSON(t *testing.T) {
	_, err := CreateAccessPolicyRequestFromJson(strings.NewReader(`not-json`))
	assert.Error(t, err)
}

func TestAccessPolicyResponse_ToJson(t *testing.T) {
	r := &AccessPolicyResponse{
		ID:            "ap-001",
		PrincipalID:   "user-abc",
		PrincipalType: "user",
		ResourceType:  "secrets",
		Operation:     "get",
		Effect:        "allow",
		CreatedAt:     time.Now().Format(time.RFC3339),
	}
	j := r.ToJson()
	assert.Contains(t, j, "ap-001")
	assert.Contains(t, j, "user-abc")
	assert.Contains(t, j, "allow")
}

func TestListAccessPoliciesResponse_ToJson(t *testing.T) {
	r := &ListAccessPoliciesResponse{
		AccessPolicies: []AccessPolicyResponse{
			{ID: "ap-1", Effect: "deny"},
		},
		Total: 1,
	}
	j := r.ToJson()
	assert.Contains(t, j, "ap-1")
	assert.Contains(t, j, "deny")
	assert.Contains(t, j, `"total":1`)
}

// ---------------------------------------------------------------------------
// oauth2_client.go
// ---------------------------------------------------------------------------

func TestCreateOAuth2ClientRequestFromJson(t *testing.T) {
	body := `{"name":"ci-bot","description":"CI pipeline client"}`
	req, err := CreateOAuth2ClientRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "ci-bot", req.Name)
	assert.Equal(t, "CI pipeline client", req.Description)
}

func TestCreateOAuth2ClientRequestFromJson_InvalidJSON(t *testing.T) {
	_, err := CreateOAuth2ClientRequestFromJson(strings.NewReader(`bad`))
	assert.Error(t, err)
}

func TestOAuth2ClientResponse_ToJson(t *testing.T) {
	r := &OAuth2ClientResponse{
		ID:          "client-123",
		Name:        "ci-bot",
		Description: "CI pipeline",
		Enabled:     true,
		CreatedAt:   time.Now(),
	}
	j := r.ToJson()
	assert.Contains(t, j, "ci-bot")
	assert.Contains(t, j, "client-123")
}

func TestListOAuth2ClientsResponse_ToJson(t *testing.T) {
	r := &ListOAuth2ClientsResponse{
		Clients: []OAuth2ClientResponse{{ID: "c1", Name: "bot"}},
		Total:   1,
	}
	j := r.ToJson()
	assert.Contains(t, j, "bot")
	assert.Contains(t, j, `"total":1`)
}

// ---------------------------------------------------------------------------
// user.go
// ---------------------------------------------------------------------------

func TestCreateUserRequestFromJson(t *testing.T) {
	body := `{"username":"alice","password":"hunter2","role":"user"}`
	req, err := CreateUserRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "alice", req.Username)
	assert.Equal(t, "hunter2", req.Password)
	assert.Equal(t, "user", req.Role)
}

func TestCreateUserRequestFromJson_InvalidJSON(t *testing.T) {
	_, err := CreateUserRequestFromJson(strings.NewReader(`bad`))
	assert.Error(t, err)
}

func TestUpdateUserRequestFromJson(t *testing.T) {
	body := `{"username":"bob","role":"admin"}`
	req, err := UpdateUserRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "bob", req.Username)
	assert.Equal(t, "admin", req.Role)
}

func TestUserResponse_ToJson(t *testing.T) {
	r := &UserResponse{ID: "u-abc", Username: "alice", Role: "user"}
	j := r.ToJson()
	assert.Contains(t, j, "u-abc")
	assert.Contains(t, j, "alice")
	assert.Contains(t, j, "user")
}

func TestListUsersResponse_ToJson(t *testing.T) {
	r := &ListUsersResponse{
		Users: []UserResponse{{ID: "u1", Username: "bob"}},
		Total: 1,
	}
	j := r.ToJson()
	assert.Contains(t, j, "bob")
	assert.Contains(t, j, `"total":1`)
}

func TestLoginRequestFromJson(t *testing.T) {
	body := `{"username":"alice","password":"pw","totp_code":"123456"}`
	req, err := LoginRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "alice", req.Username)
	assert.Equal(t, "pw", req.Password)
	assert.Equal(t, "123456", req.TOTPCode)
}

func TestLoginRequestFromJson_InvalidJSON(t *testing.T) {
	_, err := LoginRequestFromJson(strings.NewReader(`bad`))
	assert.Error(t, err)
}

func TestLoginResponse_ToJson(t *testing.T) {
	r := &LoginResponse{
		Token:        "jwt-token",
		RefreshToken: "refresh-token",
		UserID:       "u-123",
		Username:     "alice",
		Role:         "admin",
	}
	j := r.ToJson()
	assert.Contains(t, j, "jwt-token")
	assert.Contains(t, j, "alice")
}

func TestRefreshTokenRequestFromJson(t *testing.T) {
	body := `{"refresh_token":"refresh-abc"}`
	req, err := RefreshTokenRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "refresh-abc", req.RefreshToken)
}

func TestRefreshTokenRequestFromJson_InvalidJSON(t *testing.T) {
	_, err := RefreshTokenRequestFromJson(strings.NewReader(`{bad`))
	assert.Error(t, err)
}

func TestRefreshTokenResponse_ToJson(t *testing.T) {
	r := &RefreshTokenResponse{
		Token:        "new-jwt",
		RefreshToken: "new-refresh",
		UserID:       "u-456",
		Username:     "bob",
		Role:         "user",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	j := r.ToJson()
	assert.Contains(t, j, "new-jwt")
	assert.Contains(t, j, "bob")
}

// ---------------------------------------------------------------------------
// vault.go – ToResponse / FromJson / ToJson
// ---------------------------------------------------------------------------

func TestVault_ToResponse_NilOptionalFields(t *testing.T) {
	vaultID := uuid.New()
	createdBy := uuid.New()
	now := time.Now()

	v := &Vault{
		ID:            vaultID,
		Name:          "test-vault",
		Enabled:       true,
		RetentionDays: 90,
		CreatedBy:     createdBy,
		CreatedAt:     now,
		// DeletedAt, ScheduledPurgeAt, Tags, UpdatedAt, UpdatedBy all nil/empty
	}

	resp := v.ToResponse()
	assert.Equal(t, vaultID.String(), resp.ID)
	assert.Equal(t, "test-vault", resp.Name)
	assert.True(t, resp.Enabled)
	assert.Equal(t, 90, resp.RetentionDays)
	assert.Equal(t, createdBy.String(), resp.CreatedBy)
	assert.Equal(t, now.Format(time.RFC3339), resp.CreatedAt)
	assert.Empty(t, resp.DeletedAt)
	assert.Empty(t, resp.ScheduledPurgeAt)
	assert.Nil(t, resp.Tags)
	assert.Empty(t, resp.UpdatedAt)
	assert.Empty(t, resp.UpdatedBy)
}

func TestVault_ToResponse_AllOptionalFieldsPopulated(t *testing.T) {
	vaultID := uuid.New()
	createdBy := uuid.New()
	updatedBy := uuid.New()
	now := time.Now()
	deletedAt := now.Add(-24 * time.Hour)
	scheduledPurge := now.Add(7 * 24 * time.Hour)
	updatedAt := now.Add(-time.Hour)

	v := &Vault{
		ID:               vaultID,
		Name:             "full-vault",
		Enabled:          false,
		PurgeProtection:  true,
		RetentionDays:    30,
		CreatedBy:        createdBy,
		CreatedAt:        now,
		DeletedAt:        &deletedAt,
		ScheduledPurgeAt: &scheduledPurge,
		Tags:             map[string]string{"env": "prod", "team": "ops"},
		UpdatedAt:        &updatedAt,
		UpdatedBy:        &updatedBy,
	}

	resp := v.ToResponse()
	assert.Equal(t, vaultID.String(), resp.ID)
	assert.NotEmpty(t, resp.DeletedAt)
	assert.Equal(t, deletedAt.Format(time.RFC3339), resp.DeletedAt)
	assert.NotEmpty(t, resp.ScheduledPurgeAt)
	assert.Equal(t, "prod", resp.Tags["env"])
	assert.NotEmpty(t, resp.UpdatedAt)
	assert.Equal(t, updatedBy.String(), resp.UpdatedBy)
}

func TestVault_ToResponse_EmptyTagsNotIncluded(t *testing.T) {
	v := &Vault{
		ID:        uuid.New(),
		CreatedBy: uuid.New(),
		CreatedAt: time.Now(),
		Tags:      map[string]string{}, // empty map — should be omitted
	}
	resp := v.ToResponse()
	assert.Nil(t, resp.Tags)
}

func TestCreateVaultRequestFromJson(t *testing.T) {
	enabled := true
	_ = enabled
	body := `{"name":"prod-vault","enabled":true,"retention_days":90}`
	req, err := CreateVaultRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "prod-vault", req.Name)
	require.NotNil(t, req.Enabled)
	assert.True(t, *req.Enabled)
	require.NotNil(t, req.RetentionDays)
	assert.Equal(t, 90, *req.RetentionDays)
}

func TestCreateVaultRequestFromJson_InvalidJSON(t *testing.T) {
	_, err := CreateVaultRequestFromJson(strings.NewReader(`bad`))
	assert.Error(t, err)
}

func TestUpdateVaultRequestFromJson(t *testing.T) {
	body := `{"enabled":false,"retention_days":7}`
	req, err := UpdateVaultRequestFromJson(strings.NewReader(body))
	require.NoError(t, err)
	require.NotNil(t, req.Enabled)
	assert.False(t, *req.Enabled)
	require.NotNil(t, req.RetentionDays)
	assert.Equal(t, 7, *req.RetentionDays)
}

func TestVaultResponse_ToJson(t *testing.T) {
	r := &VaultResponse{
		ID:      "vault-id",
		Name:    "my-vault",
		Enabled: true,
	}
	j := r.ToJson()
	assert.Contains(t, j, "vault-id")
	assert.Contains(t, j, "my-vault")
}

func TestListVaultsResponse_ToJson(t *testing.T) {
	r := &ListVaultsResponse{
		Vaults: []VaultResponse{{ID: "v1", Name: "vault-one"}},
		Total:  1,
	}
	j := r.ToJson()
	assert.Contains(t, j, "vault-one")
	assert.Contains(t, j, `"total":1`)
}

// ---------------------------------------------------------------------------
// session.go
// ---------------------------------------------------------------------------

func TestDefaultSessionConfig_ReasonableValues(t *testing.T) {
	cfg := DefaultSessionConfig()
	assert.Greater(t, cfg.AccessTokenExpiry, time.Duration(0), "AccessTokenExpiry should be positive")
	assert.Greater(t, cfg.RefreshTokenExpiry, time.Duration(0), "RefreshTokenExpiry should be positive")
	assert.Greater(t, cfg.MaxSessions, 0, "MaxSessions should be positive")
	assert.True(t, cfg.EnableRotation, "EnableRotation should default to true")
	// Verify specific defaults documented in the codebase
	assert.Equal(t, 30*time.Minute, cfg.AccessTokenExpiry)
	assert.Equal(t, 7*24*time.Hour, cfg.RefreshTokenExpiry)
	assert.Equal(t, 5, cfg.MaxSessions)
}

func TestSessionResponse_ToJson(t *testing.T) {
	now := time.Now()
	r := &SessionResponse{
		ID:         "sess-001",
		DeviceInfo: "MacBook",
		IPAddress:  "127.0.0.1",
		ExpiresAt:  now.Add(time.Hour),
		LastUsedAt: now,
		CreatedAt:  now,
		Revoked:    false,
	}
	j := r.ToJson()
	assert.Contains(t, j, "sess-001")
	assert.Contains(t, j, "MacBook")
	assert.Contains(t, j, "127.0.0.1")
}

func TestListSessionsResponse_ToJson(t *testing.T) {
	now := time.Now()
	r := &ListSessionsResponse{
		Sessions: []SessionResponse{
			{ID: "s1", IPAddress: "10.0.0.1", ExpiresAt: now, LastUsedAt: now, CreatedAt: now},
		},
		Total: 1,
	}
	j := r.ToJson()
	assert.Contains(t, j, "s1")
	assert.Contains(t, j, `"total":1`)
}
