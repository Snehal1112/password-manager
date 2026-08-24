package cliclient

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestListSecretsRemote_LegacyPath_NoVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)
		assert.Equal(t, "Bearer tok-123", r.Header.Get("Authorization"))
		assert.Empty(t, r.URL.Query().Get("tags"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.ListSecretsResponse{
			Secrets: []model.SecretResponse{
				{ID: "id-1", Name: "api-key", Version: 1, Enabled: true, CreatedAt: "2026-01-01T00:00:00Z"},
			},
			Total: 1,
		})
	}))
	defer srv.Close()

	secrets, err := ListSecretsRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "", nil)
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	assert.Equal(t, "api-key", secrets[0].Name)
	assert.True(t, secrets[0].Enabled)
}

func TestListSecretsRemote_VaultScopedPath_WithTags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/vaults/payments/secrets", r.URL.Path)
		assert.Equal(t, "prod,db", r.URL.Query().Get("tags"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.ListSecretsResponse{Secrets: []model.SecretResponse{}, Total: 0})
	}))
	defer srv.Close()

	secrets, err := ListSecretsRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "payments", []string{"prod", "db"})
	require.NoError(t, err)
	assert.Empty(t, secrets)
}

func TestListSecretsRemote_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := ListSecretsRemote(context.Background(), srv.Client(), "expired-tok", srv.URL, "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestListSecretsRemote_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := ListSecretsRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestGetSecretRemote_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/vaults/payments/secrets/id-1", r.URL.Path)
		assert.Equal(t, "Bearer tok-123", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.SecretResponse{ID: "id-1", Name: "api-key", Value: "s3cr3t", Version: 2})
	}))
	defer srv.Close()

	secret, err := GetSecretRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "payments", "id-1")
	require.NoError(t, err)
	assert.Equal(t, "api-key", secret.Name)
	assert.Equal(t, "s3cr3t", secret.Value)
}

func TestGetSecretRemote_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := GetSecretRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "", "missing-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestCreateSecretRemote_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		var req model.CreateSecretRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "db-pass", req.Name)
		assert.Equal(t, "hunter2", req.Value)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(model.SecretResponse{ID: "id-2", Name: "db-pass", Version: 1})
	}))
	defer srv.Close()

	secret, err := CreateSecretRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "",
		model.CreateSecretRequest{Name: "db-pass", Value: "hunter2"})
	require.NoError(t, err)
	assert.Equal(t, "id-2", secret.ID)
}

func TestUpdateSecretRemote_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/id-1", r.URL.Path)
		assert.Equal(t, http.MethodPut, r.Method)
		var req model.UpdateSecretRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "new-value", req.Value)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.SecretResponse{ID: "id-1", Version: 2})
	}))
	defer srv.Close()

	secret, err := UpdateSecretRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "", "id-1",
		model.UpdateSecretRequest{Value: "new-value"})
	require.NoError(t, err)
	assert.Equal(t, 2, secret.Version)
}

func TestDeleteSecretRemote_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/id-1", r.URL.Path)
		assert.Equal(t, http.MethodDelete, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := DeleteSecretRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "", "id-1")
	require.NoError(t, err)
}

func TestDeleteSecretRemote_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := DeleteSecretRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "", "id-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestExportSecretsRemote_Success(t *testing.T) {
	fileBytes := []byte(`{"secrets":[]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/export", r.URL.Path)
		var req model.ExportSecretsRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "json", req.Format)
		assert.True(t, req.Encrypt)
		assert.Equal(t, "s3cr3t-pass", req.Passphrase)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fileBytes)
	}))
	defer srv.Close()

	data, err := ExportSecretsRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "",
		model.ExportSecretsRequest{Format: "json", Encrypt: true, Passphrase: "s3cr3t-pass"})
	require.NoError(t, err)
	assert.Equal(t, fileBytes, data)
}

func TestExportSecretsRemote_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := ExportSecretsRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "", model.ExportSecretsRequest{Format: "json"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestImportSecretsRemote_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/vaults/payments/secrets/import", r.URL.Path)
		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		require.NoError(t, err)
		require.Equal(t, "multipart/form-data", mediaType)

		mr := multipart.NewReader(r.Body, params["boundary"])
		fields := map[string]string{}
		var fileContent []byte
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			if part.FormName() == "file" {
				fileContent, _ = io.ReadAll(part)
				continue
			}
			val, _ := io.ReadAll(part)
			fields[part.FormName()] = string(val)
		}
		assert.Equal(t, []byte(`{"secrets":[]}`), fileContent)
		assert.Equal(t, "json", fields["format"])
		assert.Equal(t, "true", fields["overwrite"])
		assert.Equal(t, "s3cr3t-pass", fields["passphrase"])

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.ImportResponse{Success: true, ImportedCount: 3, TotalCount: 3})
	}))
	defer srv.Close()

	result, err := ImportSecretsRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "payments",
		[]byte(`{"secrets":[]}`), "json", true, "s3cr3t-pass")
	require.NoError(t, err)
	assert.Equal(t, 3, result.ImportedCount)
}

func TestImportSecretsRemote_NoPassphrase_OmitsField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		require.NoError(t, err)
		require.Equal(t, "multipart/form-data", mediaType)

		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			assert.NotEqual(t, "passphrase", part.FormName())
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.ImportResponse{Success: true})
	}))
	defer srv.Close()

	_, err := ImportSecretsRemote(context.Background(), srv.Client(), "tok-123", srv.URL, "", []byte("plain"), "json", false, "")
	require.NoError(t, err)
}
