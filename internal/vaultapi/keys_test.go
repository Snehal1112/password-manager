package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const rsaKeyID = "4a1504e0-4f89-11d3-9a0c-0305e82c3401"

func TestListKeys_UsesVaultScopedRouteAndKeysWrapper(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[
			{"id":"` + rsaKeyID + `","name":"signing-key","type":"RSA","enabled":true,
			 "revoked":false,"tags":["prod"],"created_at":"2026-08-01T00:00:00Z"}
		]}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListKeys(context.Background(), "prod", 50)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/keys", gotPath)
	require.False(t, truncated)
	require.Len(t, got, 1)
	require.Equal(t, "signing-key", got[0].Name)
	require.Equal(t, "RSA", got[0].Type)
	require.Equal(t, uuid.MustParse(rsaKeyID), got[0].ID)
	require.True(t, got[0].Enabled)
	require.False(t, got[0].Revoked)
}

func TestListKeys_TruncatesAtLimitAndReportsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[
			{"id":"` + rsaKeyID + `","name":"a","type":"RSA"},
			{"id":"` + dbSecretID + `","name":"b","type":"EC"},
			{"id":"` + apiSecretID + `","name":"c","type":"RSA"}
		]}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListKeys(context.Background(), "prod", 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.True(t, truncated)
}

func TestListKeys_RequiresVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, _, err := newClientForTest(t, srv).ListKeys(context.Background(), "", 50)
	require.ErrorContains(t, err, "vault is required")
}

func TestGetKey_ReturnsRSAPublicComponents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + rsaKeyID + `","name":"signing-key","type":"RSA",
			"bits":2048,"enabled":true,"n":"sXchDaQ","e":"AQAB","created_at":"2026-08-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKey(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Equal(t, "signing-key", got.Name)
	require.Equal(t, 2048, got.Bits)
	require.Equal(t, "sXchDaQ", got.PublicJWK.N)
	require.Equal(t, "AQAB", got.PublicJWK.E)
	require.False(t, got.PublicJWK.IsEmpty())
}

func TestGetKey_ReturnsECPublicComponents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + rsaKeyID + `","name":"ec-key","type":"EC",
			"curve":"P-256","x":"f83OJ3D2","y":"x_FEzRu9","enabled":true}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKey(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Equal(t, "P-256", got.Curve)
	require.Equal(t, "f83OJ3D2", got.PublicJWK.X)
	require.Equal(t, "x_FEzRu9", got.PublicJWK.Y)
	require.False(t, got.PublicJWK.IsEmpty())
}

func TestGetKey_HSMKeyWithNoComponentsIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// An HSM-backed key's material never left the token, so the JWK
		// components are omitted. That is expected, not a failure.
		_, _ = w.Write([]byte(`{"id":"` + rsaKeyID + `","name":"hsm-key","type":"RSA","enabled":true}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKey(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err, "an HSM key without public components must not be an error")
	require.True(t, got.PublicJWK.IsEmpty())
	require.Equal(t, "hsm-key", got.Name)
}

func TestGetKey_ResolvesNameThenFetchesByID(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/vaults/prod/keys" {
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"` + rsaKeyID + `","name":"signing-key","type":"RSA"}`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetKey(context.Background(), "prod", "signing-key")
	require.NoError(t, err)
	require.Equal(t, []string{"/api/v1/vaults/prod/keys", "/api/v1/vaults/prod/keys/" + rsaKeyID}, paths)
}

func TestGetKey_CarriesNoPrivateMaterialField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Even if a server were to send private material, it must not surface.
		_, _ = w.Write([]byte(`{"id":"` + rsaKeyID + `","name":"signing-key","type":"RSA",
			"value":"-----BEGIN PRIVATE KEY-----LEAKED-----END PRIVATE KEY-----"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKey(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED",
		"Key has no private-material field, so a stray server value is dropped")
	require.NotContains(t, string(encoded), "PRIVATE KEY")
}

func TestGetKeyVersions_DecodesFlatEmbeddedShape(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		// KeyVersionResponse embeds model.KeyVersion, so the JSON is flat.
		_, _ = w.Write([]byte(`[
			{"key_id":"` + rsaKeyID + `","version":1,"created_at":"2026-06-01T00:00:00Z","n":"old-n","e":"AQAB"},
			{"key_id":"` + rsaKeyID + `","version":2,"created_at":"2026-07-01T00:00:00Z","n":"new-n","e":"AQAB"}
		]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyVersions(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/versions", gotPath)
	require.Len(t, got, 2)
	require.Equal(t, 1, got[0].Version)
	require.Equal(t, "old-n", got[0].PublicJWK.N)
	require.Equal(t, 2, got[1].Version)
	require.Equal(t, "new-n", got[1].PublicJWK.N)
	require.Equal(t, uuid.MustParse(rsaKeyID), got[0].KeyID)
}

func TestGetKeyVersions_HSMVersionsHaveEmptyComponents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"key_id":"` + rsaKeyID + `","version":1,"created_at":"2026-06-01T00:00:00Z"}]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyVersions(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, got[0].PublicJWK.IsEmpty())
}

func TestGetKeyVersions_ResolvesNameFirst(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/vaults/prod/keys" {
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}
		_, _ = w.Write([]byte(`[{"key_id":"` + rsaKeyID + `","version":1}]`))
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetKeyVersions(context.Background(), "prod", "signing-key")
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/versions", paths[1])
}

func TestGetKeyVersions_EmptyHistoryIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyVersions(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestGetKeyVersions_CarriesNoPrivateMaterialField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"key_id":"` + rsaKeyID + `","version":1,"value":"LEAKED-PRIVATE"}]`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyVersions(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED-PRIVATE")
}

func TestGetKeyRotationPolicy_ReturnsThePolicy(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + dbSecretID + `","key_id":"` + rsaKeyID + `",
			"user_id":"` + apiSecretID + `","vault_id":"` + signKeyID + `",
			"rotate_after_days":90,"notify_before_expiry_days":14,"expiry_days":365,
			"enabled":true,"next_rotation_at":"2026-11-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyRotationPolicy(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/rotationpolicy", gotPath)
	require.Equal(t, 90, got.RotateAfterDays)
	require.Equal(t, 14, got.NotifyBeforeExpiryDays)
	require.Equal(t, 365, got.ExpiryDays)
	require.True(t, got.Enabled)
	require.Equal(t, uuid.MustParse(rsaKeyID), got.KeyID)
}

func TestGetKeyRotationPolicy_AbsentPolicyIsNilNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyRotationPolicy(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err, "most keys have no rotation policy, which is an ordinary state")
	require.Nil(t, got)
}

func TestGetKeyRotationPolicy_ForbiddenIsStillAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetKeyRotationPolicy(context.Background(), "prod", rsaKeyID)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr, "absent and denied must not be conflated")
	require.Equal(t, KindForbidden, apiErr.Kind)
}

func TestGetKeyRotationPolicy_OmitsInternalIdentifiers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + dbSecretID + `","key_id":"` + rsaKeyID + `",
			"user_id":"` + apiSecretID + `","vault_id":"` + signKeyID + `","rotate_after_days":90}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyRotationPolicy(context.Background(), "prod", rsaKeyID)
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), apiSecretID, "user_id has no meaning to an agent")
	require.NotContains(t, string(encoded), signKeyID, "vault_id has no meaning to an agent")
}

func TestGetKeyRotationPolicy_ResolvesNameFirst(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/vaults/prod/keys" {
			_, _ = w.Write([]byte(`{"keys":[{"id":"` + rsaKeyID + `","name":"signing-key"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"key_id":"` + rsaKeyID + `","rotate_after_days":30}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetKeyRotationPolicy(context.Background(), "prod", "signing-key")
	require.NoError(t, err)
	require.Equal(t, 30, got.RotateAfterDays)
	require.Equal(t, "/api/v1/vaults/prod/keys/"+rsaKeyID+"/rotationpolicy", paths[1])
}
