// Package api — unit test for updating a vault with tags via the handler.
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestUpdateVault_WithTags creates a vault, then patches it with tags and
// confirms the response carries them back. It reuses the shared vault API test
// harness so the request flows through the real handler with a user_id claim.
func TestUpdateVault_WithTags(t *testing.T) {
	api, _ := newVaultTestAPI()

	// Create a vault named "tagged".
	createBody, _ := json.Marshal(map[string]any{"name": "tagged"})
	w := doVaultRequest(api, http.MethodPost, "/api/v1/vaults", createBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("create vault: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Patch the vault with tags.
	patchBody, _ := json.Marshal(map[string]any{"tags": map[string]string{"env": "prod"}})
	w = doVaultRequest(api, http.MethodPatch, "/api/v1/vaults/tagged", patchBody)
	if w.Code != http.StatusOK {
		t.Fatalf("update vault: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, `"env":"prod"`) {
		t.Fatalf("expected response body to contain tags, got: %s", body)
	}
	if !strings.Contains(body, `"updated_by"`) || !strings.Contains(body, vaultTestUserID) {
		t.Fatalf("expected response body to contain updated_by with user id, got: %s", body)
	}
	if !strings.Contains(body, `"updated_at"`) {
		t.Fatalf("expected response body to contain updated_at, got: %s", body)
	}
}
