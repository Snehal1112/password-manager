package cliclient

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/vaultapi"
)

func TestCLIError_Unauthorized_TellsUserHowToReauthenticate(t *testing.T) {
	err := CLIError("grant a role", &vaultapi.APIError{
		StatusCode: http.StatusUnauthorized,
		Kind:       vaultapi.KindUnauthorized,
		Method:     http.MethodPost,
		Path:       "/api/v1/vaults/payments/role-assignments",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "grant a role")
	assert.Contains(t, err.Error(), "--username")
}

func TestCLIError_Forbidden_NamesTheAuthorizationCause(t *testing.T) {
	err := CLIError("grant a role", &vaultapi.APIError{
		StatusCode: http.StatusForbidden,
		Kind:       vaultapi.KindForbidden,
		Method:     http.MethodPost,
		Path:       "/api/v1/vaults/payments/role-assignments",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment")
}

func TestCLIError_NotFound(t *testing.T) {
	err := CLIError("list role assignments", &vaultapi.APIError{
		StatusCode: http.StatusNotFound,
		Kind:       vaultapi.KindNotFound,
		Method:     http.MethodGet,
		Path:       "/api/v1/vaults/nope/role-assignments",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCLIError_NonAPIError_PassesThrough(t *testing.T) {
	original := errors.New("dial tcp: connection refused")
	err := CLIError("grant a role", original)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestCLIError_Nil(t *testing.T) {
	assert.NoError(t, CLIError("grant a role", nil))
}

// A wrapped APIError must still be classified -- errors.As, not a type
// assertion, is what makes that work.
func TestCLIError_WrappedAPIError_IsStillClassified(t *testing.T) {
	wrapped := fmt.Errorf("calling the server: %w", &vaultapi.APIError{
		StatusCode: http.StatusForbidden,
		Kind:       vaultapi.KindForbidden,
		Method:     http.MethodPost,
		Path:       "/api/v1/vaults/payments/role-assignments",
	})
	err := CLIError("grant a role", wrapped)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment")
}

func TestCLIError_Conflict(t *testing.T) {
	err := CLIError("grant a role", &vaultapi.APIError{
		StatusCode: http.StatusConflict,
		Kind:       vaultapi.KindConflict,
	})
	require.ErrorContains(t, err, "already exists")
}

func TestCLIError_ServerError_ReportsTheStatus(t *testing.T) {
	err := CLIError("list role assignments", &vaultapi.APIError{
		StatusCode: http.StatusInternalServerError,
		Kind:       vaultapi.KindServer,
	})
	require.ErrorContains(t, err, "500")
}
