package cliclient

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/internal/vaultapi"
	"rocketvault/model"
)

func TestRoleAssignmentFromAPI_MapsEveryField(t *testing.T) {
	id, principalID := uuid.New(), uuid.New()
	got := RoleAssignmentFromAPI(&vaultapi.RoleAssignment{
		ID:                id,
		PrincipalID:       principalID,
		PrincipalUsername: "alice",
		PrincipalType:     "user",
		Role:              "Key Vault Administrator",
		VaultName:         "payments",
		CreatedAt:         "2026-09-03T10:00:00Z",
	})

	assert.Equal(t, id.String(), got.ID)
	assert.Equal(t, principalID.String(), got.PrincipalID)
	assert.Equal(t, "alice", got.PrincipalUsername)
	assert.Equal(t, "user", got.PrincipalType)
	assert.Equal(t, "Key Vault Administrator", got.Role)
	assert.Equal(t, "payments", got.VaultName)
	assert.Equal(t, "2026-09-03T10:00:00Z", got.CreatedAt)
}

func TestRoleAssignmentFromAPI_Nil(t *testing.T) {
	assert.Equal(t, model.RoleAssignmentResponse{}, RoleAssignmentFromAPI(nil))
}

// unmappedRoleAssignmentFields are the model fields the API response cannot
// supply. Each needs a reason. Adding a field to RoleAssignmentResponse
// without mapping it fails this test rather than silently dropping it from
// remote output.
var unmappedRoleAssignmentFields = map[string]string{
	"VaultID":             "the API returns vault_name, not the id; the CLI addresses vaults by name in remote mode",
	"ExpandedPolicyCount": "server-side derived field, not present in the role-assignments response",
}

func TestRoleAssignmentFromAPI_EveryModelFieldIsAccountedFor(t *testing.T) {
	populated := RoleAssignmentFromAPI(&vaultapi.RoleAssignment{
		ID:                uuid.New(),
		PrincipalID:       uuid.New(),
		PrincipalUsername: "alice",
		PrincipalType:     "user",
		Role:              "Key Vault Administrator",
		VaultName:         "payments",
		CreatedAt:         "2026-09-03T10:00:00Z",
	})

	v := reflect.ValueOf(populated)
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if _, expected := unmappedRoleAssignmentFields[name]; expected {
			continue
		}
		assert.Falsef(t, v.Field(i).IsZero(),
			"model.RoleAssignmentResponse.%s is not set by RoleAssignmentFromAPI; map it, or add it to unmappedRoleAssignmentFields with a reason",
			name)
	}
}
