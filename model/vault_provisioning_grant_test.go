package model_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

func TestVaultProvisioningGrant_Validate(t *testing.T) {
	tests := []struct {
		name    string
		grant   model.VaultProvisioningGrant
		wantErr bool
	}{
		{"valid", model.VaultProvisioningGrant{PrincipalID: uuid.New(), Quota: 5}, false},
		{"quota of one is valid", model.VaultProvisioningGrant{PrincipalID: uuid.New(), Quota: 1}, false},
		{"zero quota rejected", model.VaultProvisioningGrant{PrincipalID: uuid.New(), Quota: 0}, true},
		{"negative quota rejected", model.VaultProvisioningGrant{PrincipalID: uuid.New(), Quota: -1}, true},
		{"nil principal rejected", model.VaultProvisioningGrant{PrincipalID: uuid.Nil, Quota: 5}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.grant.Validate()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
