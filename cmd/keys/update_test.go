package keys

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/repositories"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

type MockKeyServiceForUpdate struct{ mock.Mock }

func (m *MockKeyServiceForUpdate) UpdateKey(ctx context.Context, req keyServices.UpdateKeyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}
func (m *MockKeyServiceForUpdate) CreateRSAKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) CreateECDSAKey(ctx context.Context, req keyServices.CreateKeyRequest) (*keyServices.CreateKeyResult, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) GetKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) ListKeys(ctx context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) DeleteKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.Key, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) RotateKey(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*keyServices.CreateKeyResult, error) {
	return nil, nil
}
func (m *MockKeyServiceForUpdate) ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	return nil
}

func TestUpdateKeyCommand_CallsServiceUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockKeySvc := &MockKeyServiceForUpdate{}
	keyID := uuid.New()

	mockKeySvc.On("UpdateKey", mock.Anything, mock.MatchedBy(func(r keyServices.UpdateKeyRequest) bool {
		return r.KeyID == keyID &&
			r.Scope == model.NewOwnerScope(uuid.Nil, tc.TestUserID) &&
			r.Name != nil && *r.Name == "new-name"
	})).Return(nil)
	tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String(), "--name=new-name"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	mockKeySvc.AssertExpectations(t)
}

func TestUpdateKeyCommand_SetsRevoked(t *testing.T) {
	tc := testutils.NewTestContext(t)
	mockKeySvc := &MockKeyServiceForUpdate{}
	keyID := uuid.New()

	mockKeySvc.On("UpdateKey", mock.Anything, mock.MatchedBy(func(r keyServices.UpdateKeyRequest) bool {
		return r.Revoked != nil && *r.Revoked == true
	})).Return(nil)
	tc.MockContainer.On("GetKeyService").Return(mockKeySvc)

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String(), "--revoked=true"})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	mockKeySvc.AssertExpectations(t)
}

func TestUpdateKeyCommand_NoFieldsProvided(t *testing.T) {
	tc := testutils.NewTestContext(t)
	keyID := uuid.New()

	cmd := &cobra.Command{
		Use:  "update <id>",
		Args: cobra.ExactArgs(1),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().String("name", "", "")
	cmd.Flags().Bool("revoked", false, "")
	cmd.Flags().String("tags", "", "")
	cmd.SetArgs([]string{keyID.String()})
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one update field")
}
