package secrets

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/spf13/cobra"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/formatter"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// ctxWithFormatter adds a table formatter to the test context so commands that
// write tabular output don't fail with "output formatter not available".
func ctxWithFormatter(ctx context.Context) context.Context {
	fmtr, _ := formatter.New(formatter.FormatTable)
	return context.WithValue(ctx, common.OutputFormatterKey, fmtr)
}

func TestCreateSecretCommand(t *testing.T) {
	tests := []struct {
		name       string
		setupMocks func(*testutils.TestContext)
		args       []string
		wantErr    string
		wantOut    string
	}{
		{
			name: "successful secret creation",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)
				tc.MockSecretService.On("CreateSecret", mock.Anything, mock.MatchedBy(func(r secretServices.CreateSecretRequest) bool {
					return r.UserID == tc.TestUserID &&
						r.Name == "test-secret" &&
						r.Value == "secret-value"
				})).Return(&model.Secret{
					ID:      uuid.New(),
					UserID:  tc.TestUserID,
					Name:    "test-secret",
					Version: 1,
					Enabled: true,
				}, nil)
			},
			args:    []string{"test-secret", "secret-value"},
			wantOut: "test-secret",
		},
		{
			name:       "missing both arguments",
			setupMocks: func(_ *testutils.TestContext) {},
			args:       []string{},
			wantErr:    "requires <name> and <value>",
		},
		{
			name:       "missing value argument",
			setupMocks: func(_ *testutils.TestContext) {},
			args:       []string{"test-secret"},
			wantErr:    "requires <name> and <value>",
		},
		{
			name: "service error propagated",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)
				tc.MockSecretService.On("CreateSecret", mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			args:    []string{"test-secret", "secret-value"},
			wantErr: "failed to create secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			ctx := ctxWithFormatter(tc.Ctx)

			var out bytes.Buffer
			createCmd.SetContext(ctx)
			createCmd.SetOut(&out)
			createCmd.SetErr(&out)
			createCmd.SetArgs(tt.args)

			err := createCmd.Execute()

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				if tt.wantOut != "" {
					assert.Contains(t, out.String(), tt.wantOut)
				}
			}

			tc.MockSecretService.AssertExpectations(t)
		})
	}
}

func TestCreateSecretWithTags(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)
	tc.MockSecretService.On("CreateSecret", mock.Anything, mock.MatchedBy(func(r secretServices.CreateSecretRequest) bool {
		return len(r.Tags) == 3 &&
			r.Tags[0] == "env:prod" &&
			r.Tags[1] == "team:backend" &&
			r.Tags[2] == "type:api-key"
	})).Return(&model.Secret{
		ID:      uuid.New(),
		UserID:  tc.TestUserID,
		Name:    "test-secret",
		Version: 1,
		Enabled: true,
		Tags:    []string{"env:prod", "team:backend", "type:api-key"},
	}, nil)

	// Build a fresh command wired to the real RunE so flags are registered fresh.
	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.Flags().String("content-type", "", "")

	ctx := ctxWithFormatter(tc.Ctx)
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"test-secret", "secret-value", "--tags=env:prod", "--tags=team:backend", "--tags=type:api-key"})

	err := cmd.Execute()
	require.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}
