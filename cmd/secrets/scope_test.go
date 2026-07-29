/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package secrets

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)

// TestSecretsGetBuildsAVaultScope pins that the CLI resolves --vault into a
// vault scope rather than calling a *InVault method.
func TestSecretsGetBuildsAVaultScope(t *testing.T) {
	svc, cmd, vaultID := newCLIScopeFixture(t, func() *cobra.Command {
		return &cobra.Command{Use: "get [id]", Args: cobra.ExactArgs(1), RunE: getCmd.RunE}
	})
	secretID := uuid.New()

	svc.On("GetSecret", mock.Anything, secretID, model.NewVaultScope(vaultID, uuid.Nil)).
		Return(&model.Secret{ID: secretID, Name: "s", Value: "v", Version: 1}, nil).Once()

	cmd.SetArgs([]string{secretID.String()})
	require.NoError(t, cmd.Execute())
	svc.AssertExpectations(t)
}

func TestSecretsListBuildsAVaultScope(t *testing.T) {
	svc, cmd, vaultID := newCLIScopeFixture(t, func() *cobra.Command {
		c := &cobra.Command{Use: "list", RunE: listCmd.RunE}
		c.Flags().StringSlice("tags", []string{}, "Tags to filter secrets (comma-separated)")
		return c
	})

	svc.On("ListSecrets", mock.Anything, model.NewVaultScope(vaultID, uuid.Nil), mock.Anything).
		Return([]model.Secret{{ID: uuid.New(), Name: "a"}}, nil).Once()

	require.NoError(t, cmd.Execute())
	svc.AssertExpectations(t)
}

func TestSecretsDeleteBuildsAVaultScope(t *testing.T) {
	svc, cmd, vaultID := newCLIScopeFixture(t, func() *cobra.Command {
		return &cobra.Command{Use: "delete [id]", Args: cobra.ExactArgs(1), Run: deleteCmd.Run}
	})
	secretID := uuid.New()

	svc.On("DeleteSecret", mock.Anything, secretID, model.NewVaultScope(vaultID, uuid.Nil)).
		Return(nil).Once()

	cmd.SetArgs([]string{secretID.String()})
	require.NoError(t, cmd.Execute())
	svc.AssertExpectations(t)
}

// newCLIScopeFixture returns the mock secret service, a command wired to the
// test context, and the vault id resolveVaultID will produce. buildCmd
// constructs a fresh cobra.Command per test, registering only the flags that
// command reads, so flag registration cannot collide across the three
// commands exercised in this file (get and delete take none, list takes
// --tags).
//
// It reuses testutils.NewTestContext(t), which wires a MockServiceContainer
// into the context under common.ServiceContainerKey and pre-registers a
// GetVault(ctx, "default") expectation returning the default vault, so
// resolveVaultID resolves to tc.TestVaultID without extra setup. It also
// attaches an output formatter, since the get/list RunE paths require one to
// reach the point where the scoped service call happens.
func newCLIScopeFixture(t *testing.T, buildCmd func() *cobra.Command) (*testutils.MockSecretService, *cobra.Command, uuid.UUID) {
	t.Helper()

	tc := testutils.NewTestContext(t)
	t.Cleanup(func() { tc.MockSecretService.AssertExpectations(t) })

	fmtr, err := formatter.New(formatter.FormatTable)
	require.NoError(t, err)
	ctx := context.WithValue(tc.Ctx, common.OutputFormatterKey, fmtr)

	cmd := buildCmd()
	cmd.SetContext(ctx)

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	return tc.MockSecretService, cmd, tc.TestVaultID
}
