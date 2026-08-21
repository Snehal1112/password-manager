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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateCmd_InvalidLength_ReturnsError is the regression test for the
// bug where generateCmd's Run handler called os.Exit(0) on a
// generatePassword error, making the failure indistinguishable from
// success at the shell level. RunE must return a non-nil error instead,
// letting Cobra (and, ultimately, cmd.Execute()) surface it as a non-zero
// exit code.
func TestGenerateCmd_InvalidLength_ReturnsError(t *testing.T) {
	cmd := generateCmd
	cmd.Flags().Set("length", "0") //nolint:errcheck
	cmd.SetArgs([]string{})

	err := cmd.RunE(cmd, []string{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate password")
}

// TestGenerateCmdLongTextReflectsSessionExemption pins the help text
// against the isSystemCommand fix (B41): the command no longer requires an
// active session, so its Long text must not claim otherwise.
func TestGenerateCmdLongTextReflectsSessionExemption(t *testing.T) {
	assert.NotContains(t, generateCmd.Long, "is still required to run it")
	assert.Contains(t, generateCmd.Long, "needs no active session")
}
