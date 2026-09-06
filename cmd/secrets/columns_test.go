package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/cmd/vaultcli"
	"rocketvault/model"
)

// headersOf extracts a column set's header row.
func headersOf[T any](cols []vaultcli.Column[T]) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.Header
	}
	return out
}

// Local mode renders model.Secret and remote mode renders model.SecretResponse,
// so each command needs two column sets. They must present the same table:
// `secrets get --server ...` and `secrets get` are the same command to a user,
// and a script parsing one must parse the other.
//
// The old code had these as six separate hand-written []string header literals
// scattered across three files, with nothing tying a pair together.
func TestColumnSetsAgree(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		local, remote []string
	}{
		{"get", headersOf(secretDetailColumns), headersOf(remoteSecretDetailColumns)},
		{"list", headersOf(secretSummaryColumns), headersOf(remoteSecretSummaryColumns)},
		{"create", headersOf(secretCreatedColumns), headersOf(remoteSecretCreatedColumns)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.local, tc.remote,
				"local and remote %q must render the same columns in the same order", tc.name)
		})
	}
}

// The exact headers are a public interface: scripts parse them. Pin them.
func TestColumnHeaders(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		[]string{"ID", "Name", "Value", "Version", "Enabled", "ContentType", "Tags", "Expires", "NotBefore", "Created"},
		headersOf(secretDetailColumns))
	assert.Equal(t,
		[]string{"ID", "Name", "Version", "Enabled", "Tags", "Created"},
		headersOf(secretSummaryColumns))
	assert.Equal(t,
		[]string{"ID", "Name", "Version", "Enabled", "Created"},
		headersOf(secretCreatedColumns))
}

// list must not print a secret's value: it is the one column that separates
// the summary from the detail view, and adding it would leak every secret in
// the vault to anyone who can list.
func TestSummaryColumnsOmitValue(t *testing.T) {
	t.Parallel()

	assert.NotContains(t, headersOf(secretSummaryColumns), "Value")
	assert.NotContains(t, headersOf(remoteSecretSummaryColumns), "Value")
	assert.NotContains(t, headersOf(secretCreatedColumns), "Value")
	assert.NotContains(t, headersOf(remoteSecretCreatedColumns), "Value")
}

// The two types spell the same field differently (uuid.UUID vs string,
// time.Time vs string), so check a populated record renders identically.
func TestLocalAndRemoteCellsMatch(t *testing.T) {
	t.Parallel()

	local := model.Secret{
		Name: "db-password", Version: 3, Enabled: true,
		Tags: []string{"prod", "db"}, ContentType: "application/json",
	}
	remote := model.SecretResponse{
		Name: "db-password", Version: 3, Enabled: true,
		Tags: []string{"prod", "db"}, ContentType: "application/json",
	}

	for i := range secretSummaryColumns {
		// Skip ID and Created: they are the two genuinely type-divergent
		// fields, and a zero uuid/time has no string counterpart.
		if h := secretSummaryColumns[i].Header; h == "ID" || h == "Created" {
			continue
		}
		assert.Equal(t,
			secretSummaryColumns[i].Value(local),
			remoteSecretSummaryColumns[i].Value(remote),
			"column %q renders differently in local and remote mode", secretSummaryColumns[i].Header)
	}
}
