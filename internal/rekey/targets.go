// Package rekey re-encrypts every master-key-sealed column in the database
// from an old master key to a new one.
//
// It works on raw ciphertext columns rather than through the repository layer
// on purpose: rotation must reach soft-deleted rows and version-history rows
// owned by any user (repository reads are scope- and soft-delete-filtered),
// must write ciphertext verbatim (services re-encrypt on the way through), and
// is a storage-format maintenance operation rather than a domain operation —
// the same category as internal/backup, which talks to the database directly
// for the same reasons.
package rekey

import (
	"fmt"
	"strings"
)

// ExternalKeyPrefix marks a keys/key_versions row whose value is a PKCS#11
// token label rather than master-key-sealed PEM. Mirrors pkcs11Prefix in
// internal/services/keys/crypto_service.go — HSM key material never leaves the
// token, so those rows have nothing to re-encrypt.
const ExternalKeyPrefix = "pkcs11:"

// Target describes one table column that stores AES-256-GCM ciphertext sealed
// with the master key, plus the primary-key columns used to address a row.
type Target struct {
	Table      string
	Column     string
	KeyColumns []string
}

// Targets returns every table column encrypted with the master key. Derived by
// mapping every caller of common.EncryptSecret to the column it writes:
// secrets and their version history, software (non-HSM) key PEMs and their
// version history, and certificate private-key PEMs. The JWT signing key used
// by internal/signing.SelfPKIProvider is an ordinary "keys" row and is covered
// by that entry.
//
// Returns:
//
//	The fixed list of master-key-encrypted columns.
func Targets() []Target {
	return []Target{
		{Table: "secrets", Column: "value", KeyColumns: []string{"id"}},
		{Table: "secret_versions", Column: "value", KeyColumns: []string{"id"}},
		{Table: "keys", Column: "value", KeyColumns: []string{"id"}},
		{Table: "key_versions", Column: "value", KeyColumns: []string{"key_id", "version"}},
		{Table: "certificates", Column: "private_key", KeyColumns: []string{"id"}},
	}
}

// SelectSQL builds the statement that reads every row's primary key and
// ciphertext. Table and column names come from the hardcoded Targets list, not
// from user input, so interpolating them is safe here.
//
// Returns:
//
//	A SELECT statement listing the key columns followed by the value column.
func (t Target) SelectSQL() string {
	return fmt.Sprintf("SELECT %s, %s FROM %s",
		strings.Join(t.KeyColumns, ", "), t.Column, t.Table)
}

// UpdateSQL builds the guarded re-encryption statement. The trailing
// "AND <column> = ?" compares against the ciphertext read during the plan
// phase, so a row rewritten by a still-running server matches zero rows
// instead of being silently clobbered.
//
// Returns:
//
//	An UPDATE statement whose arguments are (new value, key values..., old value).
func (t Target) UpdateSQL() string {
	conditions := make([]string, 0, len(t.KeyColumns)+1)
	for _, column := range t.KeyColumns {
		conditions = append(conditions, column+" = ?")
	}
	conditions = append(conditions, t.Column+" = ?")

	return fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s",
		t.Table, t.Column, strings.Join(conditions, " AND "))
}
