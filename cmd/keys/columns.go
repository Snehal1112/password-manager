package keys

import (
	"rocketvault/cmd/vaultcli"
	keyServices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// keyColumns is how a key is printed, everywhere. `get` and `list` each
// spelled out their own headers and cells before, which is how the two could
// have drifted apart without any test noticing.
var keyColumns = []vaultcli.Column[model.Key]{
	vaultcli.Col("ID", func(k model.Key) string { return vaultcli.CellUUID(k.ID) }),
	vaultcli.Col("Name", func(k model.Key) string { return k.Name }),
	vaultcli.Col("Type", func(k model.Key) string { return k.Type }),
	vaultcli.Col("Revoked", func(k model.Key) string { return vaultcli.CellBool(k.Revoked) }),
	vaultcli.Col("Tags", func(k model.Key) string { return vaultcli.CellCSV(k.Tags) }),
	vaultcli.Col("Created", func(k model.Key) string { return vaultcli.CellTime(k.CreatedAt) }),
}

// verifyColumns is what `verify` prints. The command additionally exits
// non-zero on an invalid signature, so this table is the detail, not the
// verdict a script should branch on.
var verifyColumns = []vaultcli.Column[*keyServices.VerifyResult]{
	vaultcli.Col("Key ID", func(r *keyServices.VerifyResult) string { return vaultcli.CellUUID(r.KeyID) }),
	vaultcli.Col("Algorithm", func(r *keyServices.VerifyResult) string { return string(r.Algorithm) }),
	vaultcli.Col("Valid", func(r *keyServices.VerifyResult) string { return vaultcli.CellBool(r.Valid) }),
}

// createdKeyColumns is what `create` and `import` print. It is deliberately
// not keyColumns: CreateKeyResult has no Revoked field (a freshly created key
// never is), and printing a hardcoded "false" column would be noise.
var createdKeyColumns = []vaultcli.Column[*keyServices.CreateKeyResult]{
	vaultcli.Col("ID", func(r *keyServices.CreateKeyResult) string { return vaultcli.CellUUID(r.KeyID) }),
	vaultcli.Col("Name", func(r *keyServices.CreateKeyResult) string { return r.Name }),
	vaultcli.Col("Type", func(r *keyServices.CreateKeyResult) string { return r.Type }),
	vaultcli.Col("Tags", func(r *keyServices.CreateKeyResult) string { return vaultcli.CellCSV(r.Tags) }),
	vaultcli.Col("Created", func(r *keyServices.CreateKeyResult) string { return vaultcli.CellTime(r.CreatedAt) }),
}
