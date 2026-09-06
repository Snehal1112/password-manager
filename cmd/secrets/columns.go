package secrets

import (
	"rocketvault/cmd/vaultcli"
	"rocketvault/model"
)

// Secrets are printed from two different types: model.Secret in local mode and
// model.SecretResponse over the wire, whose ID and CreatedAt are already
// strings. Each command therefore had two hand-built header/cell blocks, forty
// lines apart in the same file, that nothing forced to agree -- `secrets get`
// spelled the same ten headers out twice.
//
// The column sets below are still one per type (the field types genuinely
// differ), but they are declared side by side, and TestColumnSetsAgree pins
// their headers to each other so a column added to one has to be added to the
// other.

// secretDetailColumns is `get`: the full record, including the decrypted value.
var secretDetailColumns = []vaultcli.Column[model.Secret]{
	vaultcli.Col("ID", func(s model.Secret) string { return vaultcli.CellUUID(s.ID) }),
	vaultcli.Col("Name", func(s model.Secret) string { return s.Name }),
	vaultcli.Col("Value", func(s model.Secret) string { return s.Value }),
	vaultcli.Col("Version", func(s model.Secret) string { return vaultcli.CellInt(s.Version) }),
	vaultcli.Col("Enabled", func(s model.Secret) string { return vaultcli.CellBool(s.Enabled) }),
	vaultcli.Col("ContentType", func(s model.Secret) string { return s.ContentType }),
	vaultcli.Col("Tags", func(s model.Secret) string { return vaultcli.CellCSV(s.Tags) }),
	vaultcli.Col("Expires", func(s model.Secret) string { return vaultcli.CellOptTime(s.ExpiresAt) }),
	vaultcli.Col("NotBefore", func(s model.Secret) string { return vaultcli.CellOptTime(s.NotBefore) }),
	vaultcli.Col("Created", func(s model.Secret) string { return vaultcli.CellTime(s.CreatedAt) }),
}

// remoteSecretDetailColumns is `get`'s remote-mode counterpart.
var remoteSecretDetailColumns = []vaultcli.Column[model.SecretResponse]{
	vaultcli.Col("ID", func(s model.SecretResponse) string { return s.ID }),
	vaultcli.Col("Name", func(s model.SecretResponse) string { return s.Name }),
	vaultcli.Col("Value", func(s model.SecretResponse) string { return s.Value }),
	vaultcli.Col("Version", func(s model.SecretResponse) string { return vaultcli.CellInt(s.Version) }),
	vaultcli.Col("Enabled", func(s model.SecretResponse) string { return vaultcli.CellBool(s.Enabled) }),
	vaultcli.Col("ContentType", func(s model.SecretResponse) string { return s.ContentType }),
	vaultcli.Col("Tags", func(s model.SecretResponse) string { return vaultcli.CellCSV(s.Tags) }),
	vaultcli.Col("Expires", func(s model.SecretResponse) string { return vaultcli.CellOptTime(s.ExpiresAt) }),
	vaultcli.Col("NotBefore", func(s model.SecretResponse) string { return vaultcli.CellOptTime(s.NotBefore) }),
	vaultcli.Col("Created", func(s model.SecretResponse) string { return s.CreatedAt }),
}

// secretSummaryColumns is `list`: no value, no validity window.
var secretSummaryColumns = []vaultcli.Column[model.Secret]{
	vaultcli.Col("ID", func(s model.Secret) string { return vaultcli.CellUUID(s.ID) }),
	vaultcli.Col("Name", func(s model.Secret) string { return s.Name }),
	vaultcli.Col("Version", func(s model.Secret) string { return vaultcli.CellInt(s.Version) }),
	vaultcli.Col("Enabled", func(s model.Secret) string { return vaultcli.CellBool(s.Enabled) }),
	vaultcli.Col("Tags", func(s model.Secret) string { return vaultcli.CellCSV(s.Tags) }),
	vaultcli.Col("Created", func(s model.Secret) string { return vaultcli.CellTime(s.CreatedAt) }),
}

// remoteSecretSummaryColumns is `list`'s remote-mode counterpart.
var remoteSecretSummaryColumns = []vaultcli.Column[model.SecretResponse]{
	vaultcli.Col("ID", func(s model.SecretResponse) string { return s.ID }),
	vaultcli.Col("Name", func(s model.SecretResponse) string { return s.Name }),
	vaultcli.Col("Version", func(s model.SecretResponse) string { return vaultcli.CellInt(s.Version) }),
	vaultcli.Col("Enabled", func(s model.SecretResponse) string { return vaultcli.CellBool(s.Enabled) }),
	vaultcli.Col("Tags", func(s model.SecretResponse) string { return vaultcli.CellCSV(s.Tags) }),
	vaultcli.Col("Created", func(s model.SecretResponse) string { return s.CreatedAt }),
}

// secretCreatedColumns is what `create` acknowledges with.
var secretCreatedColumns = []vaultcli.Column[model.Secret]{
	vaultcli.Col("ID", func(s model.Secret) string { return vaultcli.CellUUID(s.ID) }),
	vaultcli.Col("Name", func(s model.Secret) string { return s.Name }),
	vaultcli.Col("Version", func(s model.Secret) string { return vaultcli.CellInt(s.Version) }),
	vaultcli.Col("Enabled", func(s model.Secret) string { return vaultcli.CellBool(s.Enabled) }),
	vaultcli.Col("Created", func(s model.Secret) string { return vaultcli.CellTime(s.CreatedAt) }),
}

// remoteSecretCreatedColumns is `create`'s remote-mode counterpart.
var remoteSecretCreatedColumns = []vaultcli.Column[model.SecretResponse]{
	vaultcli.Col("ID", func(s model.SecretResponse) string { return s.ID }),
	vaultcli.Col("Name", func(s model.SecretResponse) string { return s.Name }),
	vaultcli.Col("Version", func(s model.SecretResponse) string { return vaultcli.CellInt(s.Version) }),
	vaultcli.Col("Enabled", func(s model.SecretResponse) string { return vaultcli.CellBool(s.Enabled) }),
	vaultcli.Col("Created", func(s model.SecretResponse) string { return s.CreatedAt }),
}
