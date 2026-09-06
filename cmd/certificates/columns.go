package certificates

import (
	"rocketvault/cmd/vaultcli"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// certColumns is how a certificate is printed, everywhere. `get` and `list`
// each spelled out their own headers and cells before.
var certColumns = []vaultcli.Column[model.Certificate]{
	vaultcli.Col("ID", func(c model.Certificate) string { return vaultcli.CellUUID(c.ID) }),
	vaultcli.Col("Name", func(c model.Certificate) string { return c.Name }),
	vaultcli.Col("Tags", func(c model.Certificate) string { return vaultcli.CellCSV(c.Tags) }),
	vaultcli.Col("Expires", func(c model.Certificate) string { return vaultcli.CellOptTime(c.ExpiresAt) }),
	vaultcli.Col("AutoRenew", func(c model.Certificate) string { return vaultcli.CellBool(c.AutoRenew) }),
	vaultcli.Col("Created", func(c model.Certificate) string { return vaultcli.CellTime(c.CreatedAt) }),
}

// createdCertColumns is what `create` prints. Deliberately narrower than
// certColumns: CreateCertificateResult carries no tags, expiry or auto-renew
// flag, and printing empty columns for them would suggest they were unset
// rather than simply not returned.
var createdCertColumns = []vaultcli.Column[*certServices.CreateCertificateResult]{
	vaultcli.Col("ID", func(r *certServices.CreateCertificateResult) string { return vaultcli.CellUUID(r.CertID) }),
	vaultcli.Col("Name", func(r *certServices.CreateCertificateResult) string { return r.Name }),
	vaultcli.Col("Created", func(r *certServices.CreateCertificateResult) string { return vaultcli.CellTime(r.CreatedAt) }),
}
