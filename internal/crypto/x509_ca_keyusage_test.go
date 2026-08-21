package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

// parseCertPEM decodes and parses one PEM-encoded certificate.
func parseCertPEM(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "certificate PEM must decode")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// requireChainVerifies proves leafPEM was really issued by caPEM. Both checks
// matter: CheckSignatureFrom applies the issuer's own key and its CA
// constraints, and Verify additionally builds a chain to the CA as a trusted
// root, which is what a real client does.
func requireChainVerifies(t *testing.T, leafPEM, caPEM string) {
	t.Helper()

	leaf := parseCertPEM(t, leafPEM)
	ca := parseCertPEM(t, caPEM)

	require.NoError(t, leaf.CheckSignatureFrom(ca), "leaf must verify against its CA")

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: pool})
	require.NoError(t, err, "leaf must chain to the CA as a trusted root")
	require.NotEmpty(t, chains)
}

// A CA certificate must carry KeyUsageCertSign. RFC 5280 requires it once a
// key-usage extension is asserted at all, and crypto/x509 enforces it.
func TestCreateX509Template_CAGetsCertSign(t *testing.T) {
	tmpl, err := CreateX509Template(CertificateTemplate{
		CommonName:   "ca.example.com",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)
	require.True(t, tmpl.IsCA)
	require.True(t, tmpl.BasicConstraintsValid)
	require.NotZero(t, tmpl.KeyUsage&x509.KeyUsageCertSign, "a CA template must allow certificate signing")
	require.NotZero(t, tmpl.KeyUsage&x509.KeyUsageCRLSign, "a CA template must allow CRL signing")
	require.NotZero(t, tmpl.KeyUsage&x509.KeyUsageDigitalSignature, "the existing usages must be kept")
	require.NotZero(t, tmpl.KeyUsage&x509.KeyUsageKeyEncipherment, "the existing usages must be kept")
}

// Regression guard: the fix must be conditional on IsCA. A leaf that gained
// certificate-signing authority would be a worse defect than the one being
// fixed, and a blanket KeyUsage change would pass the CA test above.
func TestCreateX509Template_LeafHasNoCertSign(t *testing.T) {
	tmpl, err := CreateX509Template(CertificateTemplate{
		CommonName:   "leaf.example.com",
		ValidityDays: 365,
		IsCA:         false,
	})
	require.NoError(t, err)
	require.False(t, tmpl.IsCA)
	require.Zero(t, tmpl.KeyUsage&x509.KeyUsageCertSign, "a leaf template must not allow certificate signing")
	require.Zero(t, tmpl.KeyUsage&x509.KeyUsageCRLSign, "a leaf template must not allow CRL signing")
}

// The headline test: an RSA CA issued by this package must be able to issue a
// leaf that passes both standard verification paths. Asserting on the usage
// bits alone would accept a wrong fix, so this asserts on the outcome.
func TestCASignedChain_RSACA_Verifies(t *testing.T) {
	caKeyPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	leafKeyPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	caPEM, err := CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", CertificateTemplate{
		CommonName:   "rsa-ca.example.com",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	leafPEM, err := CreateCASignedCertificatePEM(leafKeyPEM, "RSA", caPEM, caKeyPEM, "RSA", CertificateTemplate{
		CommonName:   "leaf.example.com",
		ValidityDays: 365,
		IsCA:         false,
	})
	require.NoError(t, err)

	requireChainVerifies(t, leafPEM, caPEM)
}

// The same outcome must hold for an ECDSA CA, so the fix cannot be
// RSA-specific: it lives in the shared template, not in a signing branch.
func TestCASignedChain_ECDSACA_Verifies(t *testing.T) {
	caKeyPEM, err := GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	leafKeyPEM, err := GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)

	caPEM, err := CreateSelfSignedCertificatePEM(caKeyPEM, "ECDSA", CertificateTemplate{
		CommonName:   "ec-ca.example.com",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	leafPEM, err := CreateCASignedCertificatePEM(leafKeyPEM, "ECDSA", caPEM, caKeyPEM, "ECDSA", CertificateTemplate{
		CommonName:   "ec-leaf.example.com",
		ValidityDays: 365,
		IsCA:         false,
	})
	require.NoError(t, err)

	requireChainVerifies(t, leafPEM, caPEM)
}

// An issued CA certificate must carry the usage in its signed body, not just
// in the in-memory template -- that is the part an already-issued certificate
// can never gain.
func TestSelfSignedCA_CarriesCertSignInTheIssuedCertificate(t *testing.T) {
	caKeyPEM, err := GenerateRSAKeyPEM(2048)
	require.NoError(t, err)

	caPEM, err := CreateSelfSignedCertificatePEM(caKeyPEM, "RSA", CertificateTemplate{
		CommonName:   "issued-ca.example.com",
		ValidityDays: 3650,
		IsCA:         true,
	})
	require.NoError(t, err)

	ca := parseCertPEM(t, caPEM)
	require.True(t, ca.IsCA)
	require.True(t, ca.BasicConstraintsValid)
	require.NotZero(t, ca.KeyUsage&x509.KeyUsageCertSign)
	require.NotZero(t, ca.KeyUsage&x509.KeyUsageCRLSign)
}
