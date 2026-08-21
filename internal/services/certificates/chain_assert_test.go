package certificates

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

// assertSignedBy proves that leafPEM was issued by caPEM: the issuer common
// name matches, the CA's own signature check accepts the leaf, and the leaf
// chains to the CA as a root. All three, because an issuer field alone can be
// written by anyone -- it is the signature that makes the chain real.
func assertSignedBy(t *testing.T, leafPEM, caPEM, wantIssuerCN string) {
	t.Helper()

	leaf := parseCertPEM(t, leafPEM)
	ca := parseCertPEM(t, caPEM)

	require.Equal(t, wantIssuerCN, leaf.Issuer.CommonName, "issuer common name")
	require.NoError(t, leaf.CheckSignatureFrom(ca), "leaf must verify against the CA")

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err, "leaf must chain to the CA")
}

// assertSelfSigned proves a certificate is its own issuer and verifies against
// its own public key.
func assertSelfSigned(t *testing.T, certPEM string) {
	t.Helper()

	cert := parseCertPEM(t, certPEM)
	require.Equal(t, cert.Subject.CommonName, cert.Issuer.CommonName, "a self-signed certificate issues itself")
	require.NoError(t, cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature),
		"a self-signed certificate must verify against its own key")
}
