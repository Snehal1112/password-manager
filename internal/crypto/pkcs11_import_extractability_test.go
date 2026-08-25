package crypto

// This file is an in-package (package crypto, not crypto_test) test so it can
// reach PKCS11KeyProvider's unexported ctx/openRWSession/closeSession/
// findPrivateKey to assert CKA_EXTRACTABLE directly on the token object
// ImportKey creates. pkcs11_provider_test.go (package crypto_test) cannot do
// this: it only has the exported surface, so its ImportKey tests can prove a
// key is usable (Sign/Verify) but not that it is actually non-extractable --
// the one property this whole feature exists to protect. Deleting
// CKA_EXTRACTABLE: false from ImportKey would still leave every test in
// pkcs11_provider_test.go green; the tests here are the regression guard for
// exactly that.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"os/exec"
	"testing"

	p11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// softhsmAvailableInPackage duplicates pkcs11_provider_test.go's
// softhsmAvailable check. It can't be reused directly: that helper lives in
// the external crypto_test package, which this in-package test file cannot
// import (an in-package test file and an external test file for the same
// package compile as siblings, but _test.go files are never importable).
func softhsmAvailableInPackage() bool {
	_, err := exec.LookPath("softhsm2-util")
	if err != nil {
		return false
	}
	lib := os.Getenv("SOFTHSM2_LIB")
	if lib == "" {
		return false
	}
	if _, err := os.Stat(lib); err != nil {
		return false
	}
	return true
}

// newInPackageTestPKCS11Provider mirrors newTestPKCS11Provider from
// pkcs11_provider_test.go, constructing against the same "rocketvault"
// SoftHSM2 token/PIN convention used throughout this package's PKCS#11
// tests. Skips when SoftHSM2 isn't available, same as the external tests.
func newInPackageTestPKCS11Provider(t *testing.T) *PKCS11KeyProvider {
	t.Helper()
	if !softhsmAvailableInPackage() {
		t.Skip("softhsm2-util not found or SOFTHSM2_LIB not set; skipping PKCS#11 integration tests")
	}

	lib := os.Getenv("SOFTHSM2_LIB")
	cfg := PKCS11Config{
		LibPath:    lib,
		TokenLabel: "rocketvault",
		PIN:        "1234",
	}

	p, err := NewPKCS11KeyProvider(cfg)
	require.NoError(t, err, "failed to create PKCS11KeyProvider")
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// assertPrivateKeyNonExtractable looks up the private key object ImportKey
// created (by its CKA_LABEL handle) and reads back CKA_EXTRACTABLE directly
// from the token, asserting it is CK_FALSE. This is the real regression
// guard for ImportKey's core security property: a Sign/Verify round trip
// alone proves the key is usable, not that it's non-extractable.
func assertPrivateKeyNonExtractable(t *testing.T, p *PKCS11KeyProvider, handle string) {
	t.Helper()

	session, err := p.openRWSession()
	require.NoError(t, err)
	defer p.closeSession(session)

	objHandle, err := p.findPrivateKey(session, handle)
	require.NoError(t, err)

	attrs, err := p.ctx.GetAttributeValue(session, objHandle, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_EXTRACTABLE, nil),
	})
	require.NoError(t, err)
	require.Len(t, attrs, 1)
	require.Len(t, attrs[0].Value, 1, "CKA_EXTRACTABLE must return a single CK_BBOOL byte")
	assert.Equal(t, byte(0), attrs[0].Value[0],
		"imported private key must be non-extractable (CKA_EXTRACTABLE: false)")
}

func TestPKCS11Provider_ImportKey_RSA_PrivateKeyIsNonExtractable(t *testing.T) {
	p := newInPackageTestPKCS11Provider(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	handle, err := p.ImportKey(context.Background(), "RSA", priv)
	require.NoError(t, err)

	assertPrivateKeyNonExtractable(t, p, handle)
}

func TestPKCS11Provider_ImportKey_ECDSA_PrivateKeyIsNonExtractable(t *testing.T) {
	p := newInPackageTestPKCS11Provider(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	handle, err := p.ImportKey(context.Background(), "ECDSA", priv)
	require.NoError(t, err)

	assertPrivateKeyNonExtractable(t, p, handle)
}
