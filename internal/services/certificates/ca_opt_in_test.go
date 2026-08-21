package certificates

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/model"
)

// parseIssuedCert decodes and parses a certificate the service just issued.
// The name deliberately avoids parseCertPEM, which plan 03 adds to this
// package in chain_assert_test.go.
func parseIssuedCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "certificate PEM must decode")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// certCapture records the certificate the service handed to the repository.
type certCapture struct {
	cert *model.Certificate
}

// selfSignedFixture wires everything CreateSelfSignedCertificate needs.
type selfSignedFixture struct {
	svc     CertificateService
	userID  uuid.UUID
	keyID   uuid.UUID
	capture *certCapture
}

// newSelfSignedFixture gives the caller a readable RSA key it owns, and a
// Create that records the stored certificate for inspection.
func newSelfSignedFixture(t *testing.T) *selfSignedFixture {
	t.Helper()
	setupMasterKey()

	userID := uuid.New()
	keyID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	keyRepo.On("Read", mock.Anything, keyID, certVaultScope(userID)).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}, nil)

	capture := &certCapture{}
	certRepo.On("Create", mock.Anything, mock.AnythingOfType("*model.Certificate")).
		Run(func(args mock.Arguments) { capture.cert = args.Get(1).(*model.Certificate) }).
		Return(nil)

	return &selfSignedFixture{
		svc:     newCertSvc(certRepo, keyRepo),
		userID:  userID,
		keyID:   keyID,
		capture: capture,
	}
}

// An ordinary self-signed certificate is a leaf. Both self-signed call sites
// hardcoded IsCA: true, so every certificate this service issued asserted
// CA:TRUE -- and a leaked leaf key could then mint certificates for arbitrary
// names (B44).
func TestCreateSelfSignedCertificate_DefaultsToNonCA(t *testing.T) {
	f := newSelfSignedFixture(t)

	_, err := f.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "tls-server",
		KeyID:        f.keyID,
		ValidityDays: 365,
		UserID:       f.userID,
	})
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	issued := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.False(t, issued.IsCA, "an ordinary self-signed certificate must not be a CA")
	assert.True(t, issued.BasicConstraintsValid, "basic constraints must still be asserted")
}

// A CA is something you ask for. IsCA is the opt-in behind the --is-ca flag
// and the is_ca API field.
func TestCreateSelfSignedCertificate_CAOptIn(t *testing.T) {
	f := newSelfSignedFixture(t)

	_, err := f.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "issuing-ca",
		KeyID:        f.keyID,
		ValidityDays: 3650,
		UserID:       f.userID,
		IsCA:         true,
	})
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	issued := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.True(t, issued.IsCA, "the opt-in must produce a CA certificate")
}

// The opt-in has no meaning on the CA-signed path: issuing an intermediate CA
// is a separate feature. Quietly returning a leaf when a CA was asked for is
// the same silent wrongness B44 is about, so it is refused instead.
func TestCreateCASignedCertificate_RejectsCAOptIn(t *testing.T) {
	caCertID := uuid.New()
	svc := newCertSvc(&mockCertRepository{}, &mockKeyRepo{})

	_, err := svc.CreateCASignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "intermediate",
		KeyID:        uuid.New(),
		ValidityDays: 365,
		UserID:       uuid.New(),
		CACertID:     &caCertID,
		IsCA:         true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "intermediate CA certificates are not supported")
}

// renewalFixture wires a renewal over a certificate whose stored body was
// issued with a known CA status.
type renewalFixture struct {
	svc     CertificateService
	scope   model.Scope
	certID  uuid.UUID
	capture *certCapture
}

func newRenewalFixture(t *testing.T, storedIsCA bool) *renewalFixture {
	t.Helper()
	setupMasterKey()

	userID := uuid.New()
	vaultID := uuid.New()
	certID := uuid.New()
	keyID := uuid.New()

	privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	encryptedKey, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	storedPEM, err := crypto.CreateSelfSignedCertificatePEM(privateKeyPEM, model.KeyTypeRSA, crypto.CertificateTemplate{
		CommonName:   "renew-me",
		ValidityDays: 365,
		IsCA:         storedIsCA,
	})
	require.NoError(t, err)

	scope := model.NewVaultScope(vaultID, userID)
	original := &model.Certificate{
		ID:          certID,
		UserID:      userID,
		VaultID:     vaultID,
		KeyID:       keyID,
		Name:        "renew-me",
		Certificate: storedPEM,
		PrivateKey:  encryptedKey,
		CreatedAt:   time.Now().Add(-300 * 24 * time.Hour),
		Enabled:     true,
		RenewalDays: 30,
	}

	certRepo := &mockCertRepository{}
	keyRepo := &mockKeyRepo{}

	certRepo.On("Read", mock.Anything, certID, scope).Return(original, nil)
	keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID:     keyID,
		UserID: userID,
		Type:   model.KeyTypeRSA,
		Value:  encryptedKey,
	}, nil)

	capture := &certCapture{}
	certRepo.On("Update", mock.Anything, mock.AnythingOfType("*model.Certificate"), scope).
		Run(func(args mock.Arguments) { capture.cert = args.Get(1).(*model.Certificate) }).
		Return(nil)

	return &renewalFixture{
		svc:     newCertSvc(certRepo, keyRepo),
		scope:   scope,
		certID:  certID,
		capture: capture,
	}
}

// Renewal must not promote a leaf to a CA. The renewal call site hardcoded
// IsCA: true, so the first renewal turned any certificate into a CA (B44).
func TestRenewCertificate_PreservesNonCA(t *testing.T) {
	f := newRenewalFixture(t, false)

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	assert.False(t, parseIssuedCert(t, f.capture.cert.Certificate).IsCA,
		"renewing a leaf must not turn it into a CA")
}

// The other direction matters just as much: renewal must not strip the CA bit
// from a real CA, or every CA this system issued would break the first time it
// renewed. Renewal preserves; it does not choose.
func TestRenewCertificate_PreservesCA(t *testing.T) {
	f := newRenewalFixture(t, true)

	_, err := f.svc.RenewCertificate(context.Background(), f.certID, f.scope, 365)
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	assert.True(t, parseIssuedCert(t, f.capture.cert.Certificate).IsCA,
		"renewing a CA must keep it a CA")
}

// The opt-in must produce a certificate that can actually sign. IsCA alone is
// only half a CA: without CertSign no verifier will accept anything it signs,
// which was B43. This is the assertion that ties the two fixes together.
func TestCreateSelfSignedCertificate_CAOptInCarriesCertSign(t *testing.T) {
	f := newSelfSignedFixture(t)

	_, err := f.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "issuing-ca",
		KeyID:        f.keyID,
		ValidityDays: 3650,
		UserID:       f.userID,
		IsCA:         true,
	})
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	issued := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.True(t, issued.IsCA, "the opt-in must produce a CA certificate")
	assert.NotZero(t, issued.KeyUsage&x509.KeyUsageCertSign, "a CA must be allowed to sign certificates")
	assert.NotZero(t, issued.KeyUsage&x509.KeyUsageCRLSign, "a CA must be allowed to sign CRLs")
}

// And the mirror. This is the assertion that would have caught landing B43's
// fix while B44 stood: an ordinary certificate must gain no signing authority
// from it.
func TestCreateSelfSignedCertificate_LeafGetsNoCertSign(t *testing.T) {
	f := newSelfSignedFixture(t)

	_, err := f.svc.CreateSelfSignedCertificate(context.Background(), CreateCertificateRequest{
		Name:         "tls-server",
		KeyID:        f.keyID,
		ValidityDays: 365,
		UserID:       f.userID,
	})
	require.NoError(t, err)
	require.NotNil(t, f.capture.cert)

	issued := parseIssuedCert(t, f.capture.cert.Certificate)
	assert.False(t, issued.IsCA)
	assert.Zero(t, issued.KeyUsage&x509.KeyUsageCertSign, "an ordinary certificate must not be able to sign certificates")
	assert.Zero(t, issued.KeyUsage&x509.KeyUsageCRLSign, "an ordinary certificate must not be able to sign CRLs")
}

// certificateIsCA's parse-failure branches are fail-closed: renewal aborts
// rather than guessing a CA status for a certificate it cannot read. That
// behaviour has no lock on it -- a future "cleanup" turning either branch into
// `return false, nil` would silently strip the CA bit off every real CA on
// its first renewal, with the rest of the suite still green. This pins both
// of certificateIsCA's two distinct failure paths: pem.Decode rejecting the
// stored bytes outright, and x509.ParseCertificate rejecting a
// syntactically valid PEM block whose DER body isn't a certificate.
func TestRenewCertificate_UnparsableCertificateAbortsWithoutIssuing(t *testing.T) {
	garbageDERPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not a valid DER-encoded certificate"),
	}))

	tests := []struct {
		name         string
		storedCert   string
		wantErrorMsg string
	}{
		{
			name:         "not PEM at all",
			storedCert:   "not a valid PEM certificate",
			wantErrorMsg: "renewal must abort when the stored certificate cannot be PEM-decoded",
		},
		{
			name:         "valid PEM block, unparsable DER",
			storedCert:   garbageDERPEM,
			wantErrorMsg: "renewal must abort when the stored certificate's DER body cannot be parsed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupMasterKey()

			userID := uuid.New()
			vaultID := uuid.New()
			certID := uuid.New()
			keyID := uuid.New()

			privateKeyPEM, err := crypto.GenerateRSAKeyPEM(2048)
			require.NoError(t, err)
			encryptedKey, err := common.EncryptSecret(privateKeyPEM)
			require.NoError(t, err)

			scope := model.NewVaultScope(vaultID, userID)
			original := &model.Certificate{
				ID:          certID,
				UserID:      userID,
				VaultID:     vaultID,
				KeyID:       keyID,
				Name:        "renew-me",
				Certificate: tt.storedCert,
				PrivateKey:  encryptedKey,
				CreatedAt:   time.Now().Add(-300 * 24 * time.Hour),
				Enabled:     true,
				RenewalDays: 30,
			}

			certRepo := &mockCertRepository{}
			keyRepo := &mockKeyRepo{}

			certRepo.On("Read", mock.Anything, certID, scope).Return(original, nil)
			keyRepo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
				ID:     keyID,
				UserID: userID,
				Type:   model.KeyTypeRSA,
				Value:  encryptedKey,
			}, nil)
			// No certRepo.On("Update", ...) stub: renewal must abort before it
			// would ever call Update. The hand-written mocks in this package
			// panic on an unexpected call rather than failing just the one
			// test, so an unintended Update call here fails loudly instead of
			// quietly.

			svc := newCertSvc(certRepo, keyRepo)

			_, err = svc.RenewCertificate(context.Background(), certID, scope, 365)
			require.Error(t, err, tt.wantErrorMsg)

			certRepo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
