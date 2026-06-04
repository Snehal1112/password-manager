package certificates

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// TestMain registers every Init function exactly once (covering those
// registration code paths) and then runs all tests in the package.
func TestMain(m *testing.M) {
	parent := &cobra.Command{Use: "certs"}
	InitCertificatesCreate(parent)
	InitCertificatesDelete(parent)
	InitCertificatesGet(parent)
	InitCertificatesList(parent)
	InitCertificatesRenew(parent)
	InitCertificatesUpdate(parent)
	os.Exit(m.Run())
}

// ---- mock certificate service ----

type certCmdCertService struct{ mock.Mock }

func (m *certCmdCertService) CreateSelfSignedCertificate(ctx context.Context, req certServices.CreateCertificateRequest) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}

func (m *certCmdCertService) CreateCASignedCertificate(ctx context.Context, req certServices.CreateCertificateRequest) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}

func (m *certCmdCertService) GetCertificate(ctx context.Context, certID, userID uuid.UUID) (*model.Certificate, error) {
	args := m.Called(ctx, certID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Certificate), args.Error(1)
}

func (m *certCmdCertService) ListCertificates(ctx context.Context, userID uuid.UUID) ([]model.Certificate, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Certificate), args.Error(1)
}

func (m *certCmdCertService) UpdateCertificate(ctx context.Context, req certServices.UpdateCertificateRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *certCmdCertService) DeleteCertificate(ctx context.Context, certID, userID uuid.UUID) error {
	args := m.Called(ctx, certID, userID)
	return args.Error(0)
}

func (m *certCmdCertService) GetCertificateInVault(ctx context.Context, certID, vaultID uuid.UUID) (*model.Certificate, error) {
	return nil, nil
}

func (m *certCmdCertService) ListCertificatesInVault(ctx context.Context, vaultID uuid.UUID) ([]model.Certificate, error) {
	return nil, nil
}

func (m *certCmdCertService) DeleteCertificateInVault(ctx context.Context, certID, vaultID uuid.UUID) error {
	return nil
}

func (m *certCmdCertService) RenewCertificate(ctx context.Context, certID, userID uuid.UUID, validityDays int) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, certID, userID, validityDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}

func (m *certCmdCertService) ValidateCertificateAccess(ctx context.Context, certID, userID uuid.UUID, role string) error {
	return nil
}

func (m *certCmdCertService) ValidateKeyOwnership(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	return nil
}

// ---- container wrapper ----

// certsTestContainer wraps MockServiceContainer and overrides GetCertificateService.
type certsTestContainer struct {
	*testutils.MockServiceContainer
	certSvc certServices.CertificateService
}

func (c *certsTestContainer) GetCertificateService() certServices.CertificateService {
	return c.certSvc
}

// ---- context/helper factories ----

func newCertLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func newCertFmtr() formatter.Formatter {
	f, _ := formatter.New(formatter.FormatTable)
	return f
}

// buildCertAdminCtx creates a context carrying admin claims, a logger, the
// given service container, and an output formatter.
func buildCertAdminCtx(sc interface{}) context.Context {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Username: "admin", Role: model.RoleAdmin}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())
	return ctx
}

// buildCertRoleCtx creates a context with the specified role.
func buildCertRoleCtx(sc interface{}, role string) context.Context {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Username: "user", Role: role}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())
	return ctx
}

// viperSetCert sets viper values and returns a cleanup function.
func viperSetCert(kvs map[string]interface{}) func() {
	for k, v := range kvs {
		viper.Set(k, v)
	}
	return func() {
		for k := range kvs {
			viper.Set(k, nil)
		}
	}
}

// newCertCmd creates a minimal test command that delegates to the given RunE
// and captures output in a buffer.
func newCertCmd(runE func(*cobra.Command, []string) error, args []string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "test", RunE: runE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	return cmd, &buf
}

// ========== createCmd tests ==========

func TestCertCreateCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertCreateCmd_ForbiddenRole(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertRoleCtx(sc, model.RoleUser)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name": "mycert", "cert-key-id": uuid.New().String(), "cert-validity-days": 365,
	})
	defer cleanup()
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCertCreateCmd_NoServiceContainer(t *testing.T) {
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name": "mycert", "cert-key-id": uuid.New().String(), "cert-validity-days": 365,
	})
	defer cleanup()
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No ServiceContainerKey in context.
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertCreateCmd_MissingName(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name": "", "cert-key-id": uuid.New().String(), "cert-validity-days": 365,
	})
	defer cleanup()
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name, key-id, and validity-days are required")
}

func TestCertCreateCmd_MissingKeyID(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name": "mycert", "cert-key-id": "", "cert-validity-days": 365,
	})
	defer cleanup()
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name, key-id, and validity-days are required")
}

func TestCertCreateCmd_InvalidValidityDays(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name": "mycert", "cert-key-id": uuid.New().String(), "cert-validity-days": 0,
	})
	defer cleanup()
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "name, key-id, and validity-days are required")
}

func TestCertCreateCmd_InvalidKeyIDUUID(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name": "mycert", "cert-key-id": "not-a-uuid", "cert-validity-days": 365,
	})
	defer cleanup()
	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

func TestCertCreateCmd_SelfSignedSuccess(t *testing.T) {
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	result := &certServices.CreateCertificateResult{
		CertID:    uuid.New(),
		Name:      "mycert",
		Tags:      []string{"prod"},
		CreatedAt: time.Now(),
	}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.Name == "mycert" && r.KeyID == keyID && r.ValidityDays == 365
	})).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name":         "mycert",
		"cert-key-id":       keyID.String(),
		"cert-validity-days": 365,
		"cert-tags":         "prod",
		"cert-ca-cert-id":   "",
	})
	defer cleanup()

	cmd, buf := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_CASignedSuccess(t *testing.T) {
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	caCertID := uuid.New()
	result := &certServices.CreateCertificateResult{
		CertID:    uuid.New(),
		Name:      "casignedcert",
		CreatedAt: time.Now(),
	}
	certSvc.On("CreateCASignedCertificate", mock.Anything, mock.MatchedBy(func(r certServices.CreateCertificateRequest) bool {
		return r.Name == "casignedcert" && r.KeyID == keyID && r.CACertID != nil && *r.CACertID == caCertID
	})).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name":         "casignedcert",
		"cert-key-id":       keyID.String(),
		"cert-validity-days": 180,
		"cert-tags":         "",
		"cert-ca-cert-id":   caCertID.String(),
	})
	defer cleanup()

	cmd, buf := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_InvalidCACertID(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name":         "mycert",
		"cert-key-id":       uuid.New().String(),
		"cert-validity-days": 365,
		"cert-tags":         "",
		"cert-ca-cert-id":   "bad-uuid",
	})
	defer cleanup()

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid CA certificate ID")
}

func TestCertCreateCmd_ServiceError(t *testing.T) {
	certSvc := &certCmdCertService{}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("db error"))

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	ctx := buildCertAdminCtx(sc)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name":         "failcert",
		"cert-key-id":       uuid.New().String(),
		"cert-validity-days": 365,
		"cert-tags":         "",
		"cert-ca-cert-id":   "",
	})
	defer cleanup()

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create certificate")
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_NoFormatter(t *testing.T) {
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	result := &certServices.CreateCertificateResult{CertID: uuid.New(), Name: "k", CreatedAt: time.Now()}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	// Build context WITHOUT formatter.
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{
		"cert-name":         "k",
		"cert-key-id":       keyID.String(),
		"cert-validity-days": 365,
		"cert-tags":         "",
		"cert-ca-cert-id":   "",
	})
	defer cleanup()

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	certSvc.AssertExpectations(t)
}

func TestCertCreateCmd_CertificateManagerRoleAllowed(t *testing.T) {
	certSvc := &certCmdCertService{}
	keyID := uuid.New()
	result := &certServices.CreateCertificateResult{CertID: uuid.New(), Name: "cert", CreatedAt: time.Now()}
	certSvc.On("CreateSelfSignedCertificate", mock.Anything, mock.Anything).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	ctx := buildCertRoleCtx(sc, model.RoleCertificateManager)
	cleanup := viperSetCert(map[string]interface{}{
		"cert-name":         "cert",
		"cert-key-id":       keyID.String(),
		"cert-validity-days": 365,
		"cert-tags":         "",
		"cert-ca-cert-id":   "",
	})
	defer cleanup()

	cmd, _ := newCertCmd(createCmd.RunE, nil)
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 30, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

// ========== deleteCmd tests ==========

func TestCertDeleteCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(deleteCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertDeleteCmd_ForbiddenRole(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertRoleCtx(sc, model.RoleUser)
	cmd, _ := newCertCmd(deleteCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCertDeleteCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertCmd(deleteCmd.RunE, []string{"not-a-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertDeleteCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No service container.
	cmd, _ := newCertCmd(deleteCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertDeleteCmd_Success(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	certSvc.On("DeleteCertificate", mock.Anything, certID, userID).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(deleteCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertDeleteCmd_ServiceError(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	certSvc.On("DeleteCertificate", mock.Anything, certID, userID).Return(fmt.Errorf("delete failed"))

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(deleteCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete certificate")
	certSvc.AssertExpectations(t)
}

// ========== getCmd tests ==========

func TestCertGetCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(getCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertGetCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertCmd(getCmd.RunE, []string{"bad-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertGetCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No service container.
	cmd, _ := newCertCmd(getCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertGetCmd_Success(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	cert := &model.Certificate{
		ID: certID, UserID: userID, Name: "mycert",
		Tags: []string{"ssl"}, CreatedAt: time.Now(), ExpiresAt: &expiresAt,
		AutoRenew: true, Enabled: true,
	}
	certSvc.On("GetCertificate", mock.Anything, certID, userID).Return(cert, nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, buf := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func TestCertGetCmd_ServiceError(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	certSvc.On("GetCertificate", mock.Anything, certID, userID).Return(nil, fmt.Errorf("not found"))

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to get certificate")
	certSvc.AssertExpectations(t)
}

func TestCertGetCmd_NoFormatter(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	cert := &model.Certificate{
		ID: certID, UserID: userID, Name: "k",
		CreatedAt: time.Now(), Enabled: true,
	}
	certSvc.On("GetCertificate", mock.Anything, certID, userID).Return(cert, nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No formatter.

	cmd, _ := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	certSvc.AssertExpectations(t)
}

// ========== listCmd tests ==========

func TestCertListCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertListCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No service container.
	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertListCmd_SuccessTwoCerts(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certs := []model.Certificate{
		{ID: uuid.New(), UserID: userID, Name: "cert1", CreatedAt: time.Now(), Enabled: true},
		{ID: uuid.New(), UserID: userID, Name: "cert2", CreatedAt: time.Now(), Enabled: true},
	}
	certSvc.On("ListCertificates", mock.Anything, userID).Return(certs, nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, buf := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func TestCertListCmd_EmptyList(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certSvc.On("ListCertificates", mock.Anything, userID).Return([]model.Certificate{}, nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleUser}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertListCmd_ServiceError(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certSvc.On("ListCertificates", mock.Anything, userID).Return(nil, fmt.Errorf("db error"))

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleSecretsManager}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list certificates")
	certSvc.AssertExpectations(t)
}

func TestCertListCmd_NoFormatter(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certSvc.On("ListCertificates", mock.Anything, userID).Return([]model.Certificate{}, nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleUser}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No formatter.

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	certSvc.AssertExpectations(t)
}

// ========== renewCmd tests ==========

func TestCertRenewCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(renewCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertRenewCmd_ForbiddenRole(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertRoleCtx(sc, model.RoleUser)
	cmd, _ := newCertCmd(renewCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCertRenewCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cleanup := viperSetCert(map[string]interface{}{"cert-renew-validity-days": 365})
	defer cleanup()
	cmd, _ := newCertCmd(renewCmd.RunE, []string{"not-a-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertRenewCmd_InvalidValidityDays(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cleanup := viperSetCert(map[string]interface{}{"cert-renew-validity-days": 0})
	defer cleanup()
	cmd, _ := newCertCmd(renewCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "validity-days must be greater than 0")
}

func TestCertRenewCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No service container.
	cleanup := viperSetCert(map[string]interface{}{"cert-renew-validity-days": 365})
	defer cleanup()
	cmd, _ := newCertCmd(renewCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertRenewCmd_Success(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	result := &certServices.CreateCertificateResult{
		CertID:    uuid.New(),
		Name:      "renewed",
		CreatedAt: time.Now(),
	}
	certSvc.On("RenewCertificate", mock.Anything, certID, userID, 365).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-renew-validity-days": 365})
	defer cleanup()

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertRenewCmd_ServiceError(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	certSvc.On("RenewCertificate", mock.Anything, certID, userID, 180).Return(nil, fmt.Errorf("renew failed"))

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-renew-validity-days": 180})
	defer cleanup()

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to renew certificate")
	certSvc.AssertExpectations(t)
}

// ========== updateCmd tests ==========

func TestCertUpdateCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertCmd(updateCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertUpdateCmd_ForbiddenRole(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertRoleCtx(sc, model.RoleUser)
	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "n", "cert-update-tags": ""})
	defer cleanup()
	cmd, _ := newCertCmd(updateCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCertUpdateCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "", "cert-update-tags": ""})
	defer cleanup()
	cmd, _ := newCertCmd(updateCmd.RunE, []string{"not-a-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertUpdateCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	// No service container.
	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "n", "cert-update-tags": ""})
	defer cleanup()
	cmd, _ := newCertCmd(updateCmd.RunE, []string{uuid.New().String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertUpdateCmd_SuccessWithNameUpdate(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.MatchedBy(func(r certServices.UpdateCertificateRequest) bool {
		return r.CertID == certID && r.UserID == userID && r.Name != nil && *r.Name == "newname"
	})).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "newname", "cert-update-tags": ""})
	defer cleanup()

	// Use a fresh command with args so viper picks up the name correctly.
	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertUpdateCmd_SuccessWithAutoRenewFlagChanged(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.MatchedBy(func(r certServices.UpdateCertificateRequest) bool {
		return r.CertID == certID && r.AutoRenew != nil && *r.AutoRenew == true
	})).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "", "cert-update-tags": ""})
	defer cleanup()

	// Register flags and set args so that --auto-renew is marked Changed.
	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String(), "--auto-renew=true"})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertUpdateCmd_SuccessWithRenewalDaysFlagChanged(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.MatchedBy(func(r certServices.UpdateCertificateRequest) bool {
		return r.CertID == certID && r.RenewalDays != nil && *r.RenewalDays == 60
	})).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "", "cert-update-tags": ""})
	defer cleanup()

	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String(), "--renewal-days=60"})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertUpdateCmd_ServiceError(t *testing.T) {
	certSvc := &certCmdCertService{}
	userID := uuid.New()
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.Anything).Return(fmt.Errorf("update failed"))

	sc := &certsTestContainer{
		MockServiceContainer: &testutils.MockServiceContainer{},
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "n", "cert-update-tags": ""})
	defer cleanup()

	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to update certificate")
	certSvc.AssertExpectations(t)
}

// ========== formatOptionalTime tests ==========

func TestFormatOptionalTime_Nil(t *testing.T) {
	result := formatOptionalTime(nil)
	assert.Equal(t, "", result)
}

func TestFormatOptionalTime_NonNil(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	result := formatOptionalTime(&ts)
	assert.Equal(t, ts.Format(time.RFC3339), result)
	assert.Contains(t, result, "2026-01-15")
}
