package crypto

import (
	"errors"
	"fmt"
	"testing"

	p11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
)

func TestIsHSMCapabilityError_CurveNotSupported(t *testing.T) {
	err := fmt.Errorf("pkcs11 ec key gen (P-256K): %w", p11.Error(0x140)) // CKR_CURVE_NOT_SUPPORTED
	assert.True(t, isHSMCapabilityError(err))
}

func TestIsHSMCapabilityError_DomainParamsInvalid(t *testing.T) {
	err := fmt.Errorf("pkcs11 ec key gen (P-256K): %w", p11.Error(0x130)) // CKR_DOMAIN_PARAMS_INVALID
	assert.True(t, isHSMCapabilityError(err))
}

func TestIsHSMCapabilityError_MechanismInvalid(t *testing.T) {
	err := fmt.Errorf("pkcs11 encrypt init: %w", p11.Error(0x70)) // CKR_MECHANISM_INVALID
	assert.True(t, isHSMCapabilityError(err))
}

func TestIsHSMCapabilityError_MechanismParamInvalid(t *testing.T) {
	err := fmt.Errorf("pkcs11 encrypt init: %w", p11.Error(0x71)) // CKR_MECHANISM_PARAM_INVALID
	assert.True(t, isHSMCapabilityError(err))
}

func TestIsHSMCapabilityError_UnrelatedPKCS11Error_ReturnsFalse(t *testing.T) {
	err := fmt.Errorf("pkcs11 sign: %w", p11.Error(0x05)) // CKR_GENERAL_ERROR
	assert.False(t, isHSMCapabilityError(err))
}

func TestIsHSMCapabilityError_NonPKCS11Error_ReturnsFalse(t *testing.T) {
	assert.False(t, isHSMCapabilityError(errors.New("connection refused")))
}

func TestIsHSMCapabilityError_Nil_ReturnsFalse(t *testing.T) {
	assert.False(t, isHSMCapabilityError(nil))
}

// ─── isHSMImportRejectionError ─────────────────────────────────────────────
//
// Mirrors the isHSMCapabilityError tests above, against the separate CKR_*
// code set a token uses to reject a C_CreateObject import rather than a
// C_GenerateKeyPair curve/mechanism request. This is the fix for
// PKCS11KeyProvider.ImportKey leaking a raw backend error as a 500 instead of
// a clean 400 when a token (e.g. a FIPS-mode HSM) refuses to import
// externally-supplied key material.

func TestIsHSMImportRejectionError_AttributeValueInvalid(t *testing.T) {
	err := fmt.Errorf("pkcs11 rsa import (private): %w", p11.Error(0x13)) // CKR_ATTRIBUTE_VALUE_INVALID
	assert.True(t, isHSMImportRejectionError(err))
}

func TestIsHSMImportRejectionError_TemplateIncomplete(t *testing.T) {
	err := fmt.Errorf("pkcs11 rsa import (private): %w", p11.Error(0xD0)) // CKR_TEMPLATE_INCOMPLETE
	assert.True(t, isHSMImportRejectionError(err))
}

func TestIsHSMImportRejectionError_TemplateInconsistent(t *testing.T) {
	err := fmt.Errorf("pkcs11 ecdsa import (private): %w", p11.Error(0xD1)) // CKR_TEMPLATE_INCONSISTENT
	assert.True(t, isHSMImportRejectionError(err))
}

func TestIsHSMImportRejectionError_ActionProhibited(t *testing.T) {
	err := fmt.Errorf("pkcs11 rsa import (private): %w", p11.Error(0x1B)) // CKR_ACTION_PROHIBITED
	assert.True(t, isHSMImportRejectionError(err))
}

func TestIsHSMImportRejectionError_FunctionNotSupported(t *testing.T) {
	err := fmt.Errorf("pkcs11 ecdsa import (private): %w", p11.Error(0x54)) // CKR_FUNCTION_NOT_SUPPORTED
	assert.True(t, isHSMImportRejectionError(err))
}

func TestIsHSMImportRejectionError_UnrelatedPKCS11Error_ReturnsFalse(t *testing.T) {
	err := fmt.Errorf("pkcs11 rsa import (private): %w", p11.Error(0x05)) // CKR_GENERAL_ERROR
	assert.False(t, isHSMImportRejectionError(err))
}

func TestIsHSMImportRejectionError_NonPKCS11Error_ReturnsFalse(t *testing.T) {
	assert.False(t, isHSMImportRejectionError(errors.New("connection refused")))
}

func TestIsHSMImportRejectionError_Nil_ReturnsFalse(t *testing.T) {
	assert.False(t, isHSMImportRejectionError(nil))
}

// TestIsHSMImportRejectionError_CurveNotSupported_ReturnsFalse pins that the
// two code sets are genuinely disjoint: a curve/mechanism rejection (handled
// by isHSMCapabilityError, exercised at GenerateECDSAKey) must not also be
// treated as an import rejection, and vice versa -- each helper's codes are
// meaningful only for the operation it guards.
func TestIsHSMImportRejectionError_CurveNotSupported_ReturnsFalse(t *testing.T) {
	err := fmt.Errorf("pkcs11 ec key gen (P-256K): %w", p11.Error(0x140)) // CKR_CURVE_NOT_SUPPORTED
	assert.False(t, isHSMImportRejectionError(err))
}
