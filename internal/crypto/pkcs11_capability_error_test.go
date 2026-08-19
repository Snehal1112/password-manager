package crypto

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	p11 "github.com/miekg/pkcs11"
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
