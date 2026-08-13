package crypto

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/google/uuid"
	p11 "github.com/miekg/pkcs11"
)

// ErrUnsupportedCurve is returned when a curve is valid in software but not
// supported by the PKCS#11 mechanism set (e.g., secp256k1 / P-256K).
var ErrUnsupportedCurve = errors.New("curve not supported by PKCS#11 provider")

// ErrUnsupportedAlgorithm is returned when a crypto algorithm is valid for the
// software provider but not routed through PKCS#11 (e.g., AES-GCM key ops).
var ErrUnsupportedAlgorithm = errors.New("algorithm not supported by PKCS#11 provider")

// PKCS11Config holds the runtime configuration for PKCS11KeyProvider.
type PKCS11Config struct {
	// LibPath is the absolute path to the PKCS#11 shared library.
	LibPath string

	// TokenLabel is the CKA_LABEL of the token to use.
	TokenLabel string

	// PIN is the user PIN for the token.
	PIN string

	// SlotID is the explicit slot index. 0 means auto-detect by TokenLabel.
	SlotID uint
}

// PKCS11KeyProvider implements KeyProvider by delegating all key operations
// to a PKCS#11 token. Private key material never enters Go memory.
type PKCS11KeyProvider struct {
	ctx    *p11.Ctx
	cfg    PKCS11Config
	slotID uint
}

// NewPKCS11KeyProvider initialises a PKCS#11 context, locates the token, and
// opens a connection. Call Close() when the provider is no longer needed.
func NewPKCS11KeyProvider(cfg PKCS11Config) (*PKCS11KeyProvider, error) {
	ctx := p11.New(cfg.LibPath)
	if err := ctx.Initialize(); err != nil {
		// CKR_CRYPTOKI_ALREADY_INITIALIZED (0x191) means another process in this
		// address space already called C_Initialize — safe to continue.
		if err.Error() != "pkcs11: 0x191: CKR_CRYPTOKI_ALREADY_INITIALIZED" {
			return nil, fmt.Errorf("pkcs11 initialize: %w", err)
		}
	}

	slotID, err := findSlot(ctx, cfg)
	if err != nil {
		ctx.Destroy()
		return nil, err
	}

	return &PKCS11KeyProvider{
		ctx:    ctx,
		cfg:    cfg,
		slotID: slotID,
	}, nil
}

// findSlot locates the PKCS#11 slot that holds the configured token.
func findSlot(ctx *p11.Ctx, cfg PKCS11Config) (uint, error) {
	if cfg.SlotID > 0 {
		return cfg.SlotID, nil
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 get slot list: %w", err)
	}

	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if trimPKCS11String(info.Label) == cfg.TokenLabel {
			return slot, nil
		}
	}

	return 0, fmt.Errorf("pkcs11: token with label %q not found", cfg.TokenLabel)
}

// trimPKCS11String removes trailing space padding from PKCS#11 string fields.
func trimPKCS11String(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != ' ' {
			return s[:i+1]
		}
	}
	return ""
}

// openRWSession opens a read-write user session on the configured slot.
func (p *PKCS11KeyProvider) openRWSession() (p11.SessionHandle, error) {
	session, err := p.ctx.OpenSession(p.slotID, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 open session: %w", err)
	}
	if err := p.ctx.Login(session, p11.CKU_USER, p.cfg.PIN); err != nil {
		_ = p.ctx.CloseSession(session)
		return 0, fmt.Errorf("pkcs11 login: %w", err)
	}
	return session, nil
}

// closeSession logs out and closes a session.
func (p *PKCS11KeyProvider) closeSession(session p11.SessionHandle) {
	_ = p.ctx.Logout(session)
	_ = p.ctx.CloseSession(session)
}

// GenerateRSAKey generates an RSA key pair on the token. Returns the
// CKA_LABEL UUID string as the handle.
func (p *PKCS11KeyProvider) GenerateRSAKey(_ context.Context, bits int) (string, error) {
	session, err := p.openRWSession()
	if err != nil {
		return "", err
	}
	defer p.closeSession(session)

	label := uuid.New().String()

	pubAttrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_RSA),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_ENCRYPT, true),
		p11.NewAttribute(p11.CKA_VERIFY, true),
		p11.NewAttribute(p11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		p11.NewAttribute(p11.CKA_MODULUS_BITS, bits),
	}

	privAttrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_RSA),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_PRIVATE, true),
		p11.NewAttribute(p11.CKA_SENSITIVE, true),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
		p11.NewAttribute(p11.CKA_DECRYPT, true),
		p11.NewAttribute(p11.CKA_SIGN, true),
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	_, _, err = p.ctx.GenerateKeyPair(session, mech, pubAttrs, privAttrs)
	if err != nil {
		return "", fmt.Errorf("pkcs11 rsa key gen: %w", err)
	}

	return label, nil
}

// ecOID maps Go curve names to their DER-encoded ASN.1 OID for PKCS#11
// CKA_EC_PARAMS. secp256k1 is intentionally excluded.
var ecOID = map[string]asn1.ObjectIdentifier{
	"P-256": {1, 2, 840, 10045, 3, 1, 7},
	"P-384": {1, 3, 132, 0, 34},
	"P-521": {1, 3, 132, 0, 35},
}

// GenerateECDSAKey generates an EC key pair on the token. P-256K is not
// supported on PKCS#11 and returns ErrUnsupportedCurve.
func (p *PKCS11KeyProvider) GenerateECDSAKey(_ context.Context, curveName string) (string, error) {
	oid, ok := ecOID[curveName]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedCurve, curveName)
	}

	ecParams, err := asn1.Marshal(oid)
	if err != nil {
		return "", fmt.Errorf("marshal ec params: %w", err)
	}

	session, err := p.openRWSession()
	if err != nil {
		return "", err
	}
	defer p.closeSession(session)

	label := uuid.New().String()

	pubAttrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_VERIFY, true),
		p11.NewAttribute(p11.CKA_EC_PARAMS, ecParams),
	}

	privAttrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_PRIVATE, true),
		p11.NewAttribute(p11.CKA_SENSITIVE, true),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
		p11.NewAttribute(p11.CKA_SIGN, true),
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_EC_KEY_PAIR_GEN, nil)}
	_, _, err = p.ctx.GenerateKeyPair(session, mech, pubAttrs, privAttrs)
	if err != nil {
		return "", fmt.Errorf("pkcs11 ec key gen (%s): %w", curveName, err)
	}

	return label, nil
}

// GenerateAESKey generates a non-extractable AES secret key on the token.
// Returns the CKA_LABEL UUID string as the handle. bits must be 128, 192, or
// 256.
func (p *PKCS11KeyProvider) GenerateAESKey(_ context.Context, bits int) (string, error) {
	if bits != 128 && bits != 192 && bits != 256 {
		return "", fmt.Errorf("%w: AES key size must be 128, 192, or 256 bits", ErrUnsupportedAlgorithm)
	}

	session, err := p.openRWSession()
	if err != nil {
		return "", err
	}
	defer p.closeSession(session)

	label := uuid.New().String()

	attrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_SENSITIVE, true),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
		p11.NewAttribute(p11.CKA_ENCRYPT, true),
		p11.NewAttribute(p11.CKA_DECRYPT, true),
		p11.NewAttribute(p11.CKA_WRAP, true),
		p11.NewAttribute(p11.CKA_UNWRAP, true),
		p11.NewAttribute(p11.CKA_VALUE_LEN, bits/8),
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_GEN, nil)}
	if _, err := p.ctx.GenerateKey(session, mech, attrs); err != nil {
		return "", fmt.Errorf("pkcs11 aes key gen: %w", err)
	}

	return label, nil
}

// findPrivateKey finds the private key object on the token by CKA_LABEL.
func (p *PKCS11KeyProvider) findPrivateKey(session p11.SessionHandle, label string) (p11.ObjectHandle, error) {
	template := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
		p11.NewAttribute(p11.CKA_LABEL, label),
	}
	if err := p.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("pkcs11 find init: %w", err)
	}
	defer func() { _ = p.ctx.FindObjectsFinal(session) }()

	handles, _, err := p.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 find objects: %w", err)
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("pkcs11: private key not found for label %q", label)
	}
	return handles[0], nil
}

// findPublicKey finds the public key object on the token by CKA_LABEL.
func (p *PKCS11KeyProvider) findPublicKey(session p11.SessionHandle, label string) (p11.ObjectHandle, error) {
	template := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_LABEL, label),
	}
	if err := p.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("pkcs11 find init: %w", err)
	}
	defer func() { _ = p.ctx.FindObjectsFinal(session) }()

	handles, _, err := p.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 find objects: %w", err)
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("pkcs11: public key not found for label %q", label)
	}
	return handles[0], nil
}

// findSecretKey finds the AES secret key object on the token by CKA_LABEL.
func (p *PKCS11KeyProvider) findSecretKey(session p11.SessionHandle, label string) (p11.ObjectHandle, error) {
	template := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_LABEL, label),
	}
	if err := p.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("pkcs11 find init: %w", err)
	}
	defer func() { _ = p.ctx.FindObjectsFinal(session) }()

	handles, _, err := p.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("pkcs11 find objects: %w", err)
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("pkcs11: secret key not found for label %q", label)
	}
	return handles[0], nil
}

// isAESKWAlgorithm reports whether algorithm is an AES-KW variant, which maps
// to CKM_AES_KEY_WRAP_PAD against a CKO_SECRET_KEY object rather than the
// RSA-OAEP path against a CKO_PUBLIC_KEY/CKO_PRIVATE_KEY pair.
func isAESKWAlgorithm(algorithm EncryptionAlgorithm) bool {
	switch algorithm {
	case AlgorithmA128KW, AlgorithmA192KW, AlgorithmA256KW:
		return true
	default:
		return false
	}
}

// wrapRawData wraps arbitrary plaintext with wrappingKey using
// CKM_AES_KEY_WRAP_PAD via C_WrapKey. Many PKCS#11 tokens (including
// SoftHSM2) only expose this mechanism through the CKF_WRAP/CKF_UNWRAP
// capability, not CKF_ENCRYPT/CKF_DECRYPT, so C_Encrypt/C_Decrypt fail with
// CKR_MECHANISM_INVALID. To wrap raw data rather than a key object, the
// plaintext is first imported as a temporary, extractable, non-token generic
// secret object and then wrapped as a key.
//
// data is prefixed with its own length as a 4-byte big-endian header before
// wrapping: CKM_AES_KEY_WRAP_PAD only guarantees recovering the plaintext
// rounded up to the next 8-byte block on unwrap (observed against SoftHSM2,
// which does not reconstruct the exact original length from the RFC 5649
// padding metadata for CKK_GENERIC_SECRET targets), so unwrapRawData needs
// this header to trim the trailing zero padding back off.
func (p *PKCS11KeyProvider) wrapRawData(session p11.SessionHandle, wrappingKey p11.ObjectHandle, data []byte) ([]byte, error) {
	framed := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(data)))
	copy(framed[4:], data)

	tempAttrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_GENERIC_SECRET),
		p11.NewAttribute(p11.CKA_TOKEN, false),
		p11.NewAttribute(p11.CKA_SENSITIVE, false),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, true),
		p11.NewAttribute(p11.CKA_VALUE, framed),
	}
	tempObj, err := p.ctx.CreateObject(session, tempAttrs)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 aes-kw create temp object: %w", err)
	}
	defer func() { _ = p.ctx.DestroyObject(session, tempObj) }()

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_WRAP_PAD, nil)}
	wrapped, err := p.ctx.WrapKey(session, mech, wrappingKey, tempObj)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 aes-kw wrap: %w", err)
	}
	return wrapped, nil
}

// unwrapRawData reverses wrapRawData: it unwraps wrapped into a temporary,
// extractable generic secret object with unwrappingKey, reads its CKA_VALUE
// back out, and trims the trailing padding using the 4-byte length header
// wrapRawData prepended.
func (p *PKCS11KeyProvider) unwrapRawData(session p11.SessionHandle, unwrappingKey p11.ObjectHandle, wrapped []byte) ([]byte, error) {
	tempAttrs := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_GENERIC_SECRET),
		p11.NewAttribute(p11.CKA_TOKEN, false),
		p11.NewAttribute(p11.CKA_SENSITIVE, false),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, true),
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_WRAP_PAD, nil)}
	tempObj, err := p.ctx.UnwrapKey(session, mech, unwrappingKey, wrapped, tempAttrs)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 aes-kw unwrap: %w", err)
	}
	defer func() { _ = p.ctx.DestroyObject(session, tempObj) }()

	values, err := p.ctx.GetAttributeValue(session, tempObj, []*p11.Attribute{p11.NewAttribute(p11.CKA_VALUE, nil)})
	if err != nil {
		return nil, fmt.Errorf("pkcs11 aes-kw unwrap get value: %w", err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("pkcs11 aes-kw unwrap: no value returned")
	}

	framed := values[0].Value
	if len(framed) < 4 {
		return nil, fmt.Errorf("pkcs11 aes-kw unwrap: unwrapped value too short to contain length header")
	}
	n := binary.BigEndian.Uint32(framed[:4])
	if uint64(4+n) > uint64(len(framed)) {
		return nil, fmt.Errorf("pkcs11 aes-kw unwrap: length header %d exceeds unwrapped value size %d", n, len(framed)-4)
	}
	return framed[4 : 4+n], nil
}

// signMechanism maps a SignatureAlgorithm to the PKCS#11 mechanism and
// indicates whether the data must be pre-hashed before calling C_Sign.
type signMechanism struct {
	mech    uint
	preHash bool
	// hashAlgo is used to pre-hash data for ECDSA (CKM_ECDSA takes raw digest).
	hashAlgo SignatureAlgorithm
	// mechParams holds required mechanism parameters (e.g. CK_RSA_PKCS_PSS_PARAMS
	// for PSS mechanisms). nil means no params (PKCS#1 v1.5, ECDSA).
	mechParams []byte
}

var signMechanisms = map[SignatureAlgorithm]signMechanism{
	AlgorithmRS256: {p11.CKM_SHA256_RSA_PKCS, false, "", nil},
	AlgorithmRS384: {p11.CKM_SHA384_RSA_PKCS, false, "", nil},
	AlgorithmRS512: {p11.CKM_SHA512_RSA_PKCS, false, "", nil},

	// PSS mechanisms require CK_RSA_PKCS_PSS_PARAMS; salt length = hash length.
	AlgorithmPS256: {p11.CKM_SHA256_RSA_PKCS_PSS, false, "", p11.NewPSSParams(p11.CKM_SHA256, p11.CKG_MGF1_SHA256, 32)},
	AlgorithmPS384: {p11.CKM_SHA384_RSA_PKCS_PSS, false, "", p11.NewPSSParams(p11.CKM_SHA384, p11.CKG_MGF1_SHA384, 48)},
	AlgorithmPS512: {p11.CKM_SHA512_RSA_PKCS_PSS, false, "", p11.NewPSSParams(p11.CKM_SHA512, p11.CKG_MGF1_SHA512, 64)},

	// CKM_ECDSA takes a pre-hashed digest; hash in Go before sending.
	AlgorithmES256: {p11.CKM_ECDSA, true, AlgorithmES256, nil},
	AlgorithmES384: {p11.CKM_ECDSA, true, AlgorithmES384, nil},
	AlgorithmES512: {p11.CKM_ECDSA, true, AlgorithmES512, nil},
}

// Sign signs data with the private key identified by handle (CKA_LABEL).
func (p *PKCS11KeyProvider) Sign(_ context.Context, handle string, _ string, data []byte, algorithm SignatureAlgorithm) ([]byte, error) {
	mechInfo, ok := signMechanisms[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}

	session, err := p.openRWSession()
	if err != nil {
		return nil, err
	}
	defer p.closeSession(session)

	privKey, err := p.findPrivateKey(session, handle)
	if err != nil {
		return nil, err
	}

	input := data
	if mechInfo.preHash {
		h, herr := p11GetHasher(mechInfo.hashAlgo)
		if herr != nil {
			return nil, herr
		}
		h.Write(data)
		input = h.Sum(nil)
	}

	mech := []*p11.Mechanism{p11.NewMechanism(mechInfo.mech, mechInfo.mechParams)}
	if err := p.ctx.SignInit(session, mech, privKey); err != nil {
		return nil, fmt.Errorf("pkcs11 sign init: %w", err)
	}

	sig, err := p.ctx.Sign(session, input)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 sign: %w", err)
	}

	return sig, nil
}

// Verify verifies a signature using the public key identified by handle.
func (p *PKCS11KeyProvider) Verify(_ context.Context, handle string, _ string, data []byte, sig []byte, algorithm SignatureAlgorithm) (bool, error) {
	mechInfo, ok := signMechanisms[algorithm]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}

	session, err := p.openRWSession()
	if err != nil {
		return false, err
	}
	defer p.closeSession(session)

	pubKey, err := p.findPublicKey(session, handle)
	if err != nil {
		return false, err
	}

	input := data
	if mechInfo.preHash {
		h, herr := p11GetHasher(mechInfo.hashAlgo)
		if herr != nil {
			return false, herr
		}
		h.Write(data)
		input = h.Sum(nil)
	}

	mech := []*p11.Mechanism{p11.NewMechanism(mechInfo.mech, mechInfo.mechParams)}
	if err := p.ctx.VerifyInit(session, mech, pubKey); err != nil {
		return false, fmt.Errorf("pkcs11 verify init: %w", err)
	}

	if err := p.ctx.Verify(session, input, sig); err != nil {
		if isSignatureInvalid(err) {
			return false, nil
		}
		return false, fmt.Errorf("pkcs11 verify: %w", err)
	}

	return true, nil
}

// isSignatureInvalid returns true when the PKCS#11 error indicates an invalid
// signature rather than a system error.
func isSignatureInvalid(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return s == "pkcs11: 0xC0: CKR_SIGNATURE_INVALID" ||
		s == "pkcs11: 0xC1: CKR_SIGNATURE_LEN_RANGE"
}

// Encrypt performs RSA-OAEP encryption with the token's RSA public key, or
// AES-KW wrapping with the token's AES secret key, depending on algorithm.
func (p *PKCS11KeyProvider) Encrypt(_ context.Context, handle string, data []byte, algorithm EncryptionAlgorithm) ([]byte, []byte, error) {
	session, err := p.openRWSession()
	if err != nil {
		return nil, nil, err
	}
	defer p.closeSession(session)

	if isAESKWAlgorithm(algorithm) {
		key, err := p.findSecretKey(session, handle)
		if err != nil {
			return nil, nil, err
		}

		ct, err := p.wrapRawData(session, key, data)
		if err != nil {
			return nil, nil, err
		}
		// AES-KW does not use a nonce.
		return ct, nil, nil
	}

	oaepParams, err := oaepMechParams(algorithm)
	if err != nil {
		return nil, nil, err
	}

	pubKey, err := p.findPublicKey(session, handle)
	if err != nil {
		return nil, nil, err
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_RSA_PKCS_OAEP, oaepParams)}
	if err := p.ctx.EncryptInit(session, mech, pubKey); err != nil {
		return nil, nil, fmt.Errorf("pkcs11 encrypt init: %w", err)
	}

	ct, err := p.ctx.Encrypt(session, data)
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs11 encrypt: %w", err)
	}

	// RSA-OAEP does not use a nonce.
	return ct, nil, nil
}

// Decrypt performs RSA-OAEP decryption with the token's RSA private key, or
// AES-KW unwrapping with the token's AES secret key, depending on algorithm.
func (p *PKCS11KeyProvider) Decrypt(_ context.Context, handle string, data []byte, _ []byte, algorithm EncryptionAlgorithm) ([]byte, error) {
	session, err := p.openRWSession()
	if err != nil {
		return nil, err
	}
	defer p.closeSession(session)

	if isAESKWAlgorithm(algorithm) {
		key, err := p.findSecretKey(session, handle)
		if err != nil {
			return nil, err
		}

		return p.unwrapRawData(session, key, data)
	}

	oaepParams, err := oaepMechParams(algorithm)
	if err != nil {
		return nil, err
	}

	privKey, err := p.findPrivateKey(session, handle)
	if err != nil {
		return nil, err
	}

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_RSA_PKCS_OAEP, oaepParams)}
	if err := p.ctx.DecryptInit(session, mech, privKey); err != nil {
		return nil, fmt.Errorf("pkcs11 decrypt init: %w", err)
	}

	pt, err := p.ctx.Decrypt(session, data)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 decrypt: %w", err)
	}

	return pt, nil
}

// oaepMechParams returns the OAEPParams for the given algorithm.
func oaepMechParams(algorithm EncryptionAlgorithm) (*p11.OAEPParams, error) {
	switch algorithm {
	case AlgorithmRSAOAEP:
		return p11.NewOAEPParams(p11.CKM_SHA_1, p11.CKG_MGF1_SHA1, p11.CKZ_DATA_SPECIFIED, nil), nil
	case AlgorithmRSAOAEP256:
		return p11.NewOAEPParams(p11.CKM_SHA256, p11.CKG_MGF1_SHA256, p11.CKZ_DATA_SPECIFIED, nil), nil
	default:
		return nil, fmt.Errorf("%w: %s (use software provider for AES operations)", ErrUnsupportedAlgorithm, algorithm)
	}
}

// Close finalises the PKCS#11 context and releases the library handle.
func (p *PKCS11KeyProvider) Close() error {
	return p.ctx.Finalize()
}

// p11GetHasher returns a hash.Hash for pre-hashing ECDSA data before C_Sign.
// It reuses the SignatureAlgorithm → hash mapping from crypto_operations.go.
func p11GetHasher(algorithm SignatureAlgorithm) (hash.Hash, error) {
	return getHasher(algorithm)
}
