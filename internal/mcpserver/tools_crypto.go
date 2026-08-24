package mcpserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type signArgs struct {
	KeyName    string `json:"key_name" jsonschema:"the signing key's name, or its id"`
	DataBase64 string `json:"data_base64" jsonschema:"the data to sign, base64-encoded"`
	Algorithm  string `json:"algorithm,omitempty" jsonschema:"RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384 or ES512; defaults to RS256"`
	Version    int    `json:"version,omitempty" jsonschema:"a specific key version; omit to use the current one"`
	Vault      string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type signResult struct {
	Vault           string `json:"vault"`
	KeyName         string `json:"key_name"`
	Algorithm       string `json:"algorithm"`
	SignatureBase64 string `json:"signature_base64"`
	// Version records which key version signed, which is what verifying
	// later requires after a rotation.
	Version int `json:"version"`
}

type verifyArgs struct {
	KeyName         string `json:"key_name" jsonschema:"the key's name, or its id"`
	DataBase64      string `json:"data_base64" jsonschema:"the original data, base64-encoded"`
	SignatureBase64 string `json:"signature_base64" jsonschema:"the signature to check, base64-encoded"`
	Algorithm       string `json:"algorithm,omitempty" jsonschema:"the algorithm the signature was made with"`
	Version         int    `json:"version,omitempty" jsonschema:"the key version that signed; omit to use the current one"`
	Vault           string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type verifyResult struct {
	Vault     string `json:"vault"`
	KeyName   string `json:"key_name"`
	Algorithm string `json:"algorithm"`
	Valid     bool   `json:"valid"`
	Version   int    `json:"version"`
}

// encryptArgs are the arguments to encrypt.
//
// plaintext and plaintext_base64 are alternatives and exactly one is
// required. Accepting plain text removes friction with a silent failure mode:
// a caller who forgot to encode would otherwise send a request that succeeds
// and encrypts the wrong bytes.
type encryptArgs struct {
	KeyName         string `json:"key_name" jsonschema:"the key's name, or its id"`
	Plaintext       string `json:"plaintext,omitempty" jsonschema:"the text to encrypt; use plaintext_base64 instead for binary data"`
	PlaintextBase64 string `json:"plaintext_base64,omitempty" jsonschema:"the data to encrypt, base64-encoded; use plaintext instead for text"`
	Algorithm       string `json:"algorithm,omitempty" jsonschema:"RSA-OAEP, RSA-OAEP-256 or AES256-GCM"`
	Version         int    `json:"version,omitempty" jsonschema:"a specific key version; omit to use the current one"`
	Vault           string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type encryptResult struct {
	Vault            string `json:"vault"`
	KeyName          string `json:"key_name"`
	Algorithm        string `json:"algorithm"`
	CiphertextBase64 string `json:"ciphertext_base64"`
	// NonceBase64 is present for AES-GCM. Decryption requires it.
	NonceBase64 string `json:"nonce_base64,omitempty"`
	Version     int    `json:"version"`
	// Note warns that the nonce must be kept, when there is one.
	Note string `json:"note,omitempty"`
}

type decryptArgs struct {
	KeyName          string `json:"key_name" jsonschema:"the key's name, or its id"`
	CiphertextBase64 string `json:"ciphertext_base64" jsonschema:"the ciphertext to decrypt, base64-encoded"`
	NonceBase64      string `json:"nonce_base64,omitempty" jsonschema:"the nonce returned by encrypt; required for AES-GCM"`
	Algorithm        string `json:"algorithm,omitempty" jsonschema:"the algorithm the ciphertext was produced with"`
	Version          int    `json:"version,omitempty" jsonschema:"the key version that encrypted; omit to use the current one"`
	Vault            string `json:"vault,omitempty" jsonschema:"the vault holding the key; defaults to the server's configured vault"`
}

type decryptResult struct {
	Vault     string `json:"vault"`
	KeyName   string `json:"key_name"`
	Algorithm string `json:"algorithm"`
	// Plaintext is text when the decrypted bytes are valid UTF-8, and
	// base64 otherwise. PlaintextIsBase64 says which.
	Plaintext string `json:"plaintext"`
	// PlaintextIsBase64 exists because returning invalid UTF-8 as a JSON
	// string would corrupt it silently: Go replaces invalid bytes with
	// U+FFFD on marshal, so the caller would get plausible but wrong data
	// with no indication.
	PlaintextIsBase64 bool `json:"plaintext_is_base64"`
	Version           int  `json:"version"`
}

// decodeBase64Arg decodes a base64 argument, naming the field on failure.
func decodeBase64Arg(field, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is required", field)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be base64-encoded", field)
	}
	return decoded, nil
}

// resolvePlaintextArg picks between the two plaintext inputs.
func resolvePlaintextArg(text, encoded string) ([]byte, error) {
	switch {
	case text != "" && encoded != "":
		return nil, fmt.Errorf("give either plaintext or plaintext_base64, not both")
	case text != "":
		return []byte(text), nil
	case encoded != "":
		return decodeBase64Arg("plaintext_base64", encoded)
	default:
		return nil, fmt.Errorf("encrypt requires plaintext or plaintext_base64")
	}
}

// registerCryptoTools adds the crypto-tier tools.
//
// None of them is destructive and none needs confirmation: they mutate
// nothing. They are gated at all because they use the vault's private keys on
// the caller's behalf, which is a distinct authority from reading or writing
// -- not because they destroy anything.
func registerCryptoTools(s *Server) {
	registerIf(s, TierCrypto, "sign",
		"Sign data with a key held in the vault. The private key never leaves the vault. "+
			"Data is base64-encoded, and the result records which key version signed.",
		Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
		s.handleSign)

	registerIf(s, TierCrypto, "verify",
		"Check a signature against its original data using a key in the vault. "+
			"A signature that does not match returns valid=false; that is an answer, not an error.",
		Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
		s.handleVerify)

	registerIf(s, TierCrypto, "encrypt",
		"Encrypt data with a key held in the vault. For AES-GCM the result includes a nonce that must be kept "+
			"alongside the ciphertext, since decryption requires it.",
		Annotations{ReadOnly: false, Idempotent: false, Destructive: false},
		s.handleEncrypt)

	// decrypt is gated twice. allow_crypto admits the tier, but decrypt
	// returns plaintext, and allow_secret_values is the flag governing
	// whether plaintext reaches the model. Without the second gate, an
	// operator who disabled disclosure could still have any ciphertext
	// decrypted and read, making that flag meaningless.
	if s.MayDiscloseValues() {
		registerIf(s, TierCrypto, "decrypt",
			"Decrypt ciphertext with a key held in the vault and return the plaintext. "+
				"For AES-GCM, pass the nonce that encrypt returned.",
			Annotations{ReadOnly: false, Idempotent: true, Destructive: false},
			s.handleDecrypt)
	}
}

func (s *Server) handleSign(ctx context.Context, _ *mcp.CallToolRequest, args signArgs) (*mcp.CallToolResult, signResult, error) {
	if args.KeyName == "" {
		return errorResult("sign requires a key_name"), signResult{}, nil
	}
	data, err := decodeBase64Arg("data_base64", args.DataBase64)
	if err != nil {
		return errorResult("%s", err), signResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), signResult{}, nil
	}

	signed, err := s.client.Sign(ctx, vault, args.KeyName, data, args.Algorithm, args.Version)
	if err != nil {
		return errorResult("could not sign with key %q in vault %q: %s",
			args.KeyName, vault, err), signResult{}, nil
	}

	return nil, signResult{
		Vault:           vault,
		KeyName:         args.KeyName,
		Algorithm:       signed.Algorithm,
		SignatureBase64: base64.StdEncoding.EncodeToString(signed.Signature),
		Version:         signed.Version,
	}, nil
}

func (s *Server) handleVerify(ctx context.Context, _ *mcp.CallToolRequest, args verifyArgs) (*mcp.CallToolResult, verifyResult, error) {
	if args.KeyName == "" {
		return errorResult("verify requires a key_name"), verifyResult{}, nil
	}
	data, err := decodeBase64Arg("data_base64", args.DataBase64)
	if err != nil {
		return errorResult("%s", err), verifyResult{}, nil
	}
	signature, err := decodeBase64Arg("signature_base64", args.SignatureBase64)
	if err != nil {
		return errorResult("%s", err), verifyResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), verifyResult{}, nil
	}

	checked, err := s.client.Verify(ctx, vault, args.KeyName, data, signature, args.Algorithm, args.Version)
	if err != nil {
		return errorResult("could not verify with key %q in vault %q: %s",
			args.KeyName, vault, err), verifyResult{}, nil
	}

	// A false result is returned as a successful call. Reporting it as a tool
	// error would leave the model unable to tell a forgery from an
	// unreachable vault.
	return nil, verifyResult{
		Vault:     vault,
		KeyName:   args.KeyName,
		Algorithm: checked.Algorithm,
		Valid:     checked.Valid,
		Version:   checked.Version,
	}, nil
}

func (s *Server) handleEncrypt(ctx context.Context, _ *mcp.CallToolRequest, args encryptArgs) (*mcp.CallToolResult, encryptResult, error) {
	if args.KeyName == "" {
		return errorResult("encrypt requires a key_name"), encryptResult{}, nil
	}
	plaintext, err := resolvePlaintextArg(args.Plaintext, args.PlaintextBase64)
	if err != nil {
		return errorResult("%s", err), encryptResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), encryptResult{}, nil
	}

	encrypted, err := s.client.Encrypt(ctx, vault, args.KeyName, plaintext, args.Algorithm, args.Version)
	if err != nil {
		return errorResult("could not encrypt with key %q in vault %q: %s",
			args.KeyName, vault, err), encryptResult{}, nil
	}

	result := encryptResult{
		Vault:            vault,
		KeyName:          args.KeyName,
		Algorithm:        encrypted.Algorithm,
		CiphertextBase64: base64.StdEncoding.EncodeToString(encrypted.Ciphertext),
		Version:          encrypted.Version,
	}
	if len(encrypted.Nonce) > 0 {
		result.NonceBase64 = base64.StdEncoding.EncodeToString(encrypted.Nonce)
		result.Note = "Keep nonce_base64 with the ciphertext: decryption requires it, and without it the plaintext cannot be recovered."
	}
	return nil, result, nil
}

func (s *Server) handleDecrypt(ctx context.Context, _ *mcp.CallToolRequest, args decryptArgs) (*mcp.CallToolResult, decryptResult, error) {
	if args.KeyName == "" {
		return errorResult("decrypt requires a key_name"), decryptResult{}, nil
	}
	ciphertext, err := decodeBase64Arg("ciphertext_base64", args.CiphertextBase64)
	if err != nil {
		return errorResult("%s", err), decryptResult{}, nil
	}

	var nonce []byte
	if args.NonceBase64 != "" {
		nonce, err = decodeBase64Arg("nonce_base64", args.NonceBase64)
		if err != nil {
			return errorResult("%s", err), decryptResult{}, nil
		}
	}

	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), decryptResult{}, nil
	}

	decrypted, err := s.client.Decrypt(ctx, vault, args.KeyName, ciphertext, nonce, args.Algorithm, args.Version)
	if err != nil {
		return errorResult("could not decrypt with key %q in vault %q: %s",
			args.KeyName, vault, err), decryptResult{}, nil
	}

	// Revealing here is the deliberate act this tool exists for, and it is
	// reachable only because both allow_crypto and allow_secret_values are
	// set -- the tool is not registered otherwise.
	plaintext := decrypted.Plaintext.Reveal()

	result := decryptResult{
		Vault:     vault,
		KeyName:   args.KeyName,
		Algorithm: decrypted.Algorithm,
		Version:   decrypted.Version,
	}
	if utf8.ValidString(plaintext) {
		result.Plaintext = plaintext
	} else {
		result.Plaintext = base64.StdEncoding.EncodeToString([]byte(plaintext))
		result.PlaintextIsBase64 = true
	}
	return nil, result, nil
}
