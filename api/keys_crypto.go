/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package api

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/google/uuid"

	"rocketvault/internal/container"
	"rocketvault/internal/crypto"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

// cryptoOp is the shared spine of the six key crypto handlers.
//
// All six run the same steps in the same order and differ only in their wire
// types, their default algorithm, which fields are required, and which fields
// carry base64. The order is behavior, because it decides which error a
// malformed request gets, so it is written once here instead of six times.
//
// The three type parameters mirror the three stages: Req is the decoded wire
// request, In is the base64-decoded binary input, Res is the response body.
// Separating In from Req is what keeps base64 decoding ahead of service
// resolution, matching the handlers this replaces.
type cryptoOp[Req any, In any, Res any] struct {
	// DefaultAlgorithm is applied when the request omits one. It is consulted
	// only when AlgorithmField is non-nil.
	DefaultAlgorithm string

	// AlgorithmField returns a pointer to the request's algorithm field so a
	// default can be written into it. It is nil for the operations that have no
	// default and pass through whatever the client sent — verify and decrypt.
	AlgorithmField func(*Req) *string

	// Required returns an empty string when the request carries everything the
	// operation needs, and otherwise the exact message for the 400. Nil means
	// the operation has no required fields.
	Required func(Req) string

	// Decode turns the request's base64 fields into binary. It sets c.Err and
	// returns false on a malformed field. Nil means the operation takes no
	// binary input, and In is left as its zero value.
	Decode func(c *Context, req Req) (In, bool)

	// Invoke performs the operation and builds the response body. Its error is
	// mapped by writeKeyError, so it must return the service error unwrapped.
	Invoke func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req Req, in In) (Res, error)
}

// handler turns a cryptoOp into a registrable API handler.
func (op cryptoOp[Req, In, Res]) handler() func(*Context, http.ResponseWriter, *http.Request) {
	return func(c *Context, w http.ResponseWriter, r *http.Request) {
		keyID, ok := resourceID(c, c.Params.KeyID, "key_id")
		if !ok {
			return
		}

		scope, ok := scopeFromRequest(c, r)
		if !ok {
			return
		}

		req, ok := decodeBody[Req](c, r)
		if !ok {
			return
		}

		// A nil Required means the operation has no required fields.
		if op.Required != nil {
			if msg := op.Required(req); msg != "" {
				c.SetInvalidParam(msg)
				return
			}
		}

		if op.AlgorithmField != nil {
			if field := op.AlgorithmField(&req); *field == "" {
				*field = op.DefaultAlgorithm
			}
		}

		// A nil Decode means the operation takes no binary input, so In stays
		// its zero value.
		var in In
		if op.Decode != nil {
			in, ok = op.Decode(c, req)
			if !ok {
				return
			}
		}

		cs, ok := svc(c, container.ServiceContainerInterface.GetCryptoService)
		if !ok {
			return
		}

		res, err := op.Invoke(r.Context(), cs, keyID, scope, req, in)
		if err != nil {
			writeKeyError(c, err)
			return
		}

		writeJSON(w, res)
	}
}

// wrapKey wraps plaintext key material using the vault key identified by {key_id}.
var wrapKey = cryptoOp[WrapKeyRequest, []byte, WrapKeyResponse]{
	DefaultAlgorithm: "RSA-OAEP",
	AlgorithmField:   func(req *WrapKeyRequest) *string { return &req.Algorithm },
	Required: func(req WrapKeyRequest) string {
		if req.PlaintextKey == "" {
			return "plaintext_key is required"
		}
		return ""
	},
	Decode: func(c *Context, req WrapKeyRequest) ([]byte, bool) {
		return b64Field(c, req.PlaintextKey, "plaintext_key")
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req WrapKeyRequest, in []byte) (WrapKeyResponse, error) {
		result, err := cs.WrapKey(ctx, keyservices.WrapKeyRequest{
			KeyID:        keyID,
			UserID:       scope.ActorID(),
			VaultID:      scope.VaultID(),
			Scope:        scope,
			PlaintextKey: in,
			Algorithm:    req.Algorithm,
			Version:      req.Version,
		})
		if err != nil {
			return WrapKeyResponse{}, err
		}
		return WrapKeyResponse{
			WrappedKey: base64.StdEncoding.EncodeToString(result.WrappedKey),
			Algorithm:  result.Algorithm,
			Version:    result.Version,
		}, nil
	},
}.handler()

// unwrapKey recovers plaintext key material from wrapped bytes using the vault key identified by {key_id}.
var unwrapKey = cryptoOp[UnwrapKeyRequest, []byte, UnwrapKeyResponse]{
	DefaultAlgorithm: "RSA-OAEP",
	AlgorithmField:   func(req *UnwrapKeyRequest) *string { return &req.Algorithm },
	Required: func(req UnwrapKeyRequest) string {
		if req.WrappedKey == "" {
			return "wrapped_key is required"
		}
		return ""
	},
	Decode: func(c *Context, req UnwrapKeyRequest) ([]byte, bool) {
		return b64Field(c, req.WrappedKey, "wrapped_key")
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req UnwrapKeyRequest, in []byte) (UnwrapKeyResponse, error) {
		result, err := cs.UnwrapKey(ctx, keyservices.UnwrapKeyRequest{
			KeyID:      keyID,
			UserID:     scope.ActorID(),
			VaultID:    scope.VaultID(),
			Scope:      scope,
			WrappedKey: in,
			Algorithm:  req.Algorithm,
			Version:    req.Version,
		})
		if err != nil {
			return UnwrapKeyResponse{}, err
		}
		return UnwrapKeyResponse{
			PlaintextKey: base64.StdEncoding.EncodeToString(result.PlaintextKey),
			Algorithm:    result.Algorithm,
			Version:      result.Version,
		}, nil
	},
}.handler()

// signKey signs data using the vault key identified by {key_id}.
var signKey = cryptoOp[SignKeyRequest, []byte, SignKeyResponse]{
	DefaultAlgorithm: "RS256",
	AlgorithmField:   func(req *SignKeyRequest) *string { return &req.Algorithm },
	Required: func(req SignKeyRequest) string {
		if req.Value == "" {
			return "value is required"
		}
		return ""
	},
	Decode: func(c *Context, req SignKeyRequest) ([]byte, bool) {
		return b64Field(c, req.Value, "value")
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req SignKeyRequest, in []byte) (SignKeyResponse, error) {
		result, err := cs.Sign(ctx, keyservices.SignRequest{
			KeyID:     keyID,
			Data:      in,
			Algorithm: crypto.SignatureAlgorithm(req.Algorithm),
			UserID:    scope.ActorID(),
			VaultID:   scope.VaultID(),
			Scope:     scope,
			Version:   req.Version,
		})
		if err != nil {
			return SignKeyResponse{}, err
		}
		return SignKeyResponse{
			KeyID:     keyID.String(),
			Algorithm: string(result.Algorithm),
			Value:     base64.StdEncoding.EncodeToString(result.Signature),
			Version:   result.Version,
		}, nil
	},
}.handler()

// verifyInputs carries verify's two base64-decoded fields.
type verifyInputs struct {
	Data      []byte
	Signature []byte
}

// verifyKey verifies a signature using the vault key identified by {key_id}.
//
// AlgorithmField is nil deliberately: verify applies no default algorithm and
// passes through whatever the client sent, matching the handler it replaces.
var verifyKey = cryptoOp[VerifyKeyRequest, verifyInputs, VerifyKeyResponse]{
	Required: func(req VerifyKeyRequest) string {
		if req.Value == "" || req.Signature == "" {
			return "value and signature are required"
		}
		return ""
	},
	Decode: func(c *Context, req VerifyKeyRequest) (verifyInputs, bool) {
		data, ok := b64Field(c, req.Value, "value")
		if !ok {
			return verifyInputs{}, false
		}
		sig, ok := b64Field(c, req.Signature, "signature")
		if !ok {
			return verifyInputs{}, false
		}
		return verifyInputs{Data: data, Signature: sig}, true
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req VerifyKeyRequest, in verifyInputs) (VerifyKeyResponse, error) {
		result, err := cs.Verify(ctx, keyservices.VerifyRequest{
			KeyID:     keyID,
			Data:      in.Data,
			Signature: in.Signature,
			Algorithm: crypto.SignatureAlgorithm(req.Algorithm),
			UserID:    scope.ActorID(),
			VaultID:   scope.VaultID(),
			Scope:     scope,
			Version:   req.Version,
		})
		if err != nil {
			return VerifyKeyResponse{}, err
		}
		return VerifyKeyResponse{
			KeyID:     keyID.String(),
			Algorithm: string(result.Algorithm),
			Valid:     result.Valid,
			Version:   result.Version,
		}, nil
	},
}.handler()

// encryptKey encrypts data using the vault key identified by {key_id}.
var encryptKey = cryptoOp[EncryptKeyRequest, []byte, EncryptKeyResponse]{
	DefaultAlgorithm: "RSA-OAEP",
	AlgorithmField:   func(req *EncryptKeyRequest) *string { return &req.Algorithm },
	Required: func(req EncryptKeyRequest) string {
		if req.Value == "" {
			return "value is required"
		}
		return ""
	},
	Decode: func(c *Context, req EncryptKeyRequest) ([]byte, bool) {
		return b64Field(c, req.Value, "value")
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req EncryptKeyRequest, in []byte) (EncryptKeyResponse, error) {
		result, err := cs.Encrypt(ctx, keyservices.EncryptRequest{
			KeyID:     keyID,
			Data:      in,
			Algorithm: crypto.EncryptionAlgorithm(req.Algorithm),
			UserID:    scope.ActorID(),
			VaultID:   scope.VaultID(),
			Scope:     scope,
			Version:   req.Version,
		})
		if err != nil {
			return EncryptKeyResponse{}, err
		}
		res := EncryptKeyResponse{
			KeyID:     keyID.String(),
			Algorithm: string(result.Algorithm),
			Value:     base64.StdEncoding.EncodeToString(result.Ciphertext),
			Version:   result.Version,
		}
		// Nonce is only present for AEAD modes such as AES-GCM. Encoding an
		// empty slice would put an empty string on the wire where the field
		// was previously omitted.
		if len(result.Nonce) > 0 {
			res.Nonce = base64.StdEncoding.EncodeToString(result.Nonce)
		}
		return res, nil
	},
}.handler()

// decryptInputs carries decrypt's ciphertext and its optional nonce.
type decryptInputs struct {
	Ciphertext []byte
	Nonce      []byte
}

// decryptKey decrypts data using the vault key identified by {key_id}.
//
// AlgorithmField is nil deliberately: decrypt applies no default algorithm,
// matching the handler it replaces.
var decryptKey = cryptoOp[DecryptKeyRequest, decryptInputs, DecryptKeyResponse]{
	Required: func(req DecryptKeyRequest) string {
		if req.Value == "" {
			return "value is required"
		}
		return ""
	},
	Decode: func(c *Context, req DecryptKeyRequest) (decryptInputs, bool) {
		ciphertext, ok := b64Field(c, req.Value, "value")
		if !ok {
			return decryptInputs{}, false
		}
		// An absent nonce is legitimate for non-AEAD algorithms, so only a
		// present-but-malformed one is an error.
		var nonce []byte
		if req.Nonce != "" {
			nonce, ok = b64Field(c, req.Nonce, "nonce")
			if !ok {
				return decryptInputs{}, false
			}
		}
		return decryptInputs{Ciphertext: ciphertext, Nonce: nonce}, true
	},
	Invoke: func(ctx context.Context, cs keyservices.CryptoService, keyID uuid.UUID,
		scope model.Scope, req DecryptKeyRequest, in decryptInputs) (DecryptKeyResponse, error) {
		result, err := cs.Decrypt(ctx, keyservices.DecryptRequest{
			KeyID:      keyID,
			Ciphertext: in.Ciphertext,
			Nonce:      in.Nonce,
			Algorithm:  crypto.EncryptionAlgorithm(req.Algorithm),
			UserID:     scope.ActorID(),
			VaultID:    scope.VaultID(),
			Scope:      scope,
			Version:    req.Version,
		})
		if err != nil {
			return DecryptKeyResponse{}, err
		}
		return DecryptKeyResponse{
			KeyID:     keyID.String(),
			Algorithm: string(result.Algorithm),
			Value:     base64.StdEncoding.EncodeToString(result.Plaintext),
			Version:   result.Version,
		}, nil
	},
}.handler()
