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
	"encoding/base64"
	"net/http"

	"rocketvault/internal/container"
	"rocketvault/internal/crypto"
	keyservices "rocketvault/internal/services/keys"
)

// wrapKey wraps plaintext key material using the vault key identified by {key_id}.
func wrapKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	req, bodyOK := decodeBody[WrapKeyRequest](c, r)
	if !bodyOK {
		return
	}
	if req.PlaintextKey == "" {
		c.SetInvalidParam("plaintext_key is required")
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	plaintextBytes, plaintextOK := b64Field(c, req.PlaintextKey, "plaintext_key")
	if !plaintextOK {
		return
	}

	cryptoSvc, svcOK := svc(c, container.ServiceContainerInterface.GetCryptoService)
	if !svcOK {
		return
	}

	result, err := cryptoSvc.WrapKey(r.Context(), keyservices.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       scope.ActorID(),
		VaultID:      scope.VaultID(),
		Scope:        scope,
		PlaintextKey: plaintextBytes,
		Algorithm:    req.Algorithm,
		Version:      req.Version,
	})
	if err != nil {
		writeKeyError(c, err)
		return
	}

	writeJSON(w, WrapKeyResponse{
		WrappedKey: base64.StdEncoding.EncodeToString(result.WrappedKey),
		Algorithm:  result.Algorithm,
		Version:    result.Version,
	})
}

// unwrapKey recovers plaintext key material from wrapped bytes using the vault key identified by {key_id}.
func unwrapKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	req, bodyOK := decodeBody[UnwrapKeyRequest](c, r)
	if !bodyOK {
		return
	}
	if req.WrappedKey == "" {
		c.SetInvalidParam("wrapped_key is required")
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	wrappedBytes, wrappedOK := b64Field(c, req.WrappedKey, "wrapped_key")
	if !wrappedOK {
		return
	}

	cryptoSvc, svcOK := svc(c, container.ServiceContainerInterface.GetCryptoService)
	if !svcOK {
		return
	}

	result, err := cryptoSvc.UnwrapKey(r.Context(), keyservices.UnwrapKeyRequest{
		KeyID:      keyID,
		UserID:     scope.ActorID(),
		VaultID:    scope.VaultID(),
		Scope:      scope,
		WrappedKey: wrappedBytes,
		Algorithm:  req.Algorithm,
		Version:    req.Version,
	})
	if err != nil {
		writeKeyError(c, err)
		return
	}

	writeJSON(w, UnwrapKeyResponse{
		PlaintextKey: base64.StdEncoding.EncodeToString(result.PlaintextKey),
		Algorithm:    result.Algorithm,
		Version:      result.Version,
	})
}

// signKey signs data using the vault key identified by {key_id}.
func signKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	req, bodyOK := decodeBody[SignKeyRequest](c, r)
	if !bodyOK {
		return
	}
	if req.Value == "" {
		c.SetInvalidParam("value is required")
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RS256"
	}

	data, dataOK := b64Field(c, req.Value, "value")
	if !dataOK {
		return
	}

	cryptoSvc, svcOK := svc(c, container.ServiceContainerInterface.GetCryptoService)
	if !svcOK {
		return
	}

	result, err := cryptoSvc.Sign(r.Context(), keyservices.SignRequest{
		KeyID:     keyID,
		Data:      data,
		Algorithm: crypto.SignatureAlgorithm(req.Algorithm),
		UserID:    scope.ActorID(),
		VaultID:   scope.VaultID(),
		Scope:     scope,
		Version:   req.Version,
	})
	if err != nil {
		writeKeyError(c, err)
		return
	}

	writeJSON(w, SignKeyResponse{
		KeyID:     keyID.String(),
		Algorithm: string(result.Algorithm),
		Value:     base64.StdEncoding.EncodeToString(result.Signature),
		Version:   result.Version,
	})
}

// verifyKey verifies a signature using the vault key identified by {key_id}.
func verifyKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	req, bodyOK := decodeBody[VerifyKeyRequest](c, r)
	if !bodyOK {
		return
	}
	if req.Value == "" || req.Signature == "" {
		c.SetInvalidParam("value and signature are required")
		return
	}

	data, dataOK := b64Field(c, req.Value, "value")
	if !dataOK {
		return
	}
	sig, sigOK := b64Field(c, req.Signature, "signature")
	if !sigOK {
		return
	}

	cryptoSvc, svcOK := svc(c, container.ServiceContainerInterface.GetCryptoService)
	if !svcOK {
		return
	}

	result, err := cryptoSvc.Verify(r.Context(), keyservices.VerifyRequest{
		KeyID:     keyID,
		Data:      data,
		Signature: sig,
		Algorithm: crypto.SignatureAlgorithm(req.Algorithm),
		UserID:    scope.ActorID(),
		VaultID:   scope.VaultID(),
		Scope:     scope,
		Version:   req.Version,
	})
	if err != nil {
		writeKeyError(c, err)
		return
	}

	writeJSON(w, VerifyKeyResponse{
		KeyID:     keyID.String(),
		Algorithm: string(result.Algorithm),
		Valid:     result.Valid,
		Version:   result.Version,
	})
}

// encryptKey encrypts data using the vault key identified by {key_id}.
func encryptKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	req, bodyOK := decodeBody[EncryptKeyRequest](c, r)
	if !bodyOK {
		return
	}
	if req.Value == "" {
		c.SetInvalidParam("value is required")
		return
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-OAEP"
	}

	plaintext, plaintextOK := b64Field(c, req.Value, "value")
	if !plaintextOK {
		return
	}

	cryptoSvc, svcOK := svc(c, container.ServiceContainerInterface.GetCryptoService)
	if !svcOK {
		return
	}

	result, err := cryptoSvc.Encrypt(r.Context(), keyservices.EncryptRequest{
		KeyID:     keyID,
		Data:      plaintext,
		Algorithm: crypto.EncryptionAlgorithm(req.Algorithm),
		UserID:    scope.ActorID(),
		VaultID:   scope.VaultID(),
		Scope:     scope,
		Version:   req.Version,
	})
	if err != nil {
		writeKeyError(c, err)
		return
	}

	resp := EncryptKeyResponse{
		KeyID:     keyID.String(),
		Algorithm: string(result.Algorithm),
		Value:     base64.StdEncoding.EncodeToString(result.Ciphertext),
		Version:   result.Version,
	}
	if len(result.Nonce) > 0 {
		resp.Nonce = base64.StdEncoding.EncodeToString(result.Nonce)
	}

	writeJSON(w, resp)
}

// decryptKey decrypts data using the vault key identified by {key_id}.
func decryptKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	req, bodyOK := decodeBody[DecryptKeyRequest](c, r)
	if !bodyOK {
		return
	}
	if req.Value == "" {
		c.SetInvalidParam("value is required")
		return
	}

	ciphertext, ciphertextOK := b64Field(c, req.Value, "value")
	if !ciphertextOK {
		return
	}

	var nonce []byte
	if req.Nonce != "" {
		var nonceOK bool
		nonce, nonceOK = b64Field(c, req.Nonce, "nonce")
		if !nonceOK {
			return
		}
	}

	cryptoSvc, svcOK := svc(c, container.ServiceContainerInterface.GetCryptoService)
	if !svcOK {
		return
	}

	result, err := cryptoSvc.Decrypt(r.Context(), keyservices.DecryptRequest{
		KeyID:      keyID,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Algorithm:  crypto.EncryptionAlgorithm(req.Algorithm),
		UserID:     scope.ActorID(),
		VaultID:    scope.VaultID(),
		Scope:      scope,
		Version:    req.Version,
	})
	if err != nil {
		writeKeyError(c, err)
		return
	}

	writeJSON(w, DecryptKeyResponse{
		KeyID:     keyID.String(),
		Algorithm: string(result.Algorithm),
		Value:     base64.StdEncoding.EncodeToString(result.Plaintext),
		Version:   result.Version,
	})
}
