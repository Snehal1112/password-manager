package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// ErrJWKNoPrivateKey is returned when a supplied JWK carries no private key
// material -- only a public JWK -- and so cannot be imported as a usable key.
var ErrJWKNoPrivateKey = errors.New("jwk contains no private key material")

// ParseJWK parses a JWK containing private key material and returns the
// concrete Go key together with its RocketVault key-type string ("RSA" or
// "ECDSA"). It rejects public-only JWKs and any kty/crv combination
// RocketVault does not support for import.
func ParseJWK(jwkJSON []byte) (privateKey crypto.PrivateKey, keyType string, err error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		// No "invalid JWK: " prefix here: the sole caller (KeyService.ImportKey)
		// already wraps this in keyservices.ErrInvalidJWK ("invalid jwk: %w"),
		// so prefixing here doubled the message (e.g. "invalid jwk: invalid
		// JWK: unexpected end of JSON input") once that caller-side error
		// started reaching API clients verbatim via c.SetInvalidParam(err.Error()).
		return nil, "", err
	}
	if jwk.IsPublic() {
		return nil, "", ErrJWKNoPrivateKey
	}
	switch key := jwk.Key.(type) {
	case *rsa.PrivateKey:
		return key, "RSA", nil
	case *ecdsa.PrivateKey:
		return key, "ECDSA", nil
	default:
		return nil, "", fmt.Errorf("unsupported JWK key type: %T", jwk.Key)
	}
}
