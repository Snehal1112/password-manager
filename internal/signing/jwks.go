package signing

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// RSAPublicKeyToJWK serialises an RSA public key to a JWK map (RFC 7517).
func RSAPublicKeyToJWK(key *rsa.PublicKey, kid, alg string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": alg,
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

// ECDSAPublicKeyToJWK serialises an ECDSA public key to a JWK map (RFC 7517).
func ECDSAPublicKeyToJWK(key *ecdsa.PublicKey, kid, alg string) (map[string]any, error) {
	crv, byteLen, err := curveParams(key)
	if err != nil {
		return nil, err
	}

	xBytes := padBytes(key.X.Bytes(), byteLen)
	yBytes := padBytes(key.Y.Bytes(), byteLen)

	return map[string]any{
		"kty": "EC",
		"use": "sig",
		"alg": alg,
		"kid": kid,
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}, nil
}

// PublicKeyInfoToJWK converts a PublicKeyInfo to a JWK map.
func PublicKeyInfoToJWK(info PublicKeyInfo) (map[string]any, error) {
	switch k := info.PublicKey.(type) {
	case *rsa.PublicKey:
		return RSAPublicKeyToJWK(k, info.KeyID, info.Algorithm), nil
	case *ecdsa.PublicKey:
		return ECDSAPublicKeyToJWK(k, info.KeyID, info.Algorithm)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", info.PublicKey)
	}
}

func curveParams(key *ecdsa.PublicKey) (crv string, byteLen int, err error) {
	switch key.Curve.Params().Name {
	case "P-256":
		return "P-256", 32, nil
	case "P-384":
		return "P-384", 48, nil
	case "P-521":
		return "P-521", 66, nil
	default:
		return "", 0, fmt.Errorf("unsupported ECDSA curve: %s", key.Curve.Params().Name)
	}
}

// padBytes left-pads b to length n.
func padBytes(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	padded := make([]byte, n)
	copy(padded[n-len(b):], b)
	return padded
}
