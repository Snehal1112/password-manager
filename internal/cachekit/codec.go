package cachekit

import "encoding/json"

// Codec converts a domain value to and from the bytes stored on an L2
// (network) cache tier. cachekit's in-process L1 tier never needs this —
// it stores live V values directly — so Codec is only exercised by
// TieredCache (see tiered_cache.go).
type Codec[V any] interface {
	Encode(V) ([]byte, error)
	Decode([]byte) (V, error)
}

// PlainJSONCodec is a Codec that JSON-marshals V with no encryption. Use
// for domains whose cached value never holds decrypted secret material
// (see the design spec's Problem Statement table). Zero value is usable.
type PlainJSONCodec[V any] struct{}

func (PlainJSONCodec[V]) Encode(v V) ([]byte, error) {
	return json.Marshal(v)
}

func (PlainJSONCodec[V]) Decode(payload []byte) (V, error) {
	var v V
	err := json.Unmarshal(payload, &v)
	return v, err
}

// EncryptedJSONCodec is a Codec that JSON-marshals V, then encrypts the
// bytes via Encrypt (and reverses via Decrypt on the way back). Encrypt and
// Decrypt match common.EncryptSecret/common.DecryptSecret's exact
// signature — callers pass those functions directly, keeping this package
// free of any crypto import. Use for domains whose cached value holds
// decrypted secret material (see the design spec's Problem Statement
// table): the payload leaving this process must always be ciphertext.
type EncryptedJSONCodec[V any] struct {
	Encrypt func(string) (string, error)
	Decrypt func(string) (string, error)
}

func (c EncryptedJSONCodec[V]) Encode(v V) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	ciphertext, err := c.Encrypt(string(raw))
	if err != nil {
		return nil, err
	}
	return []byte(ciphertext), nil
}

func (c EncryptedJSONCodec[V]) Decode(payload []byte) (V, error) {
	var v V
	plaintext, err := c.Decrypt(string(payload))
	if err != nil {
		return v, err
	}
	err = json.Unmarshal([]byte(plaintext), &v)
	return v, err
}
