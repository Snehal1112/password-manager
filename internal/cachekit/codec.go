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
