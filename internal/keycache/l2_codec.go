package keycache

import (
	"encoding/json"
	"fmt"
)

// entryWire is Entry's L2 wire representation. Entry.PrivateKey/PublicKey
// are crypto.PrivateKey/crypto.PublicKey interface fields -- encoding/json
// cannot reconstruct a concrete PEMKey through a bare json.Unmarshal into
// an interface field (it would decode into map[string]interface{}
// instead), so entryWire holds plain []byte fields and entryCodec
// translates explicitly in both directions.
type entryWire struct {
	PrivateKeyPEM []byte `json:"private_key_pem,omitempty"`
	PublicKeyPEM  []byte `json:"public_key_pem,omitempty"`
	HasPrivate    bool   `json:"has_private"`
	HasPublic     bool   `json:"has_public"`
	KeyType       string `json:"key_type"`
	Version       int    `json:"version"`
}

// entryCodec implements cachekit.Codec[*Entry] for the L2 tier. encrypt/
// decrypt match common.EncryptSecret/common.DecryptSecret's signature --
// this package never imports internal/crypto or the service layer
// directly, matching the pattern established for internal/cache.
type entryCodec struct {
	encrypt func(string) (string, error)
	decrypt func(string) (string, error)
}

func (c entryCodec) Encode(e *Entry) ([]byte, error) {
	w := entryWire{KeyType: e.KeyType, Version: e.Version}
	if e.PrivateKey != nil {
		pk, ok := e.PrivateKey.(PEMKey)
		if !ok {
			return nil, fmt.Errorf("keycache: cannot cache PrivateKey of type %T to L2 (only PEMKey is supported)", e.PrivateKey)
		}
		w.PrivateKeyPEM = pk.PEM
		w.HasPrivate = true
	}
	if e.PublicKey != nil {
		pk, ok := e.PublicKey.(PEMKey)
		if !ok {
			return nil, fmt.Errorf("keycache: cannot cache PublicKey of type %T to L2 (only PEMKey is supported)", e.PublicKey)
		}
		w.PublicKeyPEM = pk.PEM
		w.HasPublic = true
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	ciphertext, err := c.encrypt(string(raw))
	if err != nil {
		return nil, err
	}
	return []byte(ciphertext), nil
}

func (c entryCodec) Decode(payload []byte) (*Entry, error) {
	plaintext, err := c.decrypt(string(payload))
	if err != nil {
		return nil, err
	}
	var w entryWire
	if err := json.Unmarshal([]byte(plaintext), &w); err != nil {
		return nil, err
	}
	e := &Entry{KeyType: w.KeyType, Version: w.Version}
	if w.HasPrivate {
		e.PrivateKey = PEMKey{PEM: w.PrivateKeyPEM}
	}
	if w.HasPublic {
		e.PublicKey = PEMKey{PEM: w.PublicKeyPEM}
	}
	return e, nil
}
