package common

import (
	"encoding/base64"
	"strings"
	"testing"
)

// rawKey builds a deterministic 32-byte key for tests. Distinct seeds give
// distinct keys.
func rawKey(seed byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func TestEncryptWithKeyDecryptWithKey_RoundTrip(t *testing.T) {
	key := rawKey(1)
	plaintext := "my secret value"

	ciphertext, err := EncryptWithKey(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}
	if ciphertext == plaintext {
		t.Fatal("ciphertext must not equal plaintext")
	}

	decrypted, err := DecryptWithKey(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptWithKey failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestDecryptWithKey_WrongKeyFails(t *testing.T) {
	ciphertext, err := EncryptWithKey("my secret value", rawKey(1))
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}

	if _, err := DecryptWithKey(ciphertext, rawKey(100)); err == nil {
		t.Error("expected decryption with the wrong key to fail")
	}
}

func TestEncryptWithKey_NonceIsRandomPerCall(t *testing.T) {
	key := rawKey(1)

	first, err := EncryptWithKey("same plaintext", key)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}
	second, err := EncryptWithKey("same plaintext", key)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}
	if first == second {
		t.Error("two seals of the same plaintext must differ (random nonce)")
	}
}

// A 16-byte key is deliberately chosen here: it is a valid AES-128 key that
// aes.NewCipher accepts happily. Only the explicit 32-byte check rejects it, so
// these tests fail if that check is ever removed or loosened to allow a weaker
// AES variant. Asserting on "32" keeps them from passing on some unrelated
// error further down the function.
func TestEncryptWithKey_RejectsWrongKeyLength(t *testing.T) {
	_, err := EncryptWithKey("value", []byte("sixteen bytes!!!"))
	if err == nil {
		t.Fatal("expected error for a key that is not 32 bytes")
	}
	if !strings.Contains(err.Error(), "32") {
		t.Errorf("error should state the required length, got: %v", err)
	}
}

func TestDecryptWithKey_RejectsWrongKeyLength(t *testing.T) {
	_, err := DecryptWithKey("Zm9v", []byte("sixteen bytes!!!"))
	if err == nil {
		t.Fatal("expected error for a key that is not 32 bytes")
	}
	if !strings.Contains(err.Error(), "32") {
		t.Errorf("error should state the required length, got: %v", err)
	}
}

func TestParseMasterKey_Valid(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(rawKey(7))

	key, err := ParseMasterKey(encoded)
	if err != nil {
		t.Fatalf("ParseMasterKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(key))
	}
}

func TestParseMasterKey_Empty(t *testing.T) {
	if _, err := ParseMasterKey(""); err == nil {
		t.Error("expected error for an empty master key")
	}
}

func TestParseMasterKey_NotBase64(t *testing.T) {
	if _, err := ParseMasterKey("not-base64!!"); err == nil {
		t.Error("expected error for a non-base64 master key")
	}
}

func TestParseMasterKey_WrongLength(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("sixteen bytes!!!"))

	_, err := ParseMasterKey(encoded)
	if err == nil {
		t.Fatal("expected error for a 16-byte master key")
	}
	if !strings.Contains(err.Error(), "32") {
		t.Errorf("error should state the required length, got: %v", err)
	}
}
