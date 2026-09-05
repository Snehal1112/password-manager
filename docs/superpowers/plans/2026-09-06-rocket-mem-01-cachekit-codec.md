# Rocket-mem Tiered Cache — Plan 01: cachekit Codec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generic `Codec[V]` interface to `internal/cachekit`, plus two implementations (`PlainJSONCodec[V]`, `EncryptedJSONCodec[V]`), with zero changes to any existing file.

**Architecture:** Pure addition — new file, new types, nothing existing is touched or imported differently. `cachekit` gains no new external dependency (only `encoding/json`, already stdlib).

**Tech Stack:** Go 1.24, `encoding/json`, `testify` (existing test dependency).

**Spec:** `docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` (see "Codec — pluggable per domain" section)

## Global Constraints

- `internal/cachekit` must not import `go-redis`, `internal/crypto`, or any service-layer package — `EncryptedJSONCodec` takes plain `func(string) (string, error)` fields, not a concrete crypto type.
- No existing file in this repo is modified in this plan. `go build ./...` and `go test ./...` must be green after every task, unchanged from before this plan started (this plan only adds new, currently-unreferenced code).

---

### Task 1: `Codec[V]` interface + `PlainJSONCodec[V]`

**Files:**
- Create: `internal/cachekit/codec.go`
- Test: `internal/cachekit/codec_test.go`

**Interfaces:**
- Produces: `cachekit.Codec[V any]` (`Encode(V) ([]byte, error)`, `Decode([]byte) (V, error)`), `cachekit.PlainJSONCodec[V any]` (zero-value usable, no constructor needed).

- [ ] **Step 1: Write the failing test**

```go
// internal/cachekit/codec_test.go
package cachekit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

type codecTestValue struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

func TestPlainJSONCodec_RoundTrip(t *testing.T) {
	var codec cachekit.PlainJSONCodec[codecTestValue]
	in := codecTestValue{Name: "widget", N: 7}

	payload, err := codec.Encode(in)
	require.NoError(t, err)
	assert.Contains(t, string(payload), "widget", "plain codec must not encrypt — the JSON is readable on the wire")

	out, err := codec.Decode(payload)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestPlainJSONCodec_DecodeMalformed(t *testing.T) {
	var codec cachekit.PlainJSONCodec[codecTestValue]
	_, err := codec.Decode([]byte("not json"))
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cachekit/... -run TestPlainJSONCodec -v`
Expected: FAIL (build error — `cachekit.Codec`/`cachekit.PlainJSONCodec` do not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// internal/cachekit/codec.go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cachekit/... -run TestPlainJSONCodec -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cachekit/codec.go internal/cachekit/codec_test.go
git commit -m "feat(cachekit): add Codec interface and PlainJSONCodec"
```

---

### Task 2: `EncryptedJSONCodec[V]`

**Files:**
- Modify: `internal/cachekit/codec.go`
- Test: `internal/cachekit/codec_test.go`

**Interfaces:**
- Consumes: `Codec[V]` from Task 1.
- Produces: `cachekit.EncryptedJSONCodec[V any]` struct with exported fields `Encrypt func(string) (string, error)` and `Decrypt func(string) (string, error)` — callers construct it with `common.EncryptSecret`/`common.DecryptSecret` (see Plan 05/06), but this package must not import `common` itself.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/cachekit/codec_test.go
package cachekit_test

import (
	"encoding/base64"
	"errors"
	"strings"

	"rocketvault/internal/cachekit"
)

// fakeEncrypt/fakeDecrypt stand in for common.EncryptSecret/DecryptSecret —
// same signature (func(string) (string, error)), base64 round-trip only,
// no real crypto (this test proves the codec wiring, not AES-GCM itself,
// which internal/crypto already tests independently).
func fakeEncrypt(plaintext string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(plaintext)), nil
}

func fakeDecrypt(ciphertext string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func TestEncryptedJSONCodec_RoundTrip(t *testing.T) {
	codec := cachekit.EncryptedJSONCodec[codecTestValue]{Encrypt: fakeEncrypt, Decrypt: fakeDecrypt}
	in := codecTestValue{Name: "top-secret", N: 42}

	payload, err := codec.Encode(in)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(payload), "top-secret"),
		"encrypted codec must never leak the plaintext substring onto the wire")

	out, err := codec.Decode(payload)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestEncryptedJSONCodec_EncryptErrorPropagates(t *testing.T) {
	codec := cachekit.EncryptedJSONCodec[codecTestValue]{
		Encrypt: func(string) (string, error) { return "", errors.New("boom") },
		Decrypt: fakeDecrypt,
	}
	_, err := codec.Encode(codecTestValue{Name: "x"})
	assert.Error(t, err)
}
```

Add `"github.com/stretchr/testify/require"` is already imported from Task 1; add `"encoding/base64"`, `"errors"`, `"strings"` to the import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cachekit/... -run TestEncryptedJSONCodec -v`
Expected: FAIL (build error — `cachekit.EncryptedJSONCodec` does not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// append to internal/cachekit/codec.go

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cachekit/... -v`
Expected: PASS (all `codec_test.go` tests, including Task 1's)

- [ ] **Step 5: Commit**

```bash
git add internal/cachekit/codec.go internal/cachekit/codec_test.go
git commit -m "feat(cachekit): add EncryptedJSONCodec"
```
