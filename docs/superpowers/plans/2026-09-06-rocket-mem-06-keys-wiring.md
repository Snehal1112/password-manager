# Rocket-mem Tiered Cache — Plan 06: Wire keycache onto TieredCache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `NewCacheWithL2` for `keycache`, backed by `cachekit.TieredCache`, using a **custom** `Codec[*Entry]` — not the generic `EncryptedJSONCodec` — because `Entry.PrivateKey`/`PublicKey` are `crypto.PrivateKey`/`crypto.PublicKey` interface-typed fields that `encoding/json` cannot reconstruct through a bare `json.Unmarshal` into `*Entry`.

**Architecture:** A package-local `entryWire` DTO with concrete `[]byte` fields, and an `entryCodec` implementing `cachekit.Codec[*Entry]` by hand: `Encode` type-asserts `PrivateKey`/`PublicKey` to the concrete `PEMKey` (the only type production code ever stores there — verified in an earlier investigation) and marshals `entryWire`, encrypted via `common.EncryptSecret`; `Decode` reverses it, reconstructing real `PEMKey` values so the interface fields come back correctly typed. `keyCacheKey`'s `KeyCodec` needs an actual parser (`ID:Version` string), unlike the three string-keyed domains' identity codec.

**Tech Stack:** Go 1.25 generics, `encoding/json`, `strconv`.

**Spec:** `docs/superpowers/specs/2026-09-06-rocket-mem-tiered-cache-design.md` (Problem Statement table: keys require the encrypting codec; "Keys on the wire" section for `KeyCodec`)

## Global Constraints

- `NewCache`'s signature, behavior, and every existing test in `internal/keycache/` must be unchanged and still pass, untouched, after this plan.
- `entryCodec.Encode` must return an error (never silently drop data) if `PrivateKey`/`PublicKey` ever holds anything other than `PEMKey` or `nil` — `TieredCache.Set` already treats a codec error as "skip the L2 write, L1 still succeeds," so this fails safe rather than corrupting or silently losing data on L2.
- `go build ./...` and `go test ./...` must stay green after every task.

---

### Task 1: `entryWire` + `entryCodec`

**Files:**
- Create: `internal/keycache/l2_codec.go`
- Test: `internal/keycache/l2_codec_test.go`

**Interfaces:**
- Consumes: `keycache.Entry`, `keycache.PEMKey` (existing), `common.EncryptSecret`/`DecryptSecret`.
- Produces: `keycache.entryCodec` (unexported, package-internal — constructed only by `NewCacheWithL2` in Task 3), satisfying `cachekit.Codec[*Entry]`.

- [ ] **Step 1: Write the failing test**

```go
// internal/keycache/l2_codec_test.go
package keycache

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

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

var _ cachekit.Codec[*Entry] = entryCodec{}

func TestEntryCodec_RoundTrip_ReconstructsConcretePEMKeyType(t *testing.T) {
	codec := entryCodec{encrypt: fakeEncrypt, decrypt: fakeDecrypt}
	in := &Entry{
		PrivateKey: PEMKey{PEM: []byte("-----BEGIN PRIVATE KEY-----FAKE-----END PRIVATE KEY-----")},
		KeyType:    "RSA",
		Version:    2,
	}

	payload, err := codec.Encode(in)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(payload), "PRIVATE KEY"),
		"encrypted payload must never contain the plaintext PEM substring")

	out, err := codec.Decode(payload)
	require.NoError(t, err)
	require.NotNil(t, out.PrivateKey)
	// The critical regression check: a naive json.Unmarshal into an Entry
	// with an interface-typed PrivateKey field would decode into a
	// map[string]interface{}, not a PEMKey -- this type assertion is what
	// proves entryCodec avoids that trap.
	pemKey, ok := out.PrivateKey.(PEMKey)
	require.True(t, ok, "decoded PrivateKey must be a concrete PEMKey, not map[string]interface{} or nil")
	assert.Equal(t, "-----BEGIN PRIVATE KEY-----FAKE-----END PRIVATE KEY-----", string(pemKey.PEM))
	assert.Equal(t, "RSA", out.KeyType)
	assert.Equal(t, 2, out.Version)
	assert.Nil(t, out.PublicKey)
}

func TestEntryCodec_NilKeys_RoundTrip(t *testing.T) {
	codec := entryCodec{encrypt: fakeEncrypt, decrypt: fakeDecrypt}
	in := &Entry{KeyType: "oct", Version: 1} // both PrivateKey and PublicKey nil

	payload, err := codec.Encode(in)
	require.NoError(t, err)
	out, err := codec.Decode(payload)
	require.NoError(t, err)
	assert.Nil(t, out.PrivateKey)
	assert.Nil(t, out.PublicKey)
}

func TestEntryCodec_Encode_UnexpectedConcreteType_ReturnsError(t *testing.T) {
	codec := entryCodec{encrypt: fakeEncrypt, decrypt: fakeDecrypt}
	// Production code never stores anything but PEMKey (verified), but the
	// codec must fail safe -- not silently drop data -- if that invariant
	// is ever violated.
	in := &Entry{PrivateKey: "not-a-pemkey", KeyType: "RSA", Version: 1}
	_, err := codec.Encode(in)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keycache/... -run TestEntryCodec -v`
Expected: FAIL (build error — `entryCodec` does not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// internal/keycache/l2_codec.go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keycache/... -v`
Expected: PASS (all tests in the package, including this new one)

- [ ] **Step 5: Commit**

```bash
git add internal/keycache/l2_codec.go internal/keycache/l2_codec_test.go
git commit -m "feat(keycache): add entryCodec for correct interface-field L2 round-trip"
```

---

### Task 2: `KeyCodec[keyCacheKey]` — composite key parsing

**Files:**
- Create: `internal/keycache/l2_key_codec.go`
- Test: `internal/keycache/l2_key_codec_test.go`

**Interfaces:**
- Consumes: `keyCacheKey` (existing, unexported).
- Produces: `keycache.keyCacheKeyCodec() cachekit.KeyCodec[keyCacheKey]` (unexported helper, used by `NewCacheWithL2` in Task 3).

- [ ] **Step 1: Write the failing test**

```go
// internal/keycache/l2_key_codec_test.go
package keycache

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyCacheKeyCodec_RoundTrip(t *testing.T) {
	codec := keyCacheKeyCodec()
	k := keyCacheKey{ID: uuid.New(), Version: 3}

	wire := codec.ToWire(k)
	got, ok := codec.FromWire(wire)
	require.True(t, ok)
	assert.Equal(t, k, got)
}

func TestKeyCacheKeyCodec_FromWire_Malformed_ReturnsFalseNotError(t *testing.T) {
	codec := keyCacheKeyCodec()

	for _, bad := range []string{"", "no-colon-here", "not-a-uuid:3", uuid.New().String() + ":not-a-number"} {
		_, ok := codec.FromWire(bad)
		assert.False(t, ok, "input %q must report ok=false, never panic or error", bad)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keycache/... -run TestKeyCacheKeyCodec -v`
Expected: FAIL (build error — `keyCacheKeyCodec` does not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// internal/keycache/l2_key_codec.go
package keycache

import (
	"strconv"
	"strings"

	"github.com/google/uuid"

	"rocketvault/internal/cachekit"
)

// keyCacheKeyCodec turns a keyCacheKey into "<uuid>:<version>" and back.
// FromWire reports ok=false (never an error) for anything malformed, per
// cachekit.KeyCodec's contract -- Range/InvalidateAll must skip such
// entries silently, not fail.
func keyCacheKeyCodec() cachekit.KeyCodec[keyCacheKey] {
	return cachekit.KeyCodec[keyCacheKey]{
		ToWire: func(k keyCacheKey) string {
			return k.ID.String() + ":" + strconv.Itoa(k.Version)
		},
		FromWire: func(w string) (keyCacheKey, bool) {
			idx := strings.LastIndex(w, ":")
			if idx < 0 {
				return keyCacheKey{}, false
			}
			id, err := uuid.Parse(w[:idx])
			if err != nil {
				return keyCacheKey{}, false
			}
			version, err := strconv.Atoi(w[idx+1:])
			if err != nil {
				return keyCacheKey{}, false
			}
			return keyCacheKey{ID: id, Version: version}, true
		},
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keycache/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/keycache/l2_key_codec.go internal/keycache/l2_key_codec_test.go
git commit -m "feat(keycache): add keyCacheKeyCodec for composite-key L2 wire format"
```

---

### Task 3: `NewCacheWithL2` + container wiring

**Files:**
- Modify: `internal/keycache/memory_cache.go`
- Modify: `internal/container/service_container.go`
- Test: `internal/keycache/memory_cache_l2_test.go` (new file)

**Interfaces:**
- Consumes: `entryCodec` (Task 1), `keyCacheKeyCodec` (Task 2), `common.EncryptSecret`/`DecryptSecret`, `c.rocketMemClient` (Plan 04).
- Produces: `keycache.NewCacheWithL2(cfg cachekit.Config, l2 cachekit.L2, l2TTL time.Duration) Cache`.

- [ ] **Step 1: Write the failing test**

```go
// internal/keycache/memory_cache_l2_test.go
package keycache

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cachekit"
)

// fakeL2 mirrors internal/cachekit's own test double -- see the note in
// internal/cache/secret_cache_l2_test.go about each package keeping a
// small local copy.
type fakeL2 struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newFakeL2() *fakeL2 { return &fakeL2{data: make(map[string][]byte)} }
func (f *fakeL2) Get(wireKey string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.data[wireKey]
	return b, ok
}
func (f *fakeL2) Set(wireKey string, payload []byte, _ time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[wireKey] = payload
}
func (f *fakeL2) Invalidate(wireKey string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, wireKey)
}
func (f *fakeL2) Keys(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

var _ cachekit.L2 = (*fakeL2)(nil)

func TestNewCacheWithL2_RoundTrip_AndCiphertextOnWire(t *testing.T) {
	l2 := newFakeL2()
	c := NewCacheWithL2(cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0}, l2, time.Minute)
	defer c.Stop()

	keyID := uuid.New()
	entry := &Entry{PrivateKey: PEMKey{PEM: []byte("-----BEGIN PRIVATE KEY-----SECRET-----END PRIVATE KEY-----")}, KeyType: "RSA", Version: 1}
	c.Set(keyID, 1, entry)

	got, ok := c.Get(keyID, 1)
	require.True(t, ok)
	pemKey, ok := got.PrivateKey.(PEMKey)
	require.True(t, ok)
	assert.Equal(t, entry.PrivateKey.(PEMKey).PEM, pemKey.PEM)

	for wireKey, payload := range l2.data {
		if strings.Contains(wireKey, "rocketvault:key:") {
			assert.False(t, strings.Contains(string(payload), "SECRET"),
				"key PEM plaintext must never appear in the L2 wire payload")
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keycache/... -run TestNewCacheWithL2 -v`
Expected: FAIL (build error — `NewCacheWithL2` does not exist yet)

- [ ] **Step 3: Write minimal implementation**

```go
// append to internal/keycache/memory_cache.go, add "time" and "rocketvault/common" to the import block

// NewCacheWithL2 creates a Cache backed by a TieredCache: cfg's in-process
// cache as L1, l2 as the shared Rocket-mem tier (l2TTL is that tier's own
// entry lifetime). Uses entryCodec (not the generic EncryptedJSONCodec) so
// Entry's interface-typed PrivateKey/PublicKey fields round-trip correctly
// -- see l2_codec.go. Used only when cache.rocket_mem is enabled;
// NewCache's behavior is unchanged.
func NewCacheWithL2(cfg cachekit.Config, l2 cachekit.L2, l2TTL time.Duration) Cache {
	l1 := cachekit.NewFromConfig[keyCacheKey, *Entry](cfg)
	codec := entryCodec{encrypt: common.EncryptSecret, decrypt: common.DecryptSecret}
	return &cacheImpl{
		core: cachekit.NewTieredCache[keyCacheKey, *Entry](l1, l2, codec, keyCacheKeyCodec(), "rocketvault:key:", l2TTL),
	}
}
```

Then, in `internal/container/service_container.go`, replace the existing line (around line 567, per the earlier grep):

```go
c.keyCache = keycache.NewCache(c.cacheConfig.Keys)
```

with:

```go
if c.rocketMemClient != nil {
	c.keyCache = keycache.NewCacheWithL2(c.cacheConfig.Keys, c.rocketMemClient, c.cacheConfig.Keys.TTL)
} else {
	c.keyCache = keycache.NewCache(c.cacheConfig.Keys)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keycache/... -v`
Expected: PASS

Run: `go build ./... && go vet ./... && go test ./...` (whole repo, no tags)
Expected: identical outcome to before this plan started — `c.rocketMemClient` is `nil` by default, so the unchanged `keycache.NewCache` branch is taken.

- [ ] **Step 5: Commit**

```bash
git add internal/keycache/memory_cache.go internal/keycache/memory_cache_l2_test.go internal/container/service_container.go
git commit -m "feat(keycache): add NewCacheWithL2 and wire it into the container"
```
