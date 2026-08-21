# Shared Foundations (pwgen + export envelope) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the two shared pieces that B35 and B36 depend on — a reusable password generator and a passphrase-sealed export envelope — without changing any existing behavior.

**Architecture:** `generatePassword` moves out of `cmd/secrets` (a `cmd` package a service must not import) into `internal/pwgen`, preserving its exact semantics and its seven existing tests. A new `common/export_envelope.go` seals bytes under a passphrase using argon2id key derivation plus the AES-256-GCM primitives that already exist in `common/encrypt.go`. A passphrase resolver handles file, environment and interactive sources uniformly.

**Tech Stack:** Go 1.24.2, `golang.org/x/crypto/argon2`, `golang.org/x/term`, testify.

**Spec:** `docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md`

## Global Constraints

- Go 1.24.2. Do not raise the version floor.
- **No new module dependencies.** `golang.org/x/crypto` v0.48.0 and
  `golang.org/x/term` are already in `go.mod`/`go.sum` and were verified to
  compile and run offline on 2026-08-21.
- Comments are short, full sentences ending in a punctuation mark.
- This plan changes **no** user-visible behavior. `secrets generate-password`
  must produce output indistinguishable from today's.
- Never log, print, or include a passphrase or plaintext secret in an error
  message.
- Argon2id parameters: `time=1`, `memory=65536` (64 MiB), `threads=4`,
  `keyLen=32`, `saltLen=16`.

---

### Task 1: Extract the password generator into `internal/pwgen`

**Files:**
- Create: `internal/pwgen/pwgen.go`
- Create: `internal/pwgen/pwgen_test.go`
- Modify: `cmd/secrets/generate.go` (remove `generatePassword`, call `pwgen`)
- Modify: `cmd/secrets/generate_test.go` (drop the moved unit tests)

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```go
  package pwgen

  type Options struct {
      Length  int
      Upper   bool
      Lower   bool
      Numbers bool
      Special bool
  }

  func DefaultOptions() Options          // Length 16, all four sets true
  func Generate(opts Options) (string, error)
  ```

- [ ] **Step 1: Write the failing test**

Create `internal/pwgen/pwgen_test.go`. These assertions are ported from
`cmd/secrets/generate_test.go` so the extraction is provably behavior-preserving.

```go
package pwgen

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateLength(t *testing.T) {
	got, err := Generate(Options{Length: 24, Upper: true, Lower: true, Numbers: true, Special: true})
	require.NoError(t, err)
	assert.Len(t, got, 24)
}

func TestGenerateRejectsZeroLength(t *testing.T) {
	_, err := Generate(Options{Length: 0, Lower: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 1")
}

func TestGenerateRejectsEmptyCharset(t *testing.T) {
	_, err := Generate(Options{Length: 8})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one character type")
}

func TestGenerateHonoursCharsetSelection(t *testing.T) {
	got, err := Generate(Options{Length: 32, Numbers: true})
	require.NoError(t, err)
	for _, r := range got {
		assert.True(t, r >= '0' && r <= '9', "unexpected rune %q", r)
	}
}

func TestGenerateHasNoRepeatingRunOfThree(t *testing.T) {
	for range 200 {
		got, err := Generate(Options{Length: 16, Lower: true, Numbers: true})
		require.NoError(t, err)
		runes := []rune(got)
		for i := 0; i+2 < len(runes); i++ {
			if runes[i] == runes[i+1] && runes[i+1] == runes[i+2] {
				t.Fatalf("three identical characters in a row: %q", got)
			}
		}
	}
}

func TestGenerateIncludesEachEnabledSet(t *testing.T) {
	got, err := Generate(Options{Length: 16, Upper: true, Lower: true, Numbers: true, Special: true})
	require.NoError(t, err)
	assert.True(t, strings.ContainsAny(got, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "no uppercase in %q", got)
	assert.True(t, strings.ContainsAny(got, "abcdefghijklmnopqrstuvwxyz"), "no lowercase in %q", got)
	assert.True(t, strings.ContainsAny(got, "0123456789"), "no digit in %q", got)
	assert.True(t, strings.ContainsAny(got, "!@#$%^&*()-_=+[]{}|;:,.<>?"), "no special in %q", got)
}

func TestGenerateIsNotDeterministic(t *testing.T) {
	seen := make(map[string]struct{}, 50)
	for range 50 {
		got, err := Generate(DefaultOptions())
		require.NoError(t, err)
		seen[got] = struct{}{}
	}
	assert.Greater(t, len(seen), 45, "generator appears to repeat itself")
}

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	assert.Equal(t, 16, o.Length)
	assert.True(t, o.Upper && o.Lower && o.Numbers && o.Special)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/pwgen/ -v`
Expected: FAIL — the package does not exist yet.

- [ ] **Step 3: Create the package**

Create `internal/pwgen/pwgen.go`. Copy the body of `generatePassword` from
`cmd/secrets/generate.go:116` **verbatim** — including the guaranteed-injection
loop and the no-three-in-a-row rule — and wrap it in the `Options` signature.
Do not "improve" the algorithm; this task is a move, and any behavior change
here is a defect.

```go
// Package pwgen generates random passwords. It lives outside cmd/ so that
// service-layer callers can use it without importing a command package.
package pwgen

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	numberChars  = "0123456789"
	specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// Options selects the length and character sets for a generated password.
type Options struct {
	Length  int
	Upper   bool
	Lower   bool
	Numbers bool
	Special bool
}

// DefaultOptions returns the generator settings the CLI uses by default.
func DefaultOptions() Options {
	return Options{Length: 16, Upper: true, Lower: true, Numbers: true, Special: true}
}

// Generate returns a random password matching opts. It guarantees at least one
// character from every enabled set and never emits three identical characters
// in a row.
func Generate(opts Options) (string, error) {
	// Body ported verbatim from the former cmd/secrets.generatePassword.
	...
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/pwgen/ -v`
Expected: PASS, all eight tests.

- [ ] **Step 5: Rewire the CLI to the new package**

In `cmd/secrets/generate.go`, delete `generatePassword` entirely and change the
`RunE` call site:

```go
password, err := pwgen.Generate(pwgen.Options{
	Length:  length,
	Upper:   useUpper,
	Lower:   useLower,
	Numbers: useNumbers,
	Special: useSpecial,
})
if err != nil {
	return fmt.Errorf("failed to generate password: %w", err)
}
```

Add `"rocketvault/internal/pwgen"` to the imports. Remove `crypto/rand` and
`math/big` from that file if nothing else there uses them.

- [ ] **Step 6: Move the old unit tests out**

In `cmd/secrets/generate_test.go`, delete the seven tests that call
`generatePassword` directly (`TestGeneratePasswordUsesCSPRNG`,
`TestGeneratePasswordHasNoRepeatingRun`, `TestGeneratePasswordLength`,
`TestGeneratePasswordCharsetEnforcement`, `TestGeneratePasswordAllCharsetTypes`,
`TestGeneratePasswordRejectsEmptyCharset`, `TestGeneratePasswordRejectsZeroLength`)
— they now live in `internal/pwgen/pwgen_test.go`.

**Keep** `TestGenerateCmd_InvalidLength_ReturnsError`: it exercises the command
wiring, not the generator, and must still pass to prove the rewire works.

- [ ] **Step 7: Verify nothing regressed**

Run:
```bash
go build ./...
go test ./internal/pwgen/ ./cmd/secrets/ -v
gofmt -l internal/pwgen cmd/secrets
go vet ./internal/pwgen/ ./cmd/secrets/
```
Expected: all pass, `gofmt` silent.

- [ ] **Step 8: Confirm the user-visible output is unchanged**

Run: `go run . secrets generate-password --length 20 --special=false`
Expected: a 20-character password with no special characters. Run it twice and
confirm the two differ.

- [ ] **Step 9: Commit**

```bash
git add internal/pwgen cmd/secrets/generate.go cmd/secrets/generate_test.go
git commit -m "refactor(pwgen): extract password generator to internal/pwgen

Moves generatePassword out of cmd/secrets so service-layer callers can
use it without importing a command package. Behavior is unchanged; the
generator's unit tests move with it."
```

---

### Task 2: Passphrase-sealed export envelope

**Files:**
- Create: `common/export_envelope.go`
- Create: `common/export_envelope_test.go`

**Interfaces:**
- Consumes: `common.EncryptWithKey(value string, key []byte) (string, error)` and
  `common.DecryptWithKey(encryptedValue string, key []byte) (string, error)`,
  both already in `common/encrypt.go`.
- Produces:
  ```go
  func SealExport(plaintext []byte, passphrase string) ([]byte, error)
  func OpenExport(data []byte, passphrase string) ([]byte, error)
  func IsSealedExport(data []byte) bool

  var ErrWrongPassphrase = errors.New("wrong passphrase or corrupted export file")
  var ErrUnsupportedExportVersion = errors.New("unsupported export format version")
  ```

- [ ] **Step 1: Write the failing test**

Create `common/export_envelope_test.go`:

```go
package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSealOpenRoundTrip(t *testing.T) {
	plaintext := []byte(`[{"name":"db-password","value":"hunter2"}]`)

	sealed, err := SealExport(plaintext, "correct horse battery staple")
	require.NoError(t, err)

	opened, err := OpenExport(sealed, "correct horse battery staple")
	require.NoError(t, err)
	assert.Equal(t, plaintext, opened)
}

func TestSealedOutputLeaksNoPlaintext(t *testing.T) {
	plaintext := []byte(`[{"name":"db-password","value":"hunter2"}]`)

	sealed, err := SealExport(plaintext, "pw")
	require.NoError(t, err)

	assert.False(t, bytes.Contains(sealed, []byte("hunter2")), "ciphertext contains the secret value")
	assert.False(t, bytes.Contains(sealed, []byte("db-password")), "ciphertext contains the secret name")
}

func TestOpenWithWrongPassphraseFails(t *testing.T) {
	sealed, err := SealExport([]byte("payload"), "right")
	require.NoError(t, err)

	_, err = OpenExport(sealed, "wrong")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWrongPassphrase), "got %v", err)
}

func TestSealUsesFreshSaltAndNonce(t *testing.T) {
	a, err := SealExport([]byte("payload"), "pw")
	require.NoError(t, err)
	b, err := SealExport([]byte("payload"), "pw")
	require.NoError(t, err)

	assert.NotEqual(t, a, b, "identical plaintext and passphrase produced identical ciphertext")
}

func TestIsSealedExportDetection(t *testing.T) {
	sealed, err := SealExport([]byte("payload"), "pw")
	require.NoError(t, err)

	assert.True(t, IsSealedExport(sealed))
	assert.False(t, IsSealedExport([]byte(`[{"name":"plain"}]`)))
	assert.False(t, IsSealedExport([]byte("not json at all")))
	assert.False(t, IsSealedExport(nil))
}

func TestOpenRejectsUnknownVersion(t *testing.T) {
	sealed, err := SealExport([]byte("payload"), "pw")
	require.NoError(t, err)

	var env map[string]any
	require.NoError(t, json.Unmarshal(sealed, &env))
	env["rocketvault_export"] = 99
	bumped, err := json.Marshal(env)
	require.NoError(t, err)

	_, err = OpenExport(bumped, "pw")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnsupportedExportVersion), "got %v", err)
}

func TestSealRejectsEmptyPassphrase(t *testing.T) {
	_, err := SealExport([]byte("payload"), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "passphrase")
}

func TestEnvelopeRecordsItsKDFParams(t *testing.T) {
	sealed, err := SealExport([]byte("payload"), "pw")
	require.NoError(t, err)

	var env struct {
		Version int    `json:"rocketvault_export"`
		KDF     string `json:"kdf"`
		Params  struct {
			Time    uint32 `json:"time"`
			Memory  uint32 `json:"memory"`
			Threads uint8  `json:"threads"`
		} `json:"params"`
		Salt string `json:"salt"`
	}
	require.NoError(t, json.Unmarshal(sealed, &env))

	assert.Equal(t, 1, env.Version)
	assert.Equal(t, "argon2id", env.KDF)
	assert.Equal(t, uint32(1), env.Params.Time)
	assert.Equal(t, uint32(65536), env.Params.Memory)
	assert.Equal(t, uint8(4), env.Params.Threads)
	assert.NotEmpty(t, env.Salt)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./common/ -run 'TestSeal|TestOpen|TestIsSealed|TestEnvelope' -v`
Expected: FAIL — `undefined: SealExport`.

- [ ] **Step 3: Implement the envelope**

Create `common/export_envelope.go`:

```go
package common

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// exportFormatVersion is both the format marker and its version. Readers refuse
// a version they do not know rather than misparsing a future format.
const exportFormatVersion = 1

// Argon2id cost parameters. They are written into every envelope so that
// raising them later does not strand existing export files.
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// ErrWrongPassphrase is returned when an export cannot be opened with the
// supplied passphrase. It deliberately does not distinguish a wrong passphrase
// from a corrupted file, since GCM cannot tell them apart.
var ErrWrongPassphrase = errors.New("wrong passphrase or corrupted export file")

// ErrUnsupportedExportVersion is returned for an envelope written by a newer
// RocketVault than this one.
var ErrUnsupportedExportVersion = errors.New("unsupported export format version")

type argonParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

type exportEnvelope struct {
	Version    int         `json:"rocketvault_export"`
	KDF        string      `json:"kdf"`
	Params     argonParams `json:"params"`
	Salt       string      `json:"salt"`
	Ciphertext string      `json:"ciphertext"`
}

// SealExport encrypts plaintext under a key derived from passphrase and returns
// a self-describing JSON envelope.
func SealExport(plaintext []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("a passphrase is required to seal an export")
	}

	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// EncryptWithKey already does AES-256-GCM with a random nonce and returns
	// base64, so the nonce travels inside the ciphertext field.
	ciphertext, err := EncryptWithKey(string(plaintext), key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt export: %w", err)
	}

	return json.MarshalIndent(exportEnvelope{
		Version:    exportFormatVersion,
		KDF:        "argon2id",
		Params:     argonParams{Time: argonTime, Memory: argonMemory, Threads: argonThreads},
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Ciphertext: ciphertext,
	}, "", "  ")
}

// OpenExport reverses SealExport.
func OpenExport(data []byte, passphrase string) ([]byte, error) {
	var env exportEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("not a RocketVault export file: %w", err)
	}
	if env.Version != exportFormatVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedExportVersion, env.Version)
	}
	if env.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported key derivation function %q", env.KDF)
	}

	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, fmt.Errorf("malformed salt: %w", err)
	}

	key := argon2.IDKey([]byte(passphrase), salt, env.Params.Time, env.Params.Memory, env.Params.Threads, argonKeyLen)

	plaintext, err := DecryptWithKey(env.Ciphertext, key)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return []byte(plaintext), nil
}

// IsSealedExport reports whether data looks like an envelope written by
// SealExport, so callers can decide whether a passphrase is needed.
func IsSealedExport(data []byte) bool {
	var probe struct {
		Version int `json:"rocketvault_export"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Version != 0
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./common/ -run 'TestSeal|TestOpen|TestIsSealed|TestEnvelope' -v`
Expected: PASS, all eight tests.

- [ ] **Step 5: Run the whole common package**

Run: `go test ./common/ && gofmt -l common && go vet ./common/`
Expected: pass, `gofmt` silent. The existing `common/encrypt_key_test.go` must
still pass — this task adds to that package and changes nothing in it.

- [ ] **Step 6: Commit**

```bash
git add common/export_envelope.go common/export_envelope_test.go
git commit -m "feat(common): add passphrase-sealed export envelope

Adds SealExport/OpenExport/IsSealedExport: argon2id key derivation over
the existing AES-256-GCM primitives, in a versioned JSON envelope that
records its own KDF parameters. Groundwork for B36."
```

---

### Task 3: Passphrase resolution helper

**Files:**
- Create: `common/passphrase.go`
- Create: `common/passphrase_test.go`

**Interfaces:**
- Consumes: `golang.org/x/term`.
- Produces:
  ```go
  type PassphraseSource struct {
      File    string // --passphrase-file; first line, trimmed
      EnvVar  string // environment variable name to consult
      Prompt  string // text shown when prompting interactively
      Confirm bool   // prompt twice and require a match
  }

  func ResolvePassphrase(src PassphraseSource) (string, error)

  var ErrNoPassphraseAvailable = errors.New("no passphrase available and stdin is not a terminal")
  ```

Resolution order is file, then environment, then interactive prompt. The order
matters: automation must be able to win without a terminal.

- [ ] **Step 1: Write the failing test**

Create `common/passphrase_test.go`. The interactive branch is not unit-tested —
it requires a TTY — so the tests cover the two non-interactive sources and the
no-source failure.

```go
package common

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePassphraseFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw.txt")
	require.NoError(t, os.WriteFile(path, []byte("  s3cret  \nignored second line\n"), 0o600))

	got, err := ResolvePassphrase(PassphraseSource{File: path})
	require.NoError(t, err)
	assert.Equal(t, "s3cret", got, "first line should be used and trimmed")
}

func TestResolvePassphraseFromFileMissing(t *testing.T) {
	_, err := ResolvePassphrase(PassphraseSource{File: filepath.Join(t.TempDir(), "absent")})
	require.Error(t, err)
}

func TestResolvePassphraseRejectsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	require.NoError(t, os.WriteFile(path, []byte("\n"), 0o600))

	_, err := ResolvePassphrase(PassphraseSource{File: path})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestResolvePassphraseFromEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_TEST_PASSPHRASE", "from-env")

	got, err := ResolvePassphrase(PassphraseSource{EnvVar: "ROCKETVAULT_TEST_PASSPHRASE"})
	require.NoError(t, err)
	assert.Equal(t, "from-env", got)
}

func TestResolvePassphraseFilePrecedesEnv(t *testing.T) {
	t.Setenv("ROCKETVAULT_TEST_PASSPHRASE", "from-env")
	dir := t.TempDir()
	path := filepath.Join(dir, "pw.txt")
	require.NoError(t, os.WriteFile(path, []byte("from-file"), 0o600))

	got, err := ResolvePassphrase(PassphraseSource{File: path, EnvVar: "ROCKETVAULT_TEST_PASSPHRASE"})
	require.NoError(t, err)
	assert.Equal(t, "from-file", got)
}

func TestResolvePassphraseNoSourceNonInteractive(t *testing.T) {
	// go test runs with stdin detached, so this exercises the non-TTY branch.
	_, err := ResolvePassphrase(PassphraseSource{EnvVar: "ROCKETVAULT_DEFINITELY_UNSET"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoPassphraseAvailable), "got %v", err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./common/ -run TestResolvePassphrase -v`
Expected: FAIL — `undefined: ResolvePassphrase`.

- [ ] **Step 3: Implement the resolver**

Create `common/passphrase.go`:

```go
package common

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrNoPassphraseAvailable is returned when no passphrase source is configured
// and there is no terminal to prompt on. Callers must treat this as fatal and
// must never fall back to writing plaintext.
var ErrNoPassphraseAvailable = errors.New("no passphrase available and stdin is not a terminal")

// PassphraseSource describes where a passphrase may be read from.
type PassphraseSource struct {
	File    string
	EnvVar  string
	Prompt  string
	Confirm bool
}

// ResolvePassphrase returns a passphrase from the first available source: an
// explicit file, then an environment variable, then an interactive prompt.
func ResolvePassphrase(src PassphraseSource) (string, error) {
	if src.File != "" {
		return passphraseFromFile(src.File)
	}
	if src.EnvVar != "" {
		if v := os.Getenv(src.EnvVar); v != "" {
			return v, nil
		}
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", ErrNoPassphraseAvailable
	}
	return promptPassphrase(src)
}

func passphraseFromFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to read passphrase file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("failed to read passphrase file: %w", err)
		}
		return "", fmt.Errorf("passphrase file %s is empty", path)
	}
	pass := strings.TrimSpace(scanner.Text())
	if pass == "" {
		return "", fmt.Errorf("passphrase file %s is empty", path)
	}
	return pass, nil
}

func promptPassphrase(src PassphraseSource) (string, error) {
	prompt := src.Prompt
	if prompt == "" {
		prompt = "Passphrase: "
	}

	fmt.Fprint(os.Stderr, prompt) //nolint:errcheck
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) //nolint:errcheck
	if err != nil {
		return "", fmt.Errorf("failed to read passphrase: %w", err)
	}
	if len(first) == 0 {
		return "", errors.New("passphrase must not be empty")
	}

	if src.Confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ") //nolint:errcheck
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)                       //nolint:errcheck
		if err != nil {
			return "", fmt.Errorf("failed to read passphrase confirmation: %w", err)
		}
		if string(first) != string(second) {
			return "", errors.New("passphrases do not match")
		}
	}

	return string(first), nil
}
```

The prompt writes to stderr, not stdout, so that a command whose stdout is
redirected to a file does not have the prompt land in that file.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./common/ -run TestResolvePassphrase -v`
Expected: PASS, all six tests.

- [ ] **Step 5: Full verification**

Run:
```bash
go build ./...
go test ./common/ ./internal/pwgen/ ./cmd/...
gofmt -l common internal/pwgen
go vet ./common/ ./internal/pwgen/
```
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add common/passphrase.go common/passphrase_test.go
git commit -m "feat(common): add passphrase resolution helper

Reads a passphrase from a file, an environment variable, or an
interactive prompt, in that order, and fails explicitly when none is
available rather than letting a caller fall back to plaintext."
```

---

## Definition of Done

- `internal/pwgen` exists with eight passing tests; `secrets generate-password`
  behaves exactly as before.
- `common.SealExport` / `OpenExport` / `IsSealedExport` exist and round-trip,
  with a test proving the sealed bytes contain neither the secret name nor value.
- `common.ResolvePassphrase` exists and fails with `ErrNoPassphraseAvailable`
  rather than silently proceeding.
- `go build ./...`, `go test ./...`, `gofmt -l`, `go vet` all clean.
- No new module dependency in `go.mod`.
