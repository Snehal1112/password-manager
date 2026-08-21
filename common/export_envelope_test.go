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

	// The full-output comparison above is also satisfied by EncryptWithKey's
	// own fresh GCM nonce alone, so it does not prove the salt was fresh.
	// Isolate the salt field itself to guard against a hardcoded or reused salt.
	var envA, envB struct {
		Salt string `json:"salt"`
	}
	require.NoError(t, json.Unmarshal(a, &envA))
	require.NoError(t, json.Unmarshal(b, &envB))
	assert.NotEqual(t, envA.Salt, envB.Salt, "identical plaintext and passphrase produced the same salt")
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
	assert.True(t, errors.Is(err, ErrPassphraseRequired), "got %v", err)
}

func TestOpenRejectsEmptyPassphrase(t *testing.T) {
	sealed, err := SealExport([]byte("payload"), "pw")
	require.NoError(t, err)

	_, err = OpenExport(sealed, "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPassphraseRequired), "got %v", err)
	// It must not be reported as a wrong passphrase: the caller dropped the
	// passphrase entirely, which is a different bug than a wrong one.
	assert.False(t, errors.Is(err, ErrWrongPassphrase), "empty passphrase should not surface as ErrWrongPassphrase, got %v", err)
}

// mutateSealedParams seals payload normally, then applies mutate to the
// decoded envelope's "params" object (or removes it, if mutate is nil) before
// re-marshalling, mirroring TestOpenRejectsUnknownVersion's pattern for
// producing a malformed-but-otherwise-valid envelope.
func mutateSealedParams(t *testing.T, mutate func(params map[string]any)) []byte {
	t.Helper()

	sealed, err := SealExport([]byte("payload"), "pw")
	require.NoError(t, err)

	var env map[string]any
	require.NoError(t, json.Unmarshal(sealed, &env))

	if mutate == nil {
		delete(env, "params")
	} else {
		params, _ := env["params"].(map[string]any)
		if params == nil {
			params = map[string]any{}
		}
		mutate(params)
		env["params"] = params
	}

	mutated, err := json.Marshal(env)
	require.NoError(t, err)
	return mutated
}

func TestOpenRejectsMissingParams(t *testing.T) {
	mutated := mutateSealedParams(t, nil)

	assert.NotPanics(t, func() {
		_, err := OpenExport(mutated, "pw")
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrWrongPassphrase), "malformed file should not be reported as ErrWrongPassphrase, got %v", err)
	})
}

func TestOpenRejectsZeroTimeParam(t *testing.T) {
	mutated := mutateSealedParams(t, func(params map[string]any) {
		params["time"] = 0
	})

	assert.NotPanics(t, func() {
		_, err := OpenExport(mutated, "pw")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "time")
		assert.False(t, errors.Is(err, ErrWrongPassphrase), "malformed file should not be reported as ErrWrongPassphrase, got %v", err)
	})
}

func TestOpenRejectsZeroThreadsParam(t *testing.T) {
	mutated := mutateSealedParams(t, func(params map[string]any) {
		params["threads"] = 0
	})

	assert.NotPanics(t, func() {
		_, err := OpenExport(mutated, "pw")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "threads")
		assert.False(t, errors.Is(err, ErrWrongPassphrase), "malformed file should not be reported as ErrWrongPassphrase, got %v", err)
	})
}

func TestOpenRejectsAbsurdMemoryParam(t *testing.T) {
	mutated := mutateSealedParams(t, func(params map[string]any) {
		params["memory"] = 4294967295
	})

	assert.NotPanics(t, func() {
		_, err := OpenExport(mutated, "pw")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "memory")
		assert.False(t, errors.Is(err, ErrWrongPassphrase), "malformed file should not be reported as ErrWrongPassphrase, got %v", err)
	})
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
