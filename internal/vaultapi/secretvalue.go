package vaultapi

// redactedPlaceholder is what a SecretValue renders as on every path except
// an explicit Reveal.
const redactedPlaceholder = "[REDACTED]"

// SecretValue holds a secret's plaintext.
//
// The server returns the value on every GET of a secret and offers no way to
// suppress it (api/secrets.go:462), so the plaintext arrives whether or not
// the caller wants it. This type therefore makes discarding it the default:
// String, GoString and MarshalJSON all redact, so a value cannot reach a log
// line or a marshalled response by accident. Reading it is the deliberate act
// of calling Reveal.
type SecretValue string

// Reveal returns the plaintext. Call it only where the value is genuinely
// needed, and never on a path that logs.
func (v SecretValue) Reveal() string { return string(v) }

// String renders the value as redacted, covering %s and %v.
func (v SecretValue) String() string { return redactedPlaceholder }

// GoString renders the value as redacted, covering %#v.
func (v SecretValue) GoString() string { return redactedPlaceholder }

// MarshalJSON renders the value as redacted, so a struct carrying one is safe
// to marshal.
func (v SecretValue) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedPlaceholder + `"`), nil
}

// Zero clears the value.
//
// Go strings are immutable and the runtime may have copied this one, so this
// cannot erase every copy. It drops this reference, bounding how long the
// plaintext stays reachable — the same guarantee cachekit.Zeroable provides.
func (v *SecretValue) Zero() { *v = "" }
