package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var sigHeaderRE = regexp.MustCompile(`^t=(\d+),v1=([0-9a-f]+)$`)

var (
	ErrMissingSignature  = errors.New("missing or malformed X-RocketVault-Signature header")
	ErrTimestampSkew     = errors.New("signature timestamp outside tolerance")
	ErrSignatureMismatch = errors.New("signature does not match")
)

// Sign computes the v1 signature over timestamp and the exact raw body
// bytes, per docs/superpowers/specs/2026-08-20-webhook-delivery-primitive-design.md.
// secret is the 43-character base64url string printed by `vault-webhook set`,
// used as the HMAC key exactly as-is — never base64-decoded first.
func Sign(secret string, timestamp int64, body []byte) string {
	signedString := strconv.FormatInt(timestamp, 10) + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedString)) //nolint:errcheck
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks an X-RocketVault-Signature header value ("t=<unix>,v1=<hex>")
// against secret and the raw request body, rejecting a timestamp further
// than tolerance from now.
func Verify(secret, header string, body []byte, tolerance time.Duration, now time.Time) error {
	m := sigHeaderRE.FindStringSubmatch(header)
	if m == nil {
		return ErrMissingSignature
	}

	ts, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return fmt.Errorf("parse signature timestamp: %w", err)
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return ErrTimestampSkew
	}

	expected := Sign(secret, ts, body)
	if !hmac.Equal([]byte(expected), []byte(m[2])) {
		return ErrSignatureMismatch
	}
	return nil
}
