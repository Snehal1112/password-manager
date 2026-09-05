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
