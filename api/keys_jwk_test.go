package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// jwkStubKeyService returns a fixed key and JWK, and records the version the
// handler asked for.
type jwkStubKeyService struct {
	scopeStubKeyService

	jwk         *model.PublicJWK
	jwkErr      error
	version     *model.KeyVersion
	askedFor    int
	jwkCallSeen bool
}

func (s *jwkStubKeyService) GetPublicJWK(_ context.Context, _ uuid.UUID, version int, _ model.Scope) (*model.PublicJWK, error) {
	s.askedFor = version
	s.jwkCallSeen = true
	return s.jwk, s.jwkErr
}

func (s *jwkStubKeyService) GetKeyVersion(_ context.Context, _ uuid.UUID, _ int, _ model.Scope) (*model.KeyVersion, error) {
	return s.version, nil
}

// TestGetKey_EmitsPublicJWKComponents is the handler half of the B34
// regression. The service-layer test proves GetPublicJWK derives components;
// this proves the handler actually puts them on the wire. Before the fix,
// buildKeyResponse extracted them itself from the encrypted key.Value and
// discarded the error, so these four fields were always absent.
func TestGetKey_EmitsPublicJWKComponents(t *testing.T) {
	keyID := uuid.New()
	svc := &jwkStubKeyService{
		scopeStubKeyService: scopeStubKeyService{
			key: &model.Key{ID: keyID, Name: "k", Type: model.KeyTypeRSA, Enabled: true},
		},
		jwk: &model.PublicJWK{N: "modulus-b64", E: "AQAB"},
	}

	c, w, r := newKeyHandlerFixture(t, svc, keyID, "team-a")
	getKey(c, w, r)
	require.Nil(t, c.Err)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "modulus-b64", body["n"], "n must reach the response body")
	assert.Equal(t, "AQAB", body["e"])
	assert.NotContains(t, body, "x", "an RSA key emits no EC coordinates")
	assert.Equal(t, 0, svc.askedFor, "a single-key response asks for the current version")
}

// TestGetKey_JWKFailureDoesNotFailTheRequest pins the deliberate choice that a
// JWK derivation failure omits the components rather than 500ing a response
// whose primary content is already in hand.
func TestGetKey_JWKFailureDoesNotFailTheRequest(t *testing.T) {
	keyID := uuid.New()
	svc := &jwkStubKeyService{
		scopeStubKeyService: scopeStubKeyService{
			key: &model.Key{ID: keyID, Name: "k", Type: model.KeyTypeRSA, Enabled: true},
		},
		jwkErr: assert.AnError,
	}

	c, w, r := newKeyHandlerFixture(t, svc, keyID, "team-a")
	getKey(c, w, r)
	require.Nil(t, c.Err, "a JWK failure must not fail the request")

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, keyID.String(), body["id"])
	assert.NotContains(t, body, "n", "components are omitted, not empty-stringed")
}

// TestGetKeyVersion_EmitsThatVersionsJWK pins that the version route asks for
// the version being addressed, not the key's current one -- the entire point
// of addressing a version.
func TestGetKeyVersion_EmitsThatVersionsJWK(t *testing.T) {
	keyID := uuid.New()
	svc := &jwkStubKeyService{
		scopeStubKeyService: scopeStubKeyService{
			key: &model.Key{ID: keyID, Name: "k", Type: model.KeyTypeECDSA, Enabled: true},
		},
		jwk:     &model.PublicJWK{X: "x-b64", Y: "y-b64"},
		version: &model.KeyVersion{KeyID: keyID, Version: 2},
	}

	c, w, r := newKeyHandlerFixture(t, svc, keyID, "team-a")
	c.Params.Version = 2
	getKeyVersion(c, w, r)
	require.Nil(t, c.Err)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "x-b64", body["x"])
	assert.Equal(t, "y-b64", body["y"])
	assert.Equal(t, float64(2), body["version"])
	assert.NotContains(t, body, "value", "a version response must never carry material")
	assert.Equal(t, 2, svc.askedFor, "the version route must ask for version 2, not 0")
}
