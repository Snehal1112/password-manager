package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

// decodeBody decodes the request body into a T.
//
// On failure it sets the same 400 the twenty hand-rolled call sites set, so
// the response is unchanged. The zero T is returned alongside false; callers
// must check ok rather than inspecting the value.
func decodeBody[T any](c *Context, r *http.Request) (T, bool) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		c.SetInvalidParam("request body")
		return v, false
	}
	return v, true
}

// resourceID parses a path parameter as a UUID.
//
// param is the parameter's wire name ("key_id", "secret_id", ...) and is what
// reaches the client in the error, so it must match what the call site used
// before. It is a separate argument rather than being derived from raw because
// raw is the value, not the name.
//
// This is deliberately not generic over the parsed type: every one of the
// fifty-one call sites parses a UUID, and a type-parameterized version would
// add a constraint nothing needs.
func resourceID(c *Context, raw, param string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	if err != nil {
		c.SetInvalidParam(param)
		return uuid.Nil, false
	}
	return id, true
}

// b64Field decodes a standard-encoding base64 request field.
//
// name is the field's wire name, and the message is built to match the eight
// existing sites verbatim: "<name>: must be valid base64".
func b64Field(c *Context, value, name string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		c.SetInvalidParam(name + ": must be valid base64")
		return nil, false
	}
	return decoded, true
}
