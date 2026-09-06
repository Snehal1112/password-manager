/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package api

import (
	"net/http"

	"rocketvault/internal/container"
	"rocketvault/model"
)

// rotateKey rotates a cryptographic key by generating a new key pair and revoking the old key.
func rotateKey(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	// Rotate the key. The scoped read inside the service is the access check.
	result, err := keyService.RotateKey(r.Context(), keyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	// Fetch the full key record so buildKeyResponse can inspect the stored
	// value, using the same scope that authorized the rotation.
	key, err := keyService.GetKey(r.Context(), result.KeyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	writeJSON(w, buildKeyResponse(key, keyJWK(c, r, keyService, key.ID, scope, 0)))
}

// listKeyVersions returns the version history for a key, excluding raw key material.
func listKeyVersions(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	// KeyService.ListKeyVersions does the scope-aware auth check internally,
	// exactly like getKey on this same route, before delegating to the
	// repository.
	versions, err := keyService.ListKeyVersions(r.Context(), keyID, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	// Return an empty array rather than null when no versions exist.
	if versions == nil {
		versions = []model.KeyVersion{}
	}

	writeJSON(w, map[string]interface{}{"versions": versions})
}

// getKeyVersion retrieves metadata for one version of the vault key
// identified by {key_id}. Never returns key material — see model.KeyVersion.
func getKeyVersion(c *Context, w http.ResponseWriter, r *http.Request) {
	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	keyService, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	scope, ok := scopeFromRequest(c, r)
	if !ok {
		return
	}

	version, err := keyService.GetKeyVersion(r.Context(), keyID, c.Params.Version, scope)
	if err != nil {
		writeKeyError(c, err)
		return
	}

	// The public components for THIS version, not the key's current ones --
	// that is the whole point of addressing a version.
	resp := KeyVersionResponse{KeyVersion: *version}
	if jwk := keyJWK(c, r, keyService, keyID, scope, c.Params.Version); jwk != nil {
		resp.N, resp.E, resp.X, resp.Y = jwk.N, jwk.E, jwk.X, jwk.Y
	}

	writeJSON(w, resp)
}
