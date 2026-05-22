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

// Package api — internal tests for oauth2 handlers.
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

// TestCreateServiceAccount_NonAdminForbidden verifies that a non-admin user
// receives 403 Forbidden when attempting to create a service account.
func TestCreateServiceAccount_NonAdminForbidden(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/service-accounts", strings.NewReader(`{"name":"svc"}`))

	c := &Context{
		// App is nil — the role guard must fire before any App access.
		Claims: jwt.MapClaims{
			"role": model.RoleUser,
		},
	}

	createServiceAccount(c, w, r)

	// Write the error set on c to w, as the middleware wrapper would do.
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestCreateServiceAccount_AdminAllowed verifies that an admin role passes
// the role guard and proceeds into the handler body (past the permission check).
// App is left nil intentionally so the handler panics when it reaches the
// service call — we use recover to catch that and confirm no 403 was set.
func TestCreateServiceAccount_AdminAllowed(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/service-accounts", strings.NewReader(`{"name":"svc"}`))

	c := &Context{
		Claims: jwt.MapClaims{
			"role": model.RoleAdmin,
		},
	}

	w := httptest.NewRecorder()

	// Catch the nil-pointer panic that occurs when the handler reaches
	// c.App.ServiceContainer — that means the role guard was passed.
	func() {
		defer func() { recover() }() //nolint:errcheck
		createServiceAccount(c, w, r)
	}()

	// The guard must not have set a 403 for an admin user.
	if c.Err != nil {
		assert.NotEqual(t, http.StatusForbidden, c.Err.StatusCode,
			"admin should not receive a 403 from the role guard")
	}
}
