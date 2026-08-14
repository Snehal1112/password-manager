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

// Package api — internal tests for unexported Context accessor helpers.
package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"rocketvault/app"
)

// TestContext_SecretSvc_NilApp_SetsErr verifies that secretSvc sets c.Err
// and returns nil when c.App is nil.
func TestContext_SecretSvc_NilApp_SetsErr(t *testing.T) {
	ctx := &Context{App: nil}
	svc := ctx.secretSvc()
	assert.Nil(t, svc)
	assert.NotNil(t, ctx.Err)
	assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}

// TestContext_SecretSvc_NilContainer_SetsErr verifies that secretSvc sets
// c.Err and returns nil when the service container is nil.
func TestContext_SecretSvc_NilContainer_SetsErr(t *testing.T) {
	ctx := &Context{App: &app.App{ServiceContainer: nil}}
	svc := ctx.secretSvc()
	assert.Nil(t, svc)
	assert.NotNil(t, ctx.Err)
	assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}

// TestContext_KeySvc_NilApp_SetsErr verifies that keySvc sets c.Err and
// returns nil when c.App is nil.
func TestContext_KeySvc_NilApp_SetsErr(t *testing.T) {
	ctx := &Context{App: nil}
	svc := ctx.keySvc()
	assert.Nil(t, svc)
	assert.NotNil(t, ctx.Err)
	assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}

// TestContext_KeySvc_NilContainer_SetsErr verifies that keySvc sets c.Err
// and returns nil when the service container is nil.
func TestContext_KeySvc_NilContainer_SetsErr(t *testing.T) {
	ctx := &Context{App: &app.App{ServiceContainer: nil}}
	svc := ctx.keySvc()
	assert.Nil(t, svc)
	assert.NotNil(t, ctx.Err)
	assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}

// TestContext_UserSvc_NilApp_SetsErr verifies that userSvc sets c.Err and
// returns nil when c.App is nil.
func TestContext_UserSvc_NilApp_SetsErr(t *testing.T) {
	ctx := &Context{App: nil}
	svc := ctx.userSvc()
	assert.Nil(t, svc)
	assert.NotNil(t, ctx.Err)
	assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}

// TestContext_UserSvc_NilContainer_SetsErr verifies that userSvc sets c.Err
// and returns nil when the service container is nil.
func TestContext_UserSvc_NilContainer_SetsErr(t *testing.T) {
	ctx := &Context{App: &app.App{ServiceContainer: nil}}
	svc := ctx.userSvc()
	assert.Nil(t, svc)
	assert.NotNil(t, ctx.Err)
	assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}

// TestContext_CertSvc_NilApp_SetsErr verifies that certSvc sets c.Err and
// returns nil when c.App is nil.
func TestContext_CertSvc_NilApp_SetsErr(t *testing.T) {
	ctx := &Context{App: nil}
	svc := ctx.certSvc()
	assert.Nil(t, svc)
	assert.NotNil(t, ctx.Err)
	assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}

// TestContext_CertSvc_NilContainer_SetsErr verifies that certSvc sets c.Err
// and returns nil when the service container is nil.
func TestContext_CertSvc_NilContainer_SetsErr(t *testing.T) {
	ctx := &Context{App: &app.App{ServiceContainer: nil}}
	svc := ctx.certSvc()
	assert.Nil(t, svc)
	assert.NotNil(t, ctx.Err)
	assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}

// TestContext_AuthSvc_NilApp_SetsErr verifies that authSvc sets c.Err
// and returns nil when c.App is nil.
func TestContext_AuthSvc_NilApp_SetsErr(t *testing.T) {
	ctx := &Context{App: nil}
	svc := ctx.authSvc()
	assert.Nil(t, svc)
	assert.NotNil(t, ctx.Err)
	assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}

// TestContext_AuthSvc_NilContainer_SetsErr verifies that authSvc sets c.Err
// and returns nil when the service container is nil.
func TestContext_AuthSvc_NilContainer_SetsErr(t *testing.T) {
	ctx := &Context{App: &app.App{ServiceContainer: nil}}
	svc := ctx.authSvc()
	assert.Nil(t, svc)
	assert.NotNil(t, ctx.Err)
	assert.Equal(t, http.StatusInternalServerError, ctx.Err.StatusCode)
}
