package vaultapi

import "context"

// staticToken is a TokenSource returning a fixed token, for tests that are
// not exercising token acquisition itself.
type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }
