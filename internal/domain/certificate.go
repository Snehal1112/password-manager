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

package domain

import (
	"time"

	"github.com/google/uuid"
)

// Certificate represents an X.509 certificate in the password manager.
// It includes the certificate's ID, user ID, name, PEM-encoded certificate,
// encrypted private key, creation time, and tags.
type Certificate struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Name        string
	Certificate string // PEM-encoded X.509 certificate
	PrivateKey  string // Encrypted PEM-encoded private key
	CreatedAt   time.Time
	Tags        []string
}

// RevokedCertificate represents a revoked certificate in the CRL (Certificate Revocation List).
// It includes the certificate's ID, user ID, serial number, name, and revocation time.
type RevokedCertificate struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	SerialNumber string
	Name         string
	RevokedAt    time.Time
}
