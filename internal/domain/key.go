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

// Key represents a cryptographic key in the password manager.
// It stores encrypted PEM-encoded private keys for RSA and ECDSA algorithms,
// with soft delete support for compliance and data retention.
type Key struct {
	ID              uuid.UUID  `json:"id"`
	UserID          uuid.UUID  `json:"user_id"`
	Name            string     `json:"name"`
	Type            string     `json:"type"` // "RSA" or "ECDSA"
	Value           string     `json:"value"` // Encrypted PEM-encoded private key
	Revoked         bool       `json:"revoked"`
	CreatedAt       time.Time  `json:"created_at"`
	Tags            []string   `json:"tags"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`        // Soft delete timestamp
	PurgeProtection  bool       `json:"purge_protection"`            // Prevents permanent deletion
	ScheduledPurgeAt *time.Time `json:"scheduled_purge_at,omitempty"` // Scheduled purge time
}

// KeyType constants for supported cryptographic key types.
const (
	KeyTypeRSA   = "RSA"
	KeyTypeECDSA = "ECDSA"
)
