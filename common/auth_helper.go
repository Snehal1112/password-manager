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

package common

import "strings"

// HasRequiredRole checks if a user has at least one of the required roles.
// It supports both single role assignments ("admin") and comma-separated
// multiple role assignments ("secrets_manager, crypto_manager").
//
// Parameters:
//   - userRole: The user's role(s), either single ("admin") or comma-separated ("role1, role2")
//   - requiredRoles: Variable number of roles to check against
//
// Returns:
//   - true if the user has at least one of the required roles
//   - false otherwise
//
// Examples:
//
//	HasRequiredRole("admin", "admin", "secrets_manager") → true
//	HasRequiredRole("secrets_manager, crypto_manager", "admin", "secrets_manager") → true
//	HasRequiredRole("user", "admin", "secrets_manager") → false
//	HasRequiredRole("secrets_manager , crypto_manager", "crypto_manager") → true (whitespace handled)
func HasRequiredRole(userRole string, requiredRoles ...string) bool {
	// Handle empty cases
	if userRole == "" || len(requiredRoles) == 0 {
		return false
	}

	// Split user's roles by comma and trim whitespace
	userRoles := strings.Split(userRole, ",")
	for i := range userRoles {
		userRoles[i] = strings.TrimSpace(userRoles[i])
	}

	// Check if user has any of the required roles
	for _, required := range requiredRoles {
		for _, role := range userRoles {
			if role == required {
				return true
			}
		}
	}

	return false
}
