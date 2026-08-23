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

// HasAnyRole reports whether userRoles contains at least one of
// requiredRoles.
//
// Parameters:
//   - userRoles: the roles a principal actually holds
//   - requiredRoles: the roles that would grant the operation being checked
//
// Matching is exact and requires normalized input: callers must pass
// already-trimmed role strings; this function does not trim whitespace.
//
// Returns true if userRoles and requiredRoles share at least one entry.
func HasAnyRole(userRoles []string, requiredRoles ...string) bool {
	if len(userRoles) == 0 || len(requiredRoles) == 0 {
		return false
	}

	for _, required := range requiredRoles {
		for _, role := range userRoles {
			if role == required {
				return true
			}
		}
	}

	return false
}
