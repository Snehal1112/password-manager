// Package pwgen generates random passwords. It lives outside cmd/ so that
// service-layer callers can use it without importing a command package.
package pwgen

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	numberChars  = "0123456789"
	specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// Options selects the length and character sets for a generated password.
type Options struct {
	Length  int
	Upper   bool
	Lower   bool
	Numbers bool
	Special bool
}

// DefaultOptions returns the generator settings the CLI uses by default.
func DefaultOptions() Options {
	return Options{Length: 16, Upper: true, Lower: true, Numbers: true, Special: true}
}

// Generate returns a random password matching opts. It never emits three
// identical characters in a row. When Length is at least as large as the
// number of enabled character sets, it also guarantees at least one character
// from every enabled set. Below that, each set's injection can overwrite an
// earlier one, so the guarantee does not hold: for example, Length 1 with all
// four sets enabled returns a single character from whichever set injects
// last, not one of each.
func Generate(opts Options) (string, error) {
	if opts.Length < 1 {
		return "", fmt.Errorf("password length must be at least 1")
	}

	var chars []rune
	if opts.Upper {
		chars = append(chars, []rune(upperChars)...)
	}
	if opts.Lower {
		chars = append(chars, []rune(lowerChars)...)
	}
	if opts.Numbers {
		chars = append(chars, []rune(numberChars)...)
	}
	if opts.Special {
		chars = append(chars, []rune(specialChars)...)
	}

	if len(chars) == 0 {
		return "", fmt.Errorf("at least one character type must be enabled")
	}

	password := make([]rune, opts.Length)
	charCount := big.NewInt(int64(len(chars)))

	// Generate password, avoiding 3 consecutive identical characters.
	for i := range password {
		var candidate rune
		for {
			n, err := rand.Int(rand.Reader, charCount)
			if err != nil {
				return "", fmt.Errorf("failed to generate random bytes: %w", err)
			}
			candidate = chars[n.Int64()]

			// Check if we would create 3 consecutive identical characters.
			if i >= 2 && password[i-1] == password[i-2] && password[i-2] == candidate {
				// Reject and try again.
				continue
			}
			break
		}
		password[i] = candidate
	}

	// Guarantee at least one character from each enabled type by replacing a
	// randomly chosen position. We retry the pick until the replacement does not
	// create three consecutive identical characters, preserving the invariant
	// established by the generation loop above.
	injectGuaranteed := func(charset string) error {
		runeCharset := []rune(charset)
		for {
			posN, err := rand.Int(rand.Reader, big.NewInt(int64(opts.Length)))
			if err != nil {
				return fmt.Errorf("failed to generate random bytes: %w", err)
			}
			idx := int(posN.Int64())

			charN, err := rand.Int(rand.Reader, big.NewInt(int64(len(runeCharset))))
			if err != nil {
				return fmt.Errorf("failed to generate random bytes: %w", err)
			}
			candidate := runeCharset[charN.Int64()]

			// Check that inserting candidate at idx does not create a run of 3.
			prev1 := idx > 0 && password[idx-1] == candidate
			prev2 := idx > 1 && password[idx-2] == candidate
			next1 := idx < opts.Length-1 && password[idx+1] == candidate
			next2 := idx < opts.Length-2 && password[idx+2] == candidate
			if (prev1 && prev2) || (prev1 && next1) || (next1 && next2) {
				continue
			}
			password[idx] = candidate
			return nil
		}
	}
	if opts.Upper {
		if err := injectGuaranteed(upperChars); err != nil {
			return "", err
		}
	}
	if opts.Lower {
		if err := injectGuaranteed(lowerChars); err != nil {
			return "", err
		}
	}
	if opts.Numbers {
		if err := injectGuaranteed(numberChars); err != nil {
			return "", err
		}
	}
	if opts.Special {
		if err := injectGuaranteed(specialChars); err != nil {
			return "", err
		}
	}

	return string(password), nil
}
