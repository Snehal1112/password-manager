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

package secrets

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate-password",
	Short: "Generate a random password",
	Long:  `Generate a random password with configurable length and character types.`,
	Example: `  # Generate a 16-character password (default)
  rocketvault secrets generate-password \
    --username admin --password admin123 --totp-code <code>

  # Generate a 32-character password without special characters
  rocketvault secrets generate-password --length 32 --special=false \
    --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		length, _ := cmd.Flags().GetInt("length")
		useUpper, _ := cmd.Flags().GetBool("uppercase")
		useLower, _ := cmd.Flags().GetBool("lowercase")
		useNumbers, _ := cmd.Flags().GetBool("numbers")
		useSpecial, _ := cmd.Flags().GetBool("special")

		password, err := generatePassword(length, useUpper, useLower, useNumbers, useSpecial)
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}

		logrus.WithFields(logrus.Fields{
			"length": length,
		}).Info("Password generated successfully")
		fmt.Println("Generated password:", password)
		return nil
	},
}

// InitSecretsGenerate initializes the generate command under the secrets command.
// It sets up the command flags and adds it to the secrets command tree.
// This function is called in the main function of the application to set up the command structure.
// It returns the modified secrets command.
// Parameters:
//
//	secretsCmd: The parent command under which the generate command will be added.
//
// Returns:
//
//	The modified secrets command with the generate command added.
func InitSecretsGenerate(secretsCmd *cobra.Command) *cobra.Command {
	secretsCmd.AddCommand(generateCmd)

	generateCmd.Flags().Int("length", 16, "Length of the generated password")
	generateCmd.Flags().Bool("uppercase", true, "Include uppercase letters")
	generateCmd.Flags().Bool("lowercase", true, "Include lowercase letters")
	generateCmd.Flags().Bool("numbers", true, "Include numbers")
	generateCmd.Flags().Bool("special", true, "Include special characters")

	return secretsCmd
}

// generatePassword generates a random password with the specified parameters.
// It includes configurable character types and ensures at least one character from each enabled type.
//
// Parameters:
//
//	length: The length of the password.
//	useUpper: Include uppercase letters.
//	useLower: Include lowercase letters.
//	useNumbers: Include numbers.
//	useSpecial: Include special characters.
//
// Returns:
//
//	The generated password and an error if generation fails.
func generatePassword(length int, useUpper, useLower, useNumbers, useSpecial bool) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("password length must be at least 1")
	}

	const (
		upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowerChars   = "abcdefghijklmnopqrstuvwxyz"
		numberChars  = "0123456789"
		specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
	)

	var chars []rune
	if useUpper {
		chars = append(chars, []rune(upperChars)...)
	}
	if useLower {
		chars = append(chars, []rune(lowerChars)...)
	}
	if useNumbers {
		chars = append(chars, []rune(numberChars)...)
	}
	if useSpecial {
		chars = append(chars, []rune(specialChars)...)
	}

	if len(chars) == 0 {
		return "", fmt.Errorf("at least one character type must be enabled")
	}

	password := make([]rune, length)
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
			posN, err := rand.Int(rand.Reader, big.NewInt(int64(length)))
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
			next1 := idx < length-1 && password[idx+1] == candidate
			next2 := idx < length-2 && password[idx+2] == candidate
			if (prev1 && prev2) || (prev1 && next1) || (next1 && next2) {
				continue
			}
			password[idx] = candidate
			return nil
		}
	}
	if useUpper {
		if err := injectGuaranteed(upperChars); err != nil {
			return "", err
		}
	}
	if useLower {
		if err := injectGuaranteed(lowerChars); err != nil {
			return "", err
		}
	}
	if useNumbers {
		if err := injectGuaranteed(numberChars); err != nil {
			return "", err
		}
	}
	if useSpecial {
		if err := injectGuaranteed(specialChars); err != nil {
			return "", err
		}
	}

	return string(password), nil
}
