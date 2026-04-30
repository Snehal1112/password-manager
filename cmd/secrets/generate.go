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
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate-password",
	Short: "Generate a random password",
	Long:  `Generate a random password with configurable length and character types.`,
	Run: func(cmd *cobra.Command, args []string) {
		length, _ := cmd.Flags().GetInt("length")
		useUpper, _ := cmd.Flags().GetBool("uppercase")
		useLower, _ := cmd.Flags().GetBool("lowercase")
		useNumbers, _ := cmd.Flags().GetBool("numbers")
		useSpecial, _ := cmd.Flags().GetBool("special")

		password, err := generatePassword(length, useUpper, useLower, useNumbers, useSpecial)
		if err != nil {
			logrus.Error("Failed to generate password: ", err)
			os.Exit(0)
			return
		}

		logrus.WithFields(logrus.Fields{
			"length": length,
		}).Info("Password generated successfully")
		fmt.Println("Generated password:", password)
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

	// Guarantee at least one character from each enabled type by overwriting at random positions.
	guaranteedChars := []struct {
		charset string
		enabled bool
	}{
		{upperChars, useUpper},
		{lowerChars, useLower},
		{numberChars, useNumbers},
		{specialChars, useSpecial},
	}

	for _, gc := range guaranteedChars {
		if !gc.enabled || length == 0 {
			continue
		}
		// Pick a random position to place a guaranteed character, avoiding 3 consecutive identical chars.
		for {
			posIdx, err := rand.Int(rand.Reader, big.NewInt(int64(length)))
			if err != nil {
				return "", fmt.Errorf("failed to generate random bytes: %w", err)
			}
			pos := posIdx.Int64()

			// Pick a random character from the guaranteed charset.
			charIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(gc.charset))))
			if err != nil {
				return "", fmt.Errorf("failed to generate random bytes: %w", err)
			}
			candidate := []rune(gc.charset)[charIdx.Int64()]

			// Check if placing this character would create 3 consecutive identical characters.
			wouldCreate3Identical := false
			if pos >= 2 && password[pos-1] == password[pos-2] && password[pos-2] == candidate {
				wouldCreate3Identical = true
			} else if pos >= 1 && pos < int64(length)-1 && password[pos-1] == password[pos+1] && password[pos+1] == candidate {
				wouldCreate3Identical = true
			} else if pos < int64(length)-2 && password[pos+1] == password[pos+2] && password[pos+2] == candidate {
				wouldCreate3Identical = true
			}

			if wouldCreate3Identical {
				continue
			}

			password[pos] = candidate
			break
		}
	}

	return string(password), nil
}
