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
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"rocketvault/internal/pwgen"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate-password",
	Short: "Generate a random password",
	Long: `Generate a random password locally and print it to standard output. Nothing
is stored: the password is not written to any vault, so pass it to
"secrets create" yourself if you want to keep it.

The character pool is built from the enabled --uppercase, --lowercase,
--numbers and --special sets, and at least one of them must remain enabled.
The result contains at least one character from every enabled set, and it
never repeats the same character three times in a row.

No role and no data action is checked, and no vault is touched. The command
needs no active session or credential flags to run it, since it performs no
server or vault operation at all.`,
	Example: `  # Generate a 16-character password from the default character sets
  rocketvault secrets generate-password

  # Generate a 32-character password with no special characters
  rocketvault secrets generate-password --length 32 --special=false

  # Generate a digits-only PIN
  rocketvault secrets generate-password --length 8 \
    --uppercase=false --lowercase=false --special=false`,
	RunE: func(cmd *cobra.Command, args []string) error {
		length, _ := cmd.Flags().GetInt("length")
		useUpper, _ := cmd.Flags().GetBool("uppercase")
		useLower, _ := cmd.Flags().GetBool("lowercase")
		useNumbers, _ := cmd.Flags().GetBool("numbers")
		useSpecial, _ := cmd.Flags().GetBool("special")

		password, err := pwgen.Generate(pwgen.Options{
			Length:  length,
			Upper:   useUpper,
			Lower:   useLower,
			Numbers: useNumbers,
			Special: useSpecial,
		})
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
