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

package cmd

import (
	"password-manager/cmd/certificates"

	"github.com/spf13/cobra"
)

// certificateCmd represents the certificate command
var certificateCmd = &cobra.Command{
	Use:     "certificate",
	Short:   "Manage certificates",
	Long:    `Manage certificates for the application, including creating, updating, and deleting certificates.`,
	Example: `certificate create --name <name> --type <type>`,
	Run: func(cmd *cobra.Command, args []string) {
		// Show help when command is called without subcommands
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(certificateCmd)

	certificates.InitCertificatesCreate(certificateCmd)
	certificates.InitCertificatesGet(certificateCmd)
	certificates.InitCertificatesList(certificateCmd)
	certificates.InitCertificatesUpdate(certificateCmd)
	certificates.InitCertificatesDelete(certificateCmd)
	certificates.InitCertificatesRenew(certificateCmd)
}
