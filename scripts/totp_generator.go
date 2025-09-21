package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	// Command line flags
	var (
		secret   = flag.String("secret", "", "TOTP secret key")
		username = flag.String("username", "admin", "Username for display")
		count    = flag.Int("count", 3, "Number of future codes to generate")
		help     = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		showUsage()
		return
	}

	// Use provided secret or try to read from file
	totpSecret := *secret
	if totpSecret == "" {
		// Try to read from saved admin secret file
		if data, err := os.ReadFile(".admin_totp_secret"); err == nil {
			totpSecret = string(data)
			fmt.Printf("Using saved TOTP secret for %s\n", *username)
		} else {
			// Use default secret from original generator
			totpSecret = "73KP3IPX3L47GBI73ZP65CG5756NVYWL"
			fmt.Printf("Using default TOTP secret\n")
		}
	}

	// Clean the secret (remove any whitespace)
	totpSecret = trimWhitespace(totpSecret)

	if totpSecret == "" {
		fmt.Printf("Error: No TOTP secret provided. Use -secret flag or ensure .admin_totp_secret file exists\n")
		showUsage()
		os.Exit(1)
	}

	// Generate current TOTP code
	currentCode, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		fmt.Printf("Error generating current TOTP: %v\n", err)
		return
	}

	// Display current information
	fmt.Printf("\n🔐 TOTP Generator for User: %s\n", *username)
	fmt.Printf("=====================================\n")
	fmt.Printf("Secret: %s\n", totpSecret)
	fmt.Printf("Current Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("Current TOTP Code: %s\n", currentCode)
	fmt.Printf("\nUse this code with: --totp-code %s\n", currentCode)

	// Generate future codes
	if *count > 0 {
		fmt.Printf("\n🕐 Next %d TOTP codes:\n", *count)
		fmt.Printf("Time Period: 30 seconds\n")
		fmt.Printf("---------------------\n")

		for i := 1; i <= *count; i++ {
			// Calculate future time (30-second intervals)
			futureTime := time.Now().Add(time.Duration(i*30) * time.Second)
			futureCode, err := totp.GenerateCode(totpSecret, futureTime)
			if err == nil {
				fmt.Printf("  %s (+%02d:%02d): %s\n",
					futureTime.Format("15:04:05"),
					i*30/60,
					(i*30)%60,
					futureCode)
			}
		}
	}

	// Show authentication example
	fmt.Printf("\n📖 Authentication Example:\n")
	fmt.Printf("./password-manager --username=%s --password=<your-password> --totp-code=%s users list\n", *username, currentCode)

	// Show QR code info if secret was provided
	if *secret != "" {
		fmt.Printf("\n📱 QR Code Setup:\n")
		fmt.Printf("For manual entry in authenticator app:\n")
		fmt.Printf("  Account: %s@password-manager\n", *username)
		fmt.Printf("  Secret: %s\n", totpSecret)
		fmt.Printf("  Type: Time-based (TOTP)\n")
		fmt.Printf("  Period: 30 seconds\n")
		fmt.Printf("  Digits: 6\n")
	}
}

// trimWhitespace removes leading/trailing whitespace and newlines
func trimWhitespace(s string) string {
	result := ""
	for _, char := range s {
		if char != ' ' && char != '\t' && char != '\n' && char != '\r' {
			result += string(char)
		}
	}
	return result
}

func showUsage() {
	fmt.Printf(`🔐 TOTP Generator for Password Manager

USAGE:
    go run scripts/totp_generator.go [OPTIONS]

OPTIONS:
    -secret STRING    TOTP secret key (if not provided, will try .admin_totp_secret file)
    -username STRING  Username for display (default: admin)
    -count NUMBER     Number of future codes to generate (default: 3)
    -help            Show this help message

EXAMPLES:
    # Generate codes using saved admin secret
    go run scripts/totp_generator.go

    # Generate codes for specific user with custom secret
    go run scripts/totp_generator.go -secret="ABCD1234EFGH5678" -username="myuser"

    # Generate only current code
    go run scripts/totp_generator.go -count=0

    # Generate many future codes
    go run scripts/totp_generator.go -count=10

NOTES:
    - TOTP codes are valid for 30 seconds
    - The script automatically reads from .admin_totp_secret if no secret is provided
    - Use the generated codes immediately for authentication
    - Keep TOTP secrets secure and never share them

`)
}