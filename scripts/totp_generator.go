package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// defaultSecret is read from the environment variable ROCKETVAULT_TOTP_SECRET.
// Set it once in your shell profile so you never need to pass -secret again:
//
//	export ROCKETVAULT_TOTP_SECRET="CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ"
const envSecretKey = "ROCKETVAULT_TOTP_SECRET"

func main() {
	var (
		secret   = flag.String("secret", "", "TOTP secret key (or set ROCKETVAULT_TOTP_SECRET env var)")
		username = flag.String("username", "admin", "Username shown in the authentication example")
		watch    = flag.Bool("watch", false, "Keep running and refresh the code every 30 seconds")
		help     = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		showUsage()
		return
	}

	// Prefer -secret flag, fall back to environment variable.
	resolvedSecret := strings.TrimSpace(*secret)
	if resolvedSecret == "" {
		resolvedSecret = strings.TrimSpace(os.Getenv(envSecretKey))
	}

	if resolvedSecret == "" {
		fmt.Fprintf(os.Stderr, "Error: TOTP secret is required.\n")
		fmt.Fprintf(os.Stderr, "  Option 1 (one-time): go run scripts/totp_generator.go -secret=\"YOUR_SECRET\"\n")
		fmt.Fprintf(os.Stderr, "  Option 2 (permanent): export %s=\"YOUR_SECRET\"\n\n", envSecretKey)
		showUsage()
		os.Exit(1)
	}

	if *watch {
		runWatch(resolvedSecret, *username)
		return
	}

	printCodes(resolvedSecret, *username)
}

// printCodes prints the current code plus remaining validity window.
func printCodes(secret, username string) {
	now := time.Now()
	currentCode, err := totp.GenerateCode(secret, now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating TOTP: %v\n", err)
		os.Exit(1)
	}

	// Seconds remaining in the current 30-second window.
	secondsUsed := now.Unix() % 30
	secondsLeft := 30 - secondsUsed

	// Visual bar showing time remaining (15 chars wide).
	barFilled := int(secondsLeft * 15 / 30)
	bar := strings.Repeat("█", barFilled) + strings.Repeat("░", 15-barFilled)

	fmt.Printf("\nRocketVault TOTP — user: %s\n", username)
	fmt.Printf("─────────────────────────────────\n")
	fmt.Printf("Current code : %s\n", currentCode)
	fmt.Printf("Valid for    : %ds  [%s]\n", secondsLeft, bar)
	fmt.Printf("Time         : %s\n", now.Format("15:04:05"))
	fmt.Printf("\nReady to use:\n")
	fmt.Printf("  --totp-code %s\n", currentCode)
	fmt.Printf("\nFull example:\n")
	fmt.Printf("  go run main.go secrets list --username %s --password <password> --totp-code %s\n\n", username, currentCode)

	// Warn if the code is about to expire.
	if secondsLeft <= 5 {
		fmt.Printf("Warning: code expires in %ds — wait for the next one to be safe.\n\n", secondsLeft)
		nextCode, err := totp.GenerateCode(secret, now.Add(30*time.Second))
		if err == nil {
			fmt.Printf("Next code (valid in %ds): %s\n\n", secondsLeft, nextCode)
		}
	}
}

// runWatch refreshes the code on every new 30-second window until Ctrl+C.
func runWatch(secret, username string) {
	fmt.Printf("Watch mode — refreshing every 30 seconds. Press Ctrl+C to stop.\n\n")

	// Print immediately, then wait for each window boundary.
	printCodes(secret, username)

	for {
		now := time.Now()
		secondsUntilNext := 30 - (now.Unix() % 30)
		time.Sleep(time.Duration(secondsUntilNext) * time.Second)
		// Clear last block and reprint.
		fmt.Print("\033[10A\033[J") // Move up 10 lines and clear to end of screen.
		printCodes(secret, username)
	}
}

func showUsage() {
	fmt.Print(`RocketVault TOTP Generator — get your --totp-code without touching your phone

USAGE:
    go run scripts/totp_generator.go [OPTIONS]

OPTIONS:
    -secret STRING    TOTP secret key (required if env var not set)
    -username STRING  Username shown in the example command (default: admin)
    -watch            Keep running and auto-refresh every 30 seconds
    -help             Show this help message

SETUP (recommended — do this once):
    Add this line to your ~/.bashrc or ~/.zshrc:
        export ROCKETVAULT_TOTP_SECRET="YOUR_SECRET_HERE"

    Then just run:
        go run scripts/totp_generator.go

EXAMPLES:
    # One-shot with secret on command line
    go run scripts/totp_generator.go -secret="ABCD1234EFGH5678"

    # One-shot using env var (after export above)
    go run scripts/totp_generator.go

    # Auto-refresh mode — keeps showing fresh codes
    go run scripts/totp_generator.go -watch

    # Different user
    go run scripts/totp_generator.go -username=alice

NOTES:
    - TOTP codes are valid for 30 seconds.
    - The validity bar shows how much time is left on the current code.
    - If the bar is almost empty, use -watch or wait for the next code.

`)
}
