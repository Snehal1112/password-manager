package main

import (
	"fmt"
	"github.com/pquerna/otp/totp"
	"time"
)

func main() {
	// TOTP secret generated for admin user
	secret := "CJMI7JIFFBM6EWHWZUN2NM7757HDWCZW"

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		fmt.Printf("Error generating TOTP: %v\n", err)
		return
	}

	fmt.Printf("Current TOTP Code for admin1: %s\n", code)
	fmt.Printf("Secret: %s\n", secret)
	fmt.Printf("Use this code with --totp-code flag for authentication\n")
}
