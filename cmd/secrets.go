// Package cmd provides CLI commands for the password manager.
// It defines Cobra commands to manage secrets, keys, and certificates,
// allowing users to interact with the application via the command line.
package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// secretsCmd is the root command for secrets management.
// It groups subcommands to create, get, update, delete, rotate, export, import,
// and generate passwords for secrets.
var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage secrets like passwords and API keys",
	Long:  `The secrets command allows users to create, retrieve, update, delete, rotate, export, import, and generate secure passwords for secrets stored in the password manager.`,
}

// createSecretCmd creates a new secret.
// It prompts for the secret name and value, sends a request to the API,
// and logs the operation.
var createSecretCmd = &cobra.Command{
	Use:   "create [name] [value]",
	Short: "Create a new secret",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if err := createSecret(args[0], args[1]); err != nil {
			logrus.Error("Failed to create secret: ", err)
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

// getSecretCmd retrieves a secret by name.
// It sends a request to the API to fetch the secret’s value and version,
// displaying the result to the user.
var getSecretCmd = &cobra.Command{
	Use:   "get [name]",
	Short: "Retrieve a secret by name",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := getSecret(args[0]); err != nil {
			logrus.Error("Failed to get secret: ", err)
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

// generatePasswordCmd generates a random password.
// It uses configurable parameters (length, character types) to create a strong password,
// optionally saving it as a secret.
var generatePasswordCmd = &cobra.Command{
	Use:   "generate-password [name]",
	Short: "Generate a random password",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		length, _ := cmd.Flags().GetInt("length")
		useUpper, _ := cmd.Flags().GetBool("uppercase")
		useLower, _ := cmd.Flags().GetBool("lowercase")
		useNumbers, _ := cmd.Flags().GetBool("numbers")
		useSpecial, _ := cmd.Flags().GetBool("special")
		save, _ := cmd.Flags().GetBool("save")

		if err := generatePassword(args[0], length, useUpper, useLower, useNumbers, useSpecial, save); err != nil {
			logrus.Error("Failed to generate password: ", err)
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

// init initializes the secrets CLI commands.
// It adds subcommands to the secrets command and defines flags for the password generator.
//
// Parameters:
//
//	none
//
// Returns:
//
//	none
//
// The function is called during CLI setup to configure secrets-related commands.
func init() {
	// Add secrets subcommands.
	secretsCmd.AddCommand(createSecretCmd)
	secretsCmd.AddCommand(getSecretCmd)
	secretsCmd.AddCommand(generatePasswordCmd)

	// Define flags for the generate-password command.
	generatePasswordCmd.Flags().Int("length", 16, "Length of the generated password")
	generatePasswordCmd.Flags().Bool("uppercase", true, "Include uppercase letters")
	generatePasswordCmd.Flags().Bool("lowercase", true, "Include lowercase letters")
	generatePasswordCmd.Flags().Bool("numbers", true, "Include numbers")
	generatePasswordCmd.Flags().Bool("special", true, "Include special characters")
	generatePasswordCmd.Flags().Bool("save", false, "Save the password as a secret")

	// Add secrets command to the root CLI command.
	rootCmd.AddCommand(secretsCmd)
}

// createSecret creates a new secret via the API.
// It sends a POST request to the /secrets endpoint with the secret name and value,
// using the user’s JWT token for authentication.
//
// Parameters:
//
//	name: The name of the secret.
//	value: The value of the secret (e.g., password, API key).
//
// Returns:
//
//	An error if the API request or authentication fails.
//
// The function is used by the secrets create CLI command to store a new secret.
func createSecret(name, value string) error {
	// Retrieve the API server address and JWT token from configuration.
	apiAddr := viper.GetString("api.address")
	token := viper.GetString("auth.token")
	if apiAddr == "" || token == "" {
		return fmt.Errorf("API address or token not configured")
	}

	// Prepare the request body.
	reqBody, err := json.Marshal(map[string]string{
		"name":  name,
		"value": value,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create an HTTP client and request.
	client := &http.Client{}
	req, err := http.NewRequest("POST", apiAddr+"/secrets", bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers for JSON content and JWT authentication.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	// Send the request to the API server.
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check the response status code.
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		logrus.WithFields(logrus.Fields{
			"status": resp.StatusCode,
			"body":   string(body),
		}).Warn("API request failed")
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	logrus.WithFields(logrus.Fields{
		"name": name,
	}).Info("Secret created successfully")
	fmt.Printf("Secret '%s' created\n", name)
	return nil
}

// getSecret retrieves a secret by name via the API.
// It sends a GET request to the /secrets/:name endpoint and displays the secret’s value
// and version to the user.
//
// Parameters:
//
//	name: The name of the secret to retrieve.
//
// Returns:
//
//	An error if the API request or authentication fails.
//
// The function is used by the secrets get CLI command to fetch a secret.
func getSecret(name string) error {
	// Retrieve the API server address and JWT token from configuration.
	apiAddr := viper.GetString("api.address")
	token := viper.GetString("auth.token")
	if apiAddr == "" || token == "" {
		return fmt.Errorf("API address or token not configured")
	}

	logrus.WithField(
		"api_url", apiAddr+"/api/secrets",
	).Debugln("Retrieving secret")
	// Create an HTTP client and request.
	client := &http.Client{}
	req, err := http.NewRequest("GET", apiAddr+"/api/secrets", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers for JWT authentication.
	req.Header.Set("Authorization", "Bearer "+token)

	// Send the request to the API server.
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check the response status code.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logrus.WithFields(logrus.Fields{
			"status": resp.StatusCode,
			"body":   string(body),
		}).Warn("API request failed")
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response body.
	var result struct {
		Name    string `json:"name"`
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"name":    name,
		"version": result.Version,
	}).Info("Secret retrieved successfully")
	fmt.Printf("Secret: %s\nValue: %s\nVersion: %d\n", result.Name, result.Value, result.Version)
	return nil
}

// generatePassword generates a random password with configurable parameters.
// It creates a strong password using crypto/rand and optionally saves it as a secret
// via the API if the save flag is set.
//
// Parameters:
//
//	name: The name for the secret if saving.
//	length: The desired password length.
//	useUpper: Include uppercase letters if true.
//	useLower: Include lowercase letters if true.
//	useNumbers: Include numbers if true.
//	useSpecial: Include special characters if true.
//	save: Save the password as a secret if true.
//
// Returns:
//
//	An error if password generation or saving fails.
//
// The function is used by the secrets generate-password CLI command to create secure passwords.
func generatePassword(name string, length int, useUpper, useLower, useNumbers, useSpecial, save bool) error {
	// Define character sets for password generation.
	const (
		upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowerChars   = "abcdefghijklmnopqrstuvwxyz"
		numberChars  = "0123456789"
		specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
	)

	// Build the character pool based on parameters.
	var charPool string
	if useUpper {
		charPool += upperChars
	}
	if useLower {
		charPool += lowerChars
	}
	if useNumbers {
		charPool += numberChars
	}
	if useSpecial {
		charPool += specialChars
	}
	if charPool == "" {
		return fmt.Errorf("at least one character type must be selected")
	}

	// Generate a random password.
	password := make([]byte, length)
	for i := 0; i < length; i++ {
		// Select a random index from the character pool.
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charPool))))
		if err != nil {
			return fmt.Errorf("failed to generate random index: %w", err)
		}
		password[i] = charPool[idx.Int64()]
	}

	// Convert the password to a string.
	passwordStr := string(password)

	// Save the password as a secret if requested.
	if save {
		if err := createSecret(name, passwordStr); err != nil {
			return fmt.Errorf("failed to save password as secret: %w", err)
		}
	}

	logrus.WithFields(logrus.Fields{
		"name":   name,
		"length": length,
		"saved":  save,
	}).Info("Password generated successfully")
	fmt.Printf("Generated password: %s\n", passwordStr)
	if save {
		fmt.Printf("Saved as secret '%s'\n", name)
	}
	return nil
}
