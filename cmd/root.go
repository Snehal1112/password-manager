package cmd

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/snehal1112/password-manager/internal/api"
	"github.com/snehal1112/password-manager/internal/config"
	"github.com/snehal1112/password-manager/internal/db"
	"github.com/snehal1112/password-manager/internal/logger"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "password-manager",
	Short: "A secure password manager",
	Long:  "A standalone password manager for managing secrets, keys, and certificates.",
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server",
	Run: func(cmd *cobra.Command, args []string) {
		if err := db.InitializeDB(); err != nil {
			logrus.Fatal("Failed to initialize database: ", err)
		}
		defer db.CloseDB()

		if err := api.StartServer(); err != nil {
			logrus.Fatal("Failed to start API server: ", err)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logrus.Error("Failed to execute command: ", err)
		os.Exit(1)
	}
}

func init() {
	// Initialize configuration
	if err := config.LoadConfig(); err != nil {
		logrus.Fatal("Failed to load configuration: ", err)
	}

	// Initialize logger
	logger.InitLogger()

	// Add subcommands
	rootCmd.AddCommand(serveCmd)

}
