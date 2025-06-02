#!/bin/bash

# Exit on any error
set -e

# Ensure Go is installed
if ! command -v go &> /dev/null; then
    echo "Go is not installed. Please install Go first."
    exit 1
fi

# Create a directory for coverage reports
mkdir -p coverage

# Run tests with coverage for all packages
echo "Running unit tests with coverage..."
go test -v -coverprofile=coverage/coverage.out -covermode=atomic ./...

# Check if tests passed
if [ $? -ne 0 ]; then
    echo "Tests failed. Please check the output above."
    exit 1
fi

# Generate coverage report
echo "Generating coverage report..."
go tool cover -html=coverage/coverage.out -o coverage/coverage.html

# Display total coverage percentage
echo "Calculating total coverage..."
go tool cover -func=coverage/coverage.out | grep total | awk '{print "Total coverage: " $3}'

echo "Coverage report generated at coverage/coverage.html"