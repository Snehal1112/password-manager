#!/bin/bash

# Configuration
CMD="password-manager secrets"
USERNAME="testuser"
PASSWORD="testpass"
TOTP_CODE="123456"
SECRET_ID="test-secret-id"
NEW_SECRET="my-secret-value"

# Function to run and display command results
run_command() {
    echo "Testing: $1"
    echo "----------------------------------------"
    eval $1
    echo -e "\nStatus: $?\n"
}

# Check if a command was provided
if [ -z "$1" ]; then
    echo "Error: Please specify a command to test (help, create, delete, generate-password, get, list, update)"
    echo "Example: $0 create"
    exit 1
fi

# Authentication flags
AUTH_FLAGS="--username $USERNAME --password $PASSWORD --totp-code $TOTP_CODE"

# Execute the requested command
case "$1" in
    help)
        run_command "$CMD --help"
        ;;
    create)
        run_command "$CMD create $AUTH_FLAGS --value $NEW_SECRET"
        ;;
    delete)
        run_command "$CMD delete $SECRET_ID $AUTH_FLAGS"
        ;;
    generate-password)
        run_command "$CMD generate-password $AUTH_FLAGS"
        ;;
    get)
        run_command "$CMD get $SECRET_ID $AUTH_FLAGS"
        ;;
    list)
        run_command "$CMD list $AUTH_FLAGS"
        ;;
    update)
        run_command "$CMD update $SECRET_ID $AUTH_FLAGS --value updated-secret"
        ;;
    *)
        echo "Error: Unknown command '$1'"
        echo "Valid commands: help, create, delete, generate-password, get, list, update"
        exit 1
        ;;
esac

echo "Test completed for command: $1"


# # !/bin/bash

# ./build/password-manager secrets list \
#   --tags="prod,dev" \
#   --password=sd101 \
#   --username=sd101 \
#   --totp-code=$1