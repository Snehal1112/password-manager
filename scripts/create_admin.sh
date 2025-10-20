#!/bin/bash

# Password Manager - Enhanced Admin User Creation Script
# This script creates admin users in two modes:
# 1. Bootstrap mode: For initial admin creation (empty database)
# 2. Authenticated mode: For additional admin users (using existing admin credentials)

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
DEFAULT_ADMIN_USERNAME="sd0098"
DEFAULT_ADMIN_PASSWORD="sd0098"
DEFAULT_CONFIG_FILE=".password-manager.yaml"
DEFAULT_TEST_CONFIG_FILE=".password-manager-test.yaml"

# Script modes
MODE_AUTO="auto"
MODE_BOOTSTRAP="bootstrap"
MODE_AUTHENTICATED="authenticated"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_mode() {
    echo -e "${CYAN}[MODE]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Enhanced admin user creation for Password Manager - supports both initial setup and adding additional admins

MODES:
    auto          Automatically detect mode (default)
    bootstrap     Force bootstrap mode (initial admin creation, requires empty database)
    authenticated Force authenticated mode (additional admin creation, requires existing admin)

OPTIONS:
    -u, --username USERNAME         New admin username (default: admin)
    -p, --password PASSWORD         New admin password (default: admin123)
    -c, --config CONFIG_FILE        Configuration file (default: .password-manager.yaml)
    -t, --test                      Use test configuration
    -g, --generate-totp             Generate TOTP codes after creation
    -m, --mode MODE                 Force specific mode: auto|bootstrap|authenticated

    # For bootstrap mode:
    --bootstrap-token TOKEN         Custom bootstrap token (overrides config file)

    # For authenticated mode only:
    --auth-user USERNAME            Existing admin username for authentication
    --auth-pass PASSWORD            Existing admin password for authentication
    --auth-totp-secret SECRET       TOTP secret for existing admin (if available)

    -h, --help                      Show this help message

EXAMPLES:
    # Auto-detect mode (recommended)
    $0 --username newadmin --password newpass123

    # Force bootstrap mode (initial setup)
    $0 --mode bootstrap --username admin --password admin123

    # Bootstrap mode with custom token
    $0 --mode bootstrap --username admin --password admin123 \\
       --bootstrap-token "custom-bootstrap-token-12345"

    # Force authenticated mode (additional admin)
    $0 --mode authenticated --username admin2 --password admin2pass \\
       --auth-user admin --auth-pass admin123 --auth-totp-secret ABCD1234...

    # Use test configuration
    $0 --test --username testadmin --generate-totp

    # Create admin using auto-detected existing admin
    $0 --username manager --password manager123 --auth-user sd0088 --auth-pass sd0088

MODES EXPLAINED:
    bootstrap:     Uses bootstrap token for first admin (database must be empty)
    authenticated: Uses existing admin credentials to create additional admins
    auto:          Checks if users exist, then chooses bootstrap or authenticated mode

NOTES:
    - Auto mode is recommended - it detects the best approach automatically
    - Bootstrap mode only works when no users exist in the database
    - Authenticated mode requires existing admin credentials with TOTP if enabled
    - TOTP secrets are saved to .admin_totp_secret for convenience
EOF
}

# Initialize variables
ADMIN_USERNAME="$DEFAULT_ADMIN_USERNAME"
ADMIN_PASSWORD="$DEFAULT_ADMIN_PASSWORD"
CONFIG_FILE="$DEFAULT_CONFIG_FILE"
USE_TEST_CONFIG=false
GENERATE_TOTP=false
SCRIPT_MODE="$MODE_AUTO"
CUSTOM_BOOTSTRAP_TOKEN=""
AUTH_USERNAME=""
AUTH_PASSWORD=""
AUTH_TOTP_SECRET=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--username)
            ADMIN_USERNAME="$2"
            shift 2
            ;;
        -p|--password)
            ADMIN_PASSWORD="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -t|--test)
            USE_TEST_CONFIG=true
            CONFIG_FILE="$DEFAULT_TEST_CONFIG_FILE"
            shift
            ;;
        -g|--generate-totp)
            GENERATE_TOTP=true
            shift
            ;;
        -m|--mode)
            SCRIPT_MODE="$2"
            shift 2
            ;;
        --auth-user)
            AUTH_USERNAME="$2"
            shift 2
            ;;
        --auth-pass)
            AUTH_PASSWORD="$2"
            shift 2
            ;;
        --auth-totp-secret)
            AUTH_TOTP_SECRET="$2"
            shift 2
            ;;
        --bootstrap-token)
            CUSTOM_BOOTSTRAP_TOKEN="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Function to check if required files exist
check_prerequisites() {
    print_info "Checking prerequisites..."

    # Check if password-manager binary exists
    if [[ ! -f "./password-manager" ]]; then
        print_error "password-manager binary not found. Please build the project first:"
        echo "  go build -o password-manager"
        exit 1
    fi

    # Check if configuration file exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi

    # Check if TOTP generator script exists
    if [[ "$GENERATE_TOTP" == true ]] && [[ ! -f "scripts/totp_generator.go" ]]; then
        print_warning "TOTP generator not found at scripts/totp_generator.go"
        print_info "TOTP codes will need to be generated manually"
        GENERATE_TOTP=false
    fi

    print_success "Prerequisites check completed"
}

# Function to check current database state
check_database_state() {
    print_info "Checking database state..."

    # Extract database connection from config
    if command -v yq &> /dev/null; then
        DB_FILE=$(yq e '.database.connection' "$CONFIG_FILE" 2>/dev/null)
    else
        DB_FILE=$(grep -A 1 "database:" "$CONFIG_FILE" | grep "connection:" | awk '{print $2}' | tr -d '"' 2>/dev/null)
    fi

    if [[ -z "$DB_FILE" ]] || [[ "$DB_FILE" == "null" ]]; then
        print_error "Cannot determine database file from configuration"
        exit 1
    fi

    # Check if database file exists and has users
    if [[ -f "$DB_FILE" ]] && command -v sqlite3 &> /dev/null; then
        USER_COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "0")
        if [[ "$USER_COUNT" -gt 0 ]]; then
            print_info "Database contains $USER_COUNT existing users"
            return 1  # Users exist
        else
            print_info "Database is empty (no users found)"
            return 0  # No users
        fi
    else
        print_info "Database file not found or sqlite3 not available"
        return 0  # Assume empty
    fi
}

# Function to auto-detect the appropriate mode
detect_mode() {
    if [[ "$SCRIPT_MODE" != "$MODE_AUTO" ]]; then
        print_mode "Mode explicitly set to: $SCRIPT_MODE"
        return 0
    fi

    print_info "Auto-detecting appropriate mode..."

    if check_database_state; then
        SCRIPT_MODE="$MODE_BOOTSTRAP"
        print_mode "Auto-detected mode: BOOTSTRAP (empty database)"
    else
        SCRIPT_MODE="$MODE_AUTHENTICATED"
        print_mode "Auto-detected mode: AUTHENTICATED (existing users found)"
    fi
}

# Function to validate bootstrap token format
validate_bootstrap_token() {
    local token="$1"

    # Check if token is not empty
    if [[ -z "$token" ]]; then
        print_error "Bootstrap token cannot be empty"
        return 1
    fi

    # Check minimum length (should be reasonably long for security)
    if [[ ${#token} -lt 16 ]]; then
        print_warning "Bootstrap token is quite short (${#token} characters). Consider using a longer token for better security."
    fi

    # Check for suspicious characters (basic validation)
    if [[ "$token" =~ [[:space:]] ]]; then
        print_error "Bootstrap token contains spaces or whitespace characters"
        return 1
    fi

    # Informational: suggest good token format
    if [[ ! "$token" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_warning "Bootstrap token contains special characters. Ensure compatibility with your system."
    fi

    print_info "Bootstrap token validation passed"
    return 0
}

# Function to extract bootstrap token from config
get_bootstrap_token() {
    # Prioritize CLI parameter over config file
    if [[ -n "$CUSTOM_BOOTSTRAP_TOKEN" ]]; then
        BOOTSTRAP_TOKEN="$CUSTOM_BOOTSTRAP_TOKEN"
        print_info "Using custom bootstrap token from command line"

        # Validate the custom token
        if ! validate_bootstrap_token "$BOOTSTRAP_TOKEN"; then
            print_error "Custom bootstrap token validation failed"
            return 1
        fi
        return 0
    fi

    # Fall back to config file
    if command -v yq &> /dev/null; then
        BOOTSTRAP_TOKEN=$(yq e '.bootstrap_token' "$CONFIG_FILE" 2>/dev/null)
    else
        BOOTSTRAP_TOKEN=$(grep "bootstrap_token:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"' 2>/dev/null)
    fi

    if [[ -z "$BOOTSTRAP_TOKEN" ]] || [[ "$BOOTSTRAP_TOKEN" == "null" ]]; then
        print_error "Bootstrap token not found in $CONFIG_FILE and not provided via --bootstrap-token"
        print_info "Please either:"
        print_info "  1. Add bootstrap_token to your configuration file, or"
        print_info "  2. Use --bootstrap-token <token> parameter"
        return 1
    fi

    print_info "Bootstrap token found in configuration file"

    # Validate the config file token
    if ! validate_bootstrap_token "$BOOTSTRAP_TOKEN"; then
        print_error "Bootstrap token from config file validation failed"
        return 1
    fi

    return 0
}

# Function to setup database for bootstrap mode
setup_database_bootstrap() {
    print_info "Setting up database for bootstrap mode..."

    # Extract database connection from config
    if command -v yq &> /dev/null; then
        DB_FILE=$(yq e '.database.connection' "$CONFIG_FILE" 2>/dev/null)
    else
        DB_FILE=$(grep -A 1 "database:" "$CONFIG_FILE" | grep "connection:" | awk '{print $2}' | tr -d '"' 2>/dev/null)
    fi

    if [[ -n "$DB_FILE" ]] && [[ "$DB_FILE" != "null" ]]; then
        if [[ -f "$DB_FILE" ]] && command -v sqlite3 &> /dev/null; then
            # Ensure bootstrap token exists in database
            TOKEN_EXISTS=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM bootstrap_tokens WHERE token='$BOOTSTRAP_TOKEN' AND used=0;" 2>/dev/null || echo "0")
            if [[ "$TOKEN_EXISTS" == "0" ]]; then
                print_info "Inserting bootstrap token into database..."
                sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO bootstrap_tokens (token, used, created_at) VALUES ('$BOOTSTRAP_TOKEN', 0, datetime('now'));" 2>/dev/null || true
            fi
        fi
    fi
}

# Function to create admin user using bootstrap method
create_admin_bootstrap() {
    print_info "Creating admin user using bootstrap method: $ADMIN_USERNAME"

    # Get bootstrap token
    if ! get_bootstrap_token; then
        exit 1
    fi

    # Setup database
    setup_database_bootstrap

    # Build the command
    CMD="./password-manager --config=\"$CONFIG_FILE\" users admin --admin-username=\"$ADMIN_USERNAME\" --admin-password=\"$ADMIN_PASSWORD\" --bootstrap-token=\"$BOOTSTRAP_TOKEN\""

    print_info "Executing bootstrap admin creation..."

    # Execute the command and capture output
    if OUTPUT=$(eval "$CMD" 2>&1); then
        print_success "Admin user created successfully using bootstrap method!"
        echo "$OUTPUT"
        extract_totp_secret_from_output "$OUTPUT"
        return 0
    else
        print_error "Bootstrap admin creation failed:"
        echo "$OUTPUT"

        # Check if it's because users already exist
        if echo "$OUTPUT" | grep -q "Bootstrap not allowed"; then
            print_warning "Bootstrap mode failed because users already exist"
            print_info "Try using authenticated mode instead:"
            print_info "  $0 --mode authenticated --username $ADMIN_USERNAME --auth-user <existing_admin> --auth-pass <password>"
        fi
        return 1
    fi
}

# Function to generate TOTP code for authentication
generate_auth_totp() {
    local secret="$1"
    if [[ -n "$secret" ]] && [[ -f "scripts/totp_generator.go" ]]; then
        TOTP_CODE=$(go run scripts/totp_generator.go -secret="$secret" -count=0 2>/dev/null | grep "Current TOTP Code:" | awk '{print $4}')
        if [[ -n "$TOTP_CODE" ]]; then
            print_info "Generated TOTP code: $TOTP_CODE"
            echo "$TOTP_CODE"
            return 0
        fi
    fi
    return 1
}

# Function to get existing admin credentials
get_auth_credentials() {
    print_info "Setting up authentication with existing admin..."

    # If auth credentials not provided, try to detect or prompt
    if [[ -z "$AUTH_USERNAME" ]]; then
        # Try to find an existing admin user from database
        if command -v sqlite3 &> /dev/null; then
            DB_FILE=$(grep -A 1 "database:" "$CONFIG_FILE" | grep "connection:" | awk '{print $2}' | tr -d '"' 2>/dev/null)
            if [[ -f "$DB_FILE" ]]; then
                EXISTING_ADMIN=$(sqlite3 "$DB_FILE" "SELECT username FROM users WHERE role='admin' LIMIT 1;" 2>/dev/null || echo "")
                if [[ -n "$EXISTING_ADMIN" ]]; then
                    AUTH_USERNAME="$EXISTING_ADMIN"
                    print_info "Found existing admin user: $AUTH_USERNAME"
                fi
            fi
        fi

        if [[ -z "$AUTH_USERNAME" ]]; then
            print_error "No existing admin username provided and none could be auto-detected"
            print_info "Please provide existing admin credentials with --auth-user and --auth-pass"
            return 1
        fi
    fi

    if [[ -z "$AUTH_PASSWORD" ]]; then
        print_error "No authentication password provided. Use --auth-pass <password>"
        return 1
    fi

    # Try to get TOTP secret if not provided
    if [[ -z "$AUTH_TOTP_SECRET" ]]; then
        # Try to get from saved file
        if [[ -f ".admin_totp_secret" ]]; then
            SAVED_SECRET=$(cat ".admin_totp_secret" | grep -o 'secret=[^&]*' | cut -d'=' -f2 2>/dev/null || cat ".admin_totp_secret")
            if [[ -n "$SAVED_SECRET" ]] && [[ ${#SAVED_SECRET} -gt 10 ]]; then
                AUTH_TOTP_SECRET="$SAVED_SECRET"
                print_info "Using TOTP secret from .admin_totp_secret"
            fi
        fi

        # Try to get from database
        if [[ -z "$AUTH_TOTP_SECRET" ]] && command -v sqlite3 &> /dev/null; then
            DB_FILE=$(grep -A 1 "database:" "$CONFIG_FILE" | grep "connection:" | awk '{print $2}' | tr -d '"' 2>/dev/null)
            if [[ -f "$DB_FILE" ]]; then
                DB_SECRET=$(sqlite3 "$DB_FILE" "SELECT totp_secret FROM users WHERE username='$AUTH_USERNAME' LIMIT 1;" 2>/dev/null || echo "")
                if [[ -n "$DB_SECRET" ]]; then
                    AUTH_TOTP_SECRET="$DB_SECRET"
                    print_info "Retrieved TOTP secret from database"
                fi
            fi
        fi
    fi

    return 0
}

# Function to create admin user using authenticated method
create_admin_authenticated() {
    print_info "Creating admin user using authenticated method: $ADMIN_USERNAME"

    # Get authentication credentials
    if ! get_auth_credentials; then
        exit 1
    fi

    # Generate TOTP code if we have the secret
    TOTP_FLAG=""
    if [[ -n "$AUTH_TOTP_SECRET" ]]; then
        if TOTP_CODE=$(generate_auth_totp "$AUTH_TOTP_SECRET"); then
            TOTP_FLAG="--totp-code=\"$TOTP_CODE\""
            print_info "Using TOTP authentication"
        else
            print_warning "Could not generate TOTP code, will try without it"
        fi
    else
        print_warning "No TOTP secret available, will try without TOTP"
    fi

    # Build the command for user creation
    CMD="./password-manager --config=\"$CONFIG_FILE\" --username=\"$AUTH_USERNAME\" --password=\"$AUTH_PASSWORD\" $TOTP_FLAG users create --new-username=\"$ADMIN_USERNAME\" --new-password=\"$ADMIN_PASSWORD\" --new-role=\"admin\""

    print_info "Executing authenticated admin creation..."
    print_info "Authenticating as: $AUTH_USERNAME"

    # Execute the command and capture output
    if OUTPUT=$(eval "$CMD" 2>&1); then
        print_success "Admin user created successfully using authenticated method!"
        echo "$OUTPUT"
        extract_totp_secret_from_output "$OUTPUT"
        return 0
    else
        print_error "Authenticated admin creation failed:"
        echo "$OUTPUT"

        # Check for common issues
        if echo "$OUTPUT" | grep -q "Authentication failed"; then
            print_warning "Authentication failed. Please check:"
            print_info "  - Username: $AUTH_USERNAME"
            print_info "  - Password: [provided]"
            print_info "  - TOTP: ${AUTH_TOTP_SECRET:+available}${AUTH_TOTP_SECRET:-missing}"
        elif echo "$OUTPUT" | grep -q "username, password, and role are required"; then
            print_warning "Command parameter issue detected. This might be a CLI flag binding problem."
            print_info "Try using direct database insertion method instead."
        fi
        return 1
    fi
}

# Function to extract TOTP secret from command output
extract_totp_secret_from_output() {
    local output="$1"

    # Try to extract TOTP secret from different output formats
    TOTP_SECRET=""

    # Format 1: "TOTP Secret: SECRET"
    TOTP_SECRET=$(echo "$output" | grep "TOTP Secret:" | awk '{print $3}' | head -1)

    # Format 2: otpauth URL
    if [[ -z "$TOTP_SECRET" ]]; then
        TOTP_SECRET=$(echo "$output" | grep "otpauth://totp" | head -1)
    fi

    if [[ -n "$TOTP_SECRET" ]]; then
        echo ""
        print_info "TOTP Secret extracted: $TOTP_SECRET"

        # Save TOTP secret for later use
        echo "$TOTP_SECRET" > ".admin_totp_secret"
        print_info "TOTP secret saved to .admin_totp_secret"
    else
        print_warning "Could not extract TOTP secret from output"
    fi
}

# Function to generate TOTP codes
generate_totp_codes() {
    if [[ "$GENERATE_TOTP" == false ]]; then
        return 0
    fi

    print_info "Generating TOTP codes..."

    # Check if we have a TOTP secret
    TOTP_SECRET=""
    if [[ -f ".admin_totp_secret" ]]; then
        TOTP_SECRET=$(cat ".admin_totp_secret")
        # Extract secret from otpauth URL if needed
        if [[ "$TOTP_SECRET" == *"otpauth"* ]]; then
            TOTP_SECRET=$(echo "$TOTP_SECRET" | grep -o 'secret=[^&]*' | cut -d'=' -f2)
        fi
    fi

    if [[ -n "$TOTP_SECRET" ]] && [[ -f "scripts/totp_generator.go" ]]; then
        print_info "Generating TOTP codes for $ADMIN_USERNAME..."
        if go run scripts/totp_generator.go -secret="$TOTP_SECRET" -username="$ADMIN_USERNAME" -count=3 2>/dev/null; then
            print_success "TOTP codes generated successfully"
        else
            print_warning "Failed to generate TOTP codes"
        fi
    else
        print_warning "TOTP generation not available (missing secret or generator)"
    fi
}

# Function to show next steps
show_next_steps() {
    echo ""
    print_success "=== Admin User Creation Complete ==="
    echo ""
    print_info "Admin user details:"
    echo "  Username: $ADMIN_USERNAME"
    echo "  Password: [set as provided]"
    echo "  Mode used: $SCRIPT_MODE"
    echo "  Configuration: $CONFIG_FILE"
    echo ""

    print_info "Next steps:"
    echo "  1. Configure your TOTP authenticator app with the secret shown above"
    echo "  2. Test authentication with:"
    echo "     ./password-manager --config=\"$CONFIG_FILE\" --username=\"$ADMIN_USERNAME\" --password=\"<password>\" --totp-code=\"<code>\" users list"
    echo "  3. Create additional users as needed"
    echo ""

    if [[ -f ".admin_totp_secret" ]]; then
        print_info "TOTP Secret saved in: .admin_totp_secret"
        print_warning "Keep this secret secure and delete the file after configuring your authenticator!"
    fi

    echo ""
    print_info "For creating additional admin users, use:"
    echo "  $0 --username <new_admin> --auth-user $ADMIN_USERNAME --auth-pass <password>"
}

# Main execution function
main() {
    echo "🔐 Password Manager - Enhanced Admin User Creation Script"
    echo "======================================================="
    echo ""

    # Check prerequisites
    check_prerequisites

    # Detect appropriate mode
    detect_mode

    # Create admin user based on detected/selected mode
    case "$SCRIPT_MODE" in
        "$MODE_BOOTSTRAP")
            if create_admin_bootstrap; then
                print_success "Bootstrap admin creation completed"
            else
                print_error "Bootstrap admin creation failed"
                exit 1
            fi
            ;;
        "$MODE_AUTHENTICATED")
            if create_admin_authenticated; then
                print_success "Authenticated admin creation completed"
            else
                print_error "Authenticated admin creation failed"
                exit 1
            fi
            ;;
        *)
            print_error "Invalid mode: $SCRIPT_MODE"
            exit 1
            ;;
    esac

    # Generate TOTP codes if requested
    generate_totp_codes

    # Show next steps
    show_next_steps
}

# Run main function
main "$@"