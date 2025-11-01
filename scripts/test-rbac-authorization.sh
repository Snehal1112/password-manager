#!/bin/bash
#
# RBAC Authorization Test Script
# Comprehensive testing of role-based access control implementation
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
BASE_URL="${BASE_URL:-http://localhost:8774}"
API_VERSION="${API_VERSION:-v1}"
API_URL="$BASE_URL/api/$API_VERSION"

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to print section headers
print_section() {
    echo ""
    echo "=========================================="
    echo "$1"
    echo "=========================================="
}

# Function to print test result
print_test_result() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ "$expected" == "$actual" ]; then
        echo -e "${GREEN}✓${NC} $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗${NC} $test_name"
        echo -e "  Expected: $expected, Got: $actual"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Function to make authenticated request
make_request() {
    local method="$1"
    local endpoint="$2"
    local token="$3"
    local data="$4"

    if [ -n "$data" ]; then
        curl -s -X "$method" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$data" \
            -w "%{http_code}" \
            -o /dev/null \
            "$API_URL$endpoint"
    else
        curl -s -X "$method" \
            -H "Authorization: Bearer $token" \
            -w "%{http_code}" \
            -o /dev/null \
            "$API_URL$endpoint"
    fi
}

# Function to login and get token
get_token() {
    local username="$1"
    local password="$2"

    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$username\",\"password\":\"$password\"}" \
        "$API_URL/auth/login")

    echo "$response" | jq -r '.token // empty' 2>/dev/null || echo ""
}

print_section "RBAC Authorization Test Suite"

# Check if server is running
echo "Checking if server is running at $BASE_URL..."
if ! curl -s "$BASE_URL/health" > /dev/null 2>&1; then
    echo -e "${RED}Error: Server is not running at $BASE_URL${NC}"
    echo "Please start the server first: ./password-manager serve"
    exit 1
fi
echo -e "${GREEN}✓ Server is running${NC}"

# Unit tests first
print_section "Phase 1: Running Unit Tests"
echo "Running RBAC permission validation tests..."
go test ./internal/services/authorization/... -v -run TestRBACPermissionValidation || {
    echo -e "${RED}Unit tests failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ RBAC permission validation tests passed${NC}"

echo "Running endpoint access validation tests..."
go test ./internal/services/authorization/... -v -run TestEndpointAccessValidation || {
    echo -e "${RED}Unit tests failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ Endpoint access validation tests passed${NC}"

echo "Running role hierarchy tests..."
go test ./internal/services/authorization/... -v -run TestRoleHierarchy || {
    echo -e "${RED}Unit tests failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ Role hierarchy tests passed${NC}"

# Integration tests (requires running server and configured users)
print_section "Phase 2: Integration Tests"
echo -e "${YELLOW}Note: Integration tests require pre-configured users${NC}"
echo "Required users:"
echo "  - admin (role: admin)"
echo "  - testuser (role: user)"
echo "  - secretsmgr (role: secrets_manager)"
echo "  - cryptomgr (role: crypto_manager)"
echo ""

read -p "Have you created these test users? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Skipping integration tests${NC}"
    echo "To create test users, run:"
    echo "  ./password-manager users create --username=testuser --password=test123 --role=user"
    echo "  ./password-manager users create --username=secretsmgr --password=test123 --role=secrets_manager"
    echo "  ./password-manager users create --username=cryptomgr --password=test123 --role=crypto_manager"
else
    print_section "Testing Admin Permissions"

    # Get admin token
    ADMIN_TOKEN=$(get_token "admin" "admin123")
    if [ -z "$ADMIN_TOKEN" ]; then
        echo -e "${RED}Failed to login as admin${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Admin login successful${NC}"

    # Admin should be able to create users
    STATUS=$(make_request "POST" "/users" "$ADMIN_TOKEN" '{"username":"tempuser","password":"temp123","role":"user"}')
    print_test_result "Admin can create users (POST /users)" "201" "$STATUS"

    # Admin should be able to create secrets
    STATUS=$(make_request "POST" "/secrets" "$ADMIN_TOKEN" '{"name":"admin-secret","value":"secret123"}')
    print_test_result "Admin can create secrets (POST /secrets)" "201" "$STATUS"

    # Admin should be able to create keys
    STATUS=$(make_request "POST" "/keys" "$ADMIN_TOKEN" '{"name":"admin-key","key_type":"RSA","bits":2048}')
    print_test_result "Admin can create keys (POST /keys)" "201" "$STATUS"

    print_section "Testing Basic User Permissions"

    # Get user token
    USER_TOKEN=$(get_token "testuser" "test123")
    if [ -z "$USER_TOKEN" ]; then
        echo -e "${YELLOW}Warning: Could not login as testuser${NC}"
    else
        echo -e "${GREEN}✓ User login successful${NC}"

        # User can read secrets
        STATUS=$(make_request "GET" "/secrets" "$USER_TOKEN")
        print_test_result "User can list secrets (GET /secrets)" "200" "$STATUS"

        # User CANNOT create secrets
        STATUS=$(make_request "POST" "/secrets" "$USER_TOKEN" '{"name":"user-secret","value":"secret123"}')
        print_test_result "User CANNOT create secrets (POST /secrets)" "403" "$STATUS"

        # User CANNOT create users
        STATUS=$(make_request "POST" "/users" "$USER_TOKEN" '{"username":"baduser","password":"bad123","role":"admin"}')
        print_test_result "User CANNOT create users (POST /users)" "403" "$STATUS"

        # User CANNOT delete keys
        STATUS=$(make_request "DELETE" "/keys/00000000-0000-0000-0000-000000000000" "$USER_TOKEN")
        print_test_result "User CANNOT delete keys (DELETE /keys/id)" "403" "$STATUS"
    fi

    print_section "Testing Secrets Manager Permissions"

    # Get secrets manager token
    SECRETS_MGR_TOKEN=$(get_token "secretsmgr" "test123")
    if [ -z "$SECRETS_MGR_TOKEN" ]; then
        echo -e "${YELLOW}Warning: Could not login as secretsmgr${NC}"
    else
        echo -e "${GREEN}✓ Secrets manager login successful${NC}"

        # Secrets manager can create secrets
        STATUS=$(make_request "POST" "/secrets" "$SECRETS_MGR_TOKEN" '{"name":"mgr-secret","value":"secret123"}')
        print_test_result "Secrets-mgr can create secrets (POST /secrets)" "201" "$STATUS"

        # Secrets manager can list secrets
        STATUS=$(make_request "GET" "/secrets" "$SECRETS_MGR_TOKEN")
        print_test_result "Secrets-mgr can list secrets (GET /secrets)" "200" "$STATUS"

        # Secrets manager CANNOT create users
        STATUS=$(make_request "POST" "/users" "$SECRETS_MGR_TOKEN" '{"username":"baduser","password":"bad123","role":"user"}')
        print_test_result "Secrets-mgr CANNOT create users (POST /users)" "403" "$STATUS"

        # Secrets manager CANNOT create keys
        STATUS=$(make_request "POST" "/keys" "$SECRETS_MGR_TOKEN" '{"name":"bad-key","key_type":"RSA","bits":2048}')
        print_test_result "Secrets-mgr CANNOT create keys (POST /keys)" "403" "$STATUS"
    fi

    print_section "Testing Crypto Manager Permissions"

    # Get crypto manager token
    CRYPTO_MGR_TOKEN=$(get_token "cryptomgr" "test123")
    if [ -z "$CRYPTO_MGR_TOKEN" ]; then
        echo -e "${YELLOW}Warning: Could not login as cryptomgr${NC}"
    else
        echo -e "${GREEN}✓ Crypto manager login successful${NC}"

        # Crypto manager can create keys
        STATUS=$(make_request "POST" "/keys" "$CRYPTO_MGR_TOKEN" '{"name":"crypto-key","key_type":"RSA","bits":2048}')
        print_test_result "Crypto-mgr can create keys (POST /keys)" "201" "$STATUS"

        # Crypto manager can list keys
        STATUS=$(make_request "GET" "/keys" "$CRYPTO_MGR_TOKEN")
        print_test_result "Crypto-mgr can list keys (GET /keys)" "200" "$STATUS"

        # Crypto manager CANNOT create secrets
        STATUS=$(make_request "POST" "/secrets" "$CRYPTO_MGR_TOKEN" '{"name":"bad-secret","value":"secret123"}')
        print_test_result "Crypto-mgr CANNOT create secrets (POST /secrets)" "403" "$STATUS"

        # Crypto manager CANNOT create users
        STATUS=$(make_request "POST" "/users" "$CRYPTO_MGR_TOKEN" '{"username":"baduser","password":"bad123","role":"user"}')
        print_test_result "Crypto-mgr CANNOT create users (POST /users)" "403" "$STATUS"
    fi
fi

print_section "Testing Public Endpoints"

# Health endpoint should work without authentication
STATUS=$(curl -s -w "%{http_code}" -o /dev/null "$BASE_URL/health")
print_test_result "Public health endpoint (GET /health)" "200" "$STATUS"

# Login endpoint should work without authentication
STATUS=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrongpass"}' \
    -w "%{http_code}" \
    -o /dev/null \
    "$API_URL/auth/login")
print_test_result "Public login endpoint (POST /auth/login)" "401" "$STATUS"

# Final summary
print_section "Test Summary"
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed${NC}"
    exit 1
fi
