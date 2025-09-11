#!/bin/bash
# validate-api-docs.sh - Validate API documentation completeness

set -e

echo "🔍 Validating API Documentation..."
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "success" ]; then
        echo -e "${GREEN}✓${NC} $message"
    elif [ "$status" = "warning" ]; then
        echo -e "${YELLOW}⚠${NC} $message"
    else
        echo -e "${RED}✗${NC} $message"
    fi
}

# Check if files exist
check_file() {
    local file=$1
    local description=$2
    if [ -f "$file" ]; then
        print_status "success" "$description found: $file"
        return 0
    else
        print_status "error" "$description missing: $file"
        return 1
    fi
}

# Validate YAML syntax
# Uses yamllint for validation (preferred), falls back to Python yaml module if available
# This ensures validation works in environments where Python yaml module may not be installed
validate_yaml() {
    local file=$1
    if command -v yamllint &> /dev/null; then
        if yamllint "$file" 2>/dev/null; then
            print_status "success" "YAML syntax valid: $file"
            return 0
        else
            print_status "error" "YAML syntax invalid: $file"
            return 1
        fi
    elif command -v python3 &> /dev/null; then
        if python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
            print_status "success" "YAML syntax valid: $file"
            return 0
        else
            print_status "error" "YAML syntax invalid: $file"
            return 1
        fi
    else
        print_status "warning" "Neither yamllint nor Python3 available, skipping YAML validation for $file"
        return 0
    fi
}

# Check file sizes (ensure they're not empty)
check_file_size() {
    local file=$1
    local min_size=${2:-100} # Minimum size in bytes
    local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
    if [ "$size" -gt "$min_size" ]; then
        print_status "success" "File size OK: $file (${size} bytes)"
        return 0
    else
        print_status "error" "File too small: $file (${size} bytes)"
        return 1
    fi
}

# Check for required content in files
check_content() {
    local file=$1
    local pattern=$2
    local description=$3
    if grep -q "$pattern" "$file"; then
        print_status "success" "$description found in $file"
        return 0
    else
        print_status "error" "$description missing in $file"
        return 1
    fi
}

echo ""
echo "📁 Checking Documentation Files..."
echo "-----------------------------------"

# Check main documentation files
check_file "docs/api-specification.yaml" "OpenAPI Specification"
check_file "docs/api-developer-guide.md" "API Developer Guide"
check_file "docs/integration-examples.md" "Integration Examples"
check_file "README.markdown" "Main README"

echo ""
echo "📏 Checking File Sizes..."
echo "------------------------"

# Validate file sizes
check_file_size "docs/api-specification.yaml" 5000
check_file_size "docs/api-developer-guide.md" 10000
check_file_size "docs/integration-examples.md" 20000

echo ""
echo "🔧 Checking File Content..."
echo "---------------------------"

# Check for key content in OpenAPI spec
check_content "docs/api-specification.yaml" "openapi: 3.0.3" "OpenAPI version declaration"
check_content "docs/api-specification.yaml" "Password Manager API" "API title"
check_content "docs/api-specification.yaml" "/health" "Health endpoints"
check_content "docs/api-specification.yaml" "/secrets" "Secrets endpoints"
check_content "docs/api-specification.yaml" "bearerAuth" "Authentication definition"

# Check for key content in developer guide
check_content "docs/api-developer-guide.md" "## Authentication" "Authentication section"
check_content "docs/api-developer-guide.md" "## API Endpoints" "API endpoints section"
check_content "docs/api-developer-guide.md" "## Error Handling" "Error handling section"
check_content "docs/api-developer-guide.md" "## SDK Examples" "SDK examples section"

# Check for key content in integration examples
check_content "docs/integration-examples.md" "## Authentication Flow" "Authentication flow examples"
check_content "docs/integration-examples.md" "## Secret Backup and Restore" "Backup/restore examples"
check_content "docs/integration-examples.md" "## CI/CD Pipeline Integration" "CI/CD integration examples"

# Check README updates
check_content "README.markdown" "## Documentation" "Documentation section in README"
check_content "README.markdown" "## API Endpoints" "API endpoints section in README"
check_content "README.markdown" "api-specification.yaml" "OpenAPI spec link in README"

echo ""
echo "📝 Validating YAML Syntax..."
echo "-----------------------------"

# Validate YAML files
validate_yaml "docs/api-specification.yaml"

echo ""
echo "🔗 Checking Cross-References..."
echo "-------------------------------"

# Check if README links point to existing files
if grep -q "docs/api-specification.yaml" README.markdown && [ -f "docs/api-specification.yaml" ]; then
    print_status "success" "README links to existing OpenAPI spec"
else
    print_status "error" "README links to missing OpenAPI spec"
fi

if grep -q "docs/api-developer-guide.md" README.markdown && [ -f "docs/api-developer-guide.md" ]; then
    print_status "success" "README links to existing developer guide"
else
    print_status "error" "README links to missing developer guide"
fi

if grep -q "docs/integration-examples.md" README.markdown && [ -f "docs/integration-examples.md" ]; then
    print_status "success" "README links to existing integration examples"
else
    print_status "error" "README links to missing integration examples"
fi

echo ""
echo "📊 Documentation Summary"
echo "========================"

total_files=4
existing_files=$(find docs/ -name "*.yaml" -o -name "*.md" | wc -l)
readme_updated=$(grep -c "api-specification.yaml" README.markdown || echo "0")

echo "Total documentation files: $total_files"
echo "Files created: $existing_files"
echo "README updated: $([ "$readme_updated" -gt 0 ] && echo "Yes" || echo "No")"

if [ "$existing_files" -eq "$total_files" ] && [ "$readme_updated" -gt 0 ]; then
    echo ""
    print_status "success" "🎉 API Documentation Complete!"
    echo ""
    echo "📚 Documentation Overview:"
    echo "  • OpenAPI 3.0.3 Specification: docs/api-specification.yaml"
    echo "  • Developer Guide: docs/api-developer-guide.md"
    echo "  • Integration Examples: docs/integration-examples.md"
    echo "  • Updated README: README.markdown"
    echo ""
    echo "🚀 Ready for production deployment!"
else
    echo ""
    print_status "error" "❌ API Documentation Incomplete"
    exit 1
fi
