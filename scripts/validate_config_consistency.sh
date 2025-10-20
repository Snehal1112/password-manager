#!/bin/bash

# Configuration Consistency Validation Script
# Ensures all environment configurations have the same structure

echo "🔍 Configuration Consistency Validation"
echo "======================================="

# Configuration files to validate
CONFIGS=(
    ".password-manager.yaml"
    ".password-manager-test.yaml"
    ".password-manager-staging.yaml"
    ".password-manager-production.yaml"
    "test-config.yaml"
)

# Required sections in each configuration
REQUIRED_SECTIONS=(
    "master_key"
    "jwt_secret"
    "bootstrap_token"
    "environment"
    "database"
    "log"
    "server"
    "monitoring"
    "health"
)

# Validation results
VALIDATION_PASSED=true
ISSUES_FOUND=()

echo "📋 Validating configuration files..."
echo

for config in "${CONFIGS[@]}"; do
    if [ ! -f "$config" ]; then
        echo "❌ Missing configuration file: $config"
        VALIDATION_PASSED=false
        ISSUES_FOUND+=("Missing file: $config")
        continue
    fi

    echo "✅ Found: $config"

    # Check for required sections
    for section in "${REQUIRED_SECTIONS[@]}"; do
        if ! grep -q "^$section:" "$config" && ! grep -q "^# $section" "$config"; then
            echo "  ⚠️  Missing section: $section"
            VALIDATION_PASSED=false
            ISSUES_FOUND+=("$config: Missing section $section")
        fi
    done
done

echo
echo "📊 Validation Summary"
echo "===================="

if [ "$VALIDATION_PASSED" = true ]; then
    echo "✅ All configuration files are consistent!"
    echo "🎯 Structure validation: PASSED"
    echo "📝 All required sections present in all files"
else
    echo "❌ Configuration consistency issues found:"
    for issue in "${ISSUES_FOUND[@]}"; do
        echo "  - $issue"
    done
    echo
    echo "🔧 Please address the issues above to ensure consistency"
fi

echo
echo "📋 Configuration File Summary:"
echo "=============================="
for config in "${CONFIGS[@]}"; do
    if [ -f "$config" ]; then
        echo "📄 $config:"
        echo "  Environment: $(grep '^environment:' "$config" | cut -d'"' -f2 | cut -d"'" -f2)"
        echo "  Database: $(grep 'connection:' "$config" | head -1 | cut -d':' -f2 | xargs)"
        echo "  Log Level: $(grep 'level:' "$config" | head -1 | cut -d'"' -f2 | cut -d"'" -f2)"
        echo
    fi
done

if [ "$VALIDATION_PASSED" = true ]; then
    exit 0
else
    exit 1
fi