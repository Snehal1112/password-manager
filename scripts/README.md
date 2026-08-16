# Password Manager Scripts

This directory contains utility scripts for managing the Password Manager application.

## 📁 Available Scripts

### 🔐 `create_admin.sh` - Admin User Creation Script

Comprehensive script to create the initial admin user with TOTP setup.

**Features:**
- ✅ Automated admin user creation
- ✅ Bootstrap token validation
- ✅ Database setup and verification
- ✅ TOTP secret extraction and management
- ✅ Automatic TOTP code generation
- ✅ Support for test and production configurations

**Usage:**
```bash
# Basic usage with defaults
./scripts/create_admin.sh

# Custom username and password
./scripts/create_admin.sh -u superadmin -p mypassword123

# Use test configuration and generate TOTP codes
./scripts/create_admin.sh --test --generate-totp

# Show help
./scripts/create_admin.sh --help
```

**Options:**
- `-u, --username` - Admin username (default: admin)
- `-p, --password` - Admin password (default: admin123)
- `-c, --config` - Configuration file (default: .password-manager.yaml)
- `-t, --test` - Use test configuration (.password-manager-test.yaml)
- `-g, --generate-totp` - Generate TOTP codes after creation
- `-h, --help` - Show help message

### 🔑 `totp_generator.go` - Enhanced TOTP Code Generator

Advanced TOTP generator with support for custom secrets and multiple time periods.

**Features:**
- ✅ Generate current TOTP codes
- ✅ Generate future TOTP codes
- ✅ Support custom TOTP secrets
- ✅ Automatic secret detection from saved files
- ✅ QR code setup information
- ✅ Authentication examples

**Usage:**
```bash
# Generate codes using saved admin secret
go run scripts/totp_generator.go

# Generate codes for specific user with custom secret
go run scripts/totp_generator.go -secret="ABCD1234EFGH5678" -username="myuser"

# Generate only current code
go run scripts/totp_generator.go -count=0

# Generate many future codes for testing
go run scripts/totp_generator.go -count=10
```

**Options:**
- `-secret` - TOTP secret key (auto-detects from .admin_totp_secret if not provided)
- `-username` - Username for display (default: admin)
- `-count` - Number of future codes to generate (default: 3)
- `-help` - Show help message

## 🚀 Quick Start Guide

### 1. First-Time Setup

```bash
# Build the password manager
go build -o password-manager

# Create admin user with defaults
./scripts/create_admin.sh --test --generate-totp
```

### 2. Production Setup

```bash
# Edit production configuration
vim .password-manager.yaml

# Create production admin user
./scripts/create_admin.sh -u admin -p YourSecurePassword123
```

### 3. Generate TOTP for Authentication

```bash
# Generate current TOTP code
go run scripts/totp_generator.go

# Use the code for authentication
./password-manager --username=admin --password=admin123 --totp-code=123456 users list
```

## 📋 Prerequisites

- Go 1.24+ installed
- Password Manager built (`go build -o password-manager`)
- Valid configuration file (`.password-manager.yaml` or test config)
- Bootstrap token configured in the configuration file

## 🔧 Configuration Files

### Production Config (`.password-manager.yaml`)
```yaml
database:
  connection: "./secrets.db"
log:
  level: "info"
  file: "password-manager.log"
master_key: "your-master-key-here"
jwt_secret: "your-jwt-secret-here"
bootstrap_token: "your-bootstrap-token-here"
```

### Test Config (`.password-manager-test.yaml`)
```yaml
database:
  connection: "./test_restore.db"
log:
  level: "debug"
  file: "password_manager.log"
master_key: "your-master-key-here"
jwt_secret: "your-jwt-secret-here"
bootstrap_token: "your-bootstrap-token-here"
```

## 🛡️ Security Best Practices

1. **Bootstrap Tokens**: Use strong, unique bootstrap tokens and invalidate them after use
2. **TOTP Secrets**: Store TOTP secrets securely and delete temporary files
3. **Passwords**: Use strong passwords for admin accounts
4. **Configuration**: Keep configuration files secure and avoid committing secrets to version control

## 🔍 Troubleshooting

### Common Issues

**Bootstrap Token Not Found:**
```bash
# Check if token exists in config
grep "bootstrap_token" .password-manager.yaml

# Manually insert token into database (if needed)
sqlite3 ./test_restore.db "INSERT INTO bootstrap_tokens (token, used, created_at) VALUES ('your-token', 0, datetime('now'));"
```

**Database Permission Issues:**
```bash
# Check database file permissions
ls -la *.db

# Fix permissions if needed
chmod 644 *.db
```

**TOTP Generation Fails:**
```bash
# Check if dependencies are available
go mod tidy

# Test TOTP generation manually
go run scripts/totp_generator.go -secret="TEST123456789012345" -count=1
```

## 📖 Examples

### Complete Admin Setup Workflow

```bash
# 1. Build the application
go build -o password-manager

# 2. Set up test environment
./scripts/create_admin.sh --test --generate-totp

# 3. Test authentication
TOTP_CODE=$(go run scripts/totp_generator.go -count=0 | grep "Current TOTP Code" | awk '{print $4}')
./password-manager --config=.password-manager-test.yaml --username=admin --password=admin123 --totp-code=$TOTP_CODE users list

# 4. Create additional users
./password-manager --config=.password-manager-test.yaml --username=admin --password=admin123 --totp-code=$TOTP_CODE users create --new-username=testuser --new-password=password123 --new-role=user
```

### Production Deployment

```bash
# 1. Generate secure tokens
BOOTSTRAP_TOKEN=$(openssl rand -hex 16)
MASTER_KEY=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 64)

# 2. Update production config with secure values
# Edit .password-manager.yaml with generated tokens

# 3. Create production admin
./scripts/create_admin.sh -u admin -p "$(openssl rand -base64 16)" --generate-totp

# 4. Secure the environment
chmod 600 .password-manager.yaml
rm -f .admin_totp_secret  # After configuring authenticator app
```

## 📚 Related Documentation

- [Main Project Documentation](../CLAUDE.md)
- [CLI Test Suite](../cmd/test_summary.md)
- [Service Architecture](../.claude/service-layer-analysis.md)
- [Security Guide](../.claude/auth-elimination-guide.md)

## rocketvault-fetch-secrets.sh

Fetches secrets from a running RocketVault instance using the OAuth2 client
credentials flow and exports them as environment variables.

### Prerequisites

- `curl` and `jq` must be available in the shell
- A service account must exist in RocketVault (`POST /api/v1/service-accounts`)
- The service account must have read access to the target secrets via access policies

### Required environment variables

| Variable | Purpose |
|---|---|
| `VAULT_URL` | RocketVault base URL, e.g. `https://vault.internal:8774` |
| `VAULT_CLIENT_ID` | Service account client ID |
| `VAULT_CLIENT_SECRET` | Service account client secret |
| `VAULT_SECRETS` | Space-separated `ENV_VAR_NAME=secret-uuid` pairs |

### Optional environment variables

| Variable | Purpose |
|---|---|
| `VAULT_ENV_FILE` | If set, secrets are also written to this file with `chmod 600` |
| `VAULT_INSECURE` | Set to `1` to skip TLS verification (dev/self-signed certs only) |

### Usage

```sh
export VAULT_URL=https://vault.internal:8774
export VAULT_CLIENT_ID=ci-runner
export VAULT_CLIENT_SECRET=$CI_VAULT_SECRET
export VAULT_SECRETS="DB_PASSWORD=<uuid> API_KEY=<uuid>"
export VAULT_ENV_FILE=.env   # optional

source scripts/rocketvault-fetch-secrets.sh
# $DB_PASSWORD and $API_KEY are now set
```

### Security notes

- Script uses `set +x` — secret values will not appear in CI trace logs
- `.env` file is created with `chmod 600`
- All internal variables are unset after completion
- Set `VAULT_INSECURE=1` only in non-production environments

---

**Note**: Always test scripts in a development environment before using in production. Keep TOTP secrets secure and follow security best practices for production deployments.