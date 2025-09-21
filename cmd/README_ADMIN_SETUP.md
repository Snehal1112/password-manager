# Password Manager - Admin Setup Guide

## 🚀 Quick Start: Create Admin User

The password manager includes comprehensive scripts for admin user creation and TOTP management.

### Prerequisites
- Password manager built: `go build -o password-manager`
- Configuration file with bootstrap token
- SQLite3 (optional, for database management)

### 1. Automated Admin Creation

```bash
# Create admin with test configuration and TOTP generation
./scripts/create_admin.sh --test --generate-totp

# Create admin with custom credentials
./scripts/create_admin.sh -u superadmin -p MySecurePassword123 --generate-totp

# Production setup
./scripts/create_admin.sh -u admin -p ProductionPassword --config .password-manager.yaml
```

### 2. Manual TOTP Code Generation

```bash
# Generate TOTP codes for authentication
go run scripts/totp_generator.go -secret="YOUR_TOTP_SECRET" -username="admin"

# Use saved admin secret (auto-detected)
go run scripts/totp_generator.go
```

### 3. Complete Authentication Test

```bash
# Get current TOTP code
TOTP_CODE=$(./totp_test -secret="SZCL7YSJ4PY3UG65B3ABIMTKZJBR5RYX" -count=0 | grep "Current TOTP Code" | awk '{print $4}')

# Test authentication
./password-manager --config=.password-manager-test.yaml \
  --username=admin \
  --password=admin123 \
  --totp-code=$TOTP_CODE \
  users list
```

## 📋 Configuration Examples

### Test Configuration (`.password-manager-test.yaml`)
```yaml
database:
  connection: "./test_restore.db"
log:
  level: "debug"
  file: "password_manager.log"
master_key: "***SECRET-REMOVED-2026-08-17***"
jwt_secret: "***SECRET-REMOVED-2026-08-17***"
bootstrap_token: "***SECRET-REMOVED-2026-08-17***"
```

### Production Configuration (`.password-manager.yaml`)
```yaml
database:
  connection: "./secrets.db"
log:
  level: "info"
  file: "password-manager.log"
master_key: "YOUR_32_BYTE_BASE64_KEY"
jwt_secret: "YOUR_JWT_SECRET"
bootstrap_token: "YOUR_BOOTSTRAP_TOKEN"
```

## 🔧 Manual Database Setup (if needed)

```bash
# Create bootstrap token in database
sqlite3 ./test_restore.db "INSERT OR REPLACE INTO bootstrap_tokens (token, used, created_at) VALUES ('***SECRET-REMOVED-2026-08-17***', 0, datetime('now'));"

# Verify token exists
sqlite3 ./test_restore.db "SELECT * FROM bootstrap_tokens;"
```

## 🛡️ Security Best Practices

1. **Strong Passwords**: Use complex passwords for admin accounts
2. **Bootstrap Tokens**: Generate unique tokens and invalidate after use
3. **TOTP Secrets**: Store securely and delete temporary files
4. **Configuration**: Keep config files secure, avoid committing secrets

## 📖 Workflow Example

```bash
# 1. Build the application
go build -o password-manager

# 2. Setup test environment
./scripts/create_admin.sh --test --generate-totp

# 3. Extract TOTP secret and generate code
TOTP_SECRET=$(grep "secret=" .admin_totp_secret | sed 's/.*secret=\([^&]*\).*/\1/')
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$TOTP_SECRET" -count=0 | grep "Current TOTP Code" | awk '{print $4}')

# 4. Test authentication
./password-manager --config=.password-manager-test.yaml \
  --username=admin \
  --password=admin123 \
  --totp-code=$TOTP_CODE \
  users list

# 5. Create additional users
./password-manager --config=.password-manager-test.yaml \
  --username=admin \
  --password=admin123 \
  --totp-code=$TOTP_CODE \
  users create --new-username=testuser --new-password=password123 --new-role=user

# 6. Clean up sensitive files
rm -f .admin_totp_secret
```

## 🔍 Troubleshooting

### Bootstrap Token Issues
```bash
# Check if token exists in config
grep "bootstrap_token" .password-manager-test.yaml

# Check if token exists in database
sqlite3 ./test_restore.db "SELECT * FROM bootstrap_tokens WHERE used = 0;"

# Re-add token if missing
sqlite3 ./test_restore.db "INSERT OR REPLACE INTO bootstrap_tokens (token, used, created_at) VALUES ('***SECRET-REMOVED-2026-08-17***', 0, datetime('now'));"
```

### TOTP Issues
```bash
# Test TOTP generation manually
go run scripts/totp_generator.go -secret="ABCD1234EFGH5678IJKL9012MNOP3456" -count=1

# Verify current time (TOTP is time-sensitive)
date
```

### Authentication Issues
```bash
# Check user exists
sqlite3 ./test_restore.db "SELECT id, username, role FROM users;"

# Verify password hash
sqlite3 ./test_restore.db "SELECT username, password_hash FROM users WHERE username='admin';"
```

## 📚 Related Files

- `scripts/create_admin.sh` - Automated admin creation script
- `scripts/totp_generator.go` - Enhanced TOTP code generator
- `scripts/README.md` - Comprehensive script documentation
- `test/totp_generator.go` - Original TOTP generator
- `cmd/users/admin.go` - Admin registration command implementation

---

**Admin Credentials for Testing:**
- Username: `admin`
- Password: `admin123`
- TOTP Secret: Generated dynamically (check `.admin_totp_secret` after creation)
- Bootstrap Token: `***SECRET-REMOVED-2026-08-17***`