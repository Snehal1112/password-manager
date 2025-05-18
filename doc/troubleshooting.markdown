# Troubleshooting

This document provides guidance for diagnosing and resolving common issues with the Password Manager application.

## Overview
The Password Manager is a Go-based application with a CLI interface, SQLite database (development), and planned PostgreSQL support (production). Issues may arise from configuration, authentication, database connectivity, or command execution. This guide covers common problems and solutions.

## Common Issues
### 1. Database Connection Failure
**Symptoms**:
- Error: `Failed to open database: ...` or `Failed to ping database: ...`
- CLI commands fail to execute.

**Causes**:
- Incorrect database path or connection string.
- SQLite file permissions issue.
- PostgreSQL server not running or inaccessible.

**Solutions**:
- **Verify Configuration**:
  - Check `config.yaml` or environment variables (`PASSWORD_MANAGER_DATABASE_TYPE`, `PASSWORD_MANAGER_DATABASE_CONNECTION`).
  - For SQLite, ensure the database file path is correct (e.g., `./password_manager.db`).
  - For PostgreSQL, verify the connection string (e.g., `host=localhost user=postgres password=secret dbname=password_manager sslmode=disable`).
- **Check File Permissions**:
  - Ensure the SQLite file is writable:
    ```bash
    chmod 664 password_manager.db
    ```
- **Start PostgreSQL**:
  - Ensure the PostgreSQL server is running:
    ```bash
    sudo systemctl start postgresql
    ```
  - Verify connectivity:
    ```bash
    psql -h localhost -U postgres -d password_manager
    ```
- **Review Logs**:
  - Check `test.log` for detailed errors:
    ```bash
    cat test.log | grep "Failed to open database"
    ```

### 2. Authentication Failure
**Symptoms**:
- Error: `Error: authentication failed: ...` or `invalid token`.
- CLI commands reject credentials.

**Causes**:
- Incorrect username, password, or TOTP code.
- Invalid `jwt_secret` in configuration.
- TOTP secret mismatch.

**Solutions**:
- **Verify Credentials**:
  - Ensure the username and password match a registered user:
    ```bash
    ./password-manager register --username testuser --password password123 --role crypto_manager
    ```
  - Generate a valid TOTP code using the user’s TOTP secret (displayed during registration).
- **Check JWT Secret**:
  - Verify `jwt_secret` in `config.yaml` or `PASSWORD_MANAGER_JWT_SECRET` is set correctly.
- **Reset TOTP**:
  - If TOTP secret is lost, re-register the user or update the `totp_secret` in the `users` table (requires database access).
- **Review Logs**:
  - Check `test.log` for authentication errors:
    ```bash
    cat test.log | grep "authentication failed"
    ```

### 3. RBAC Permission Errors
**Symptoms**:
- Error: `Error: insufficient permissions`.
- Key or certificate commands fail.

**Causes**:
- User lacks `crypto_manager` role.

**Solutions**:
- **Verify User Role**:
  - Check the user’s role in the `users` table:
    ```bash
    sqlite3 password_manager.db "SELECT username, role FROM users WHERE username = 'testuser';"
    ```
  - Re-register with `crypto_manager` role:
    ```bash
    ./password-manager register --username testuser --password password123 --role crypto_manager
    ```
- **Review Logs**:
  - Check `test.log` for RBAC errors:
    ```bash
    cat test.log | grep "insufficient permissions"
    ```

### 4. Command Execution Errors
**Symptoms**:
- Errors like `Error: key-id is required` or `Error generating certificate: ...`.
- CLI commands produce unexpected output.

**Causes**:
- Missing or invalid command flags (e.g., `--key-id`).
- Database inconsistencies (e.g., missing key for certificate generation).
- Configuration issues (e.g., invalid `master_key`).

**Solutions**:
- **Verify Flags**:
  - Check command syntax in [cli.md](cli.md).
  - Example for certificate generation:
    ```bash
    ./password-manager certificates generate --key-id 1 --name test-cert --validity-days 365 --tags prod --username admin --password admin123 --totp-code 123456
    ```
- **Check Database**:
  - Ensure the referenced key exists:
    ```bash
    sqlite3 password_manager.db "SELECT id, name FROM keys WHERE id = 1;"
    ```
- **Validate Master Key**:
  - Ensure `master_key` is a valid 32-byte base64-encoded key in `config.yaml` or `PASSWORD_MANAGER_MASTER_KEY`.
  - Regenerate if needed:
    ```bash
    openssl rand -base64 32
    ```
- **Review Logs**:
  - Check `test.log` for command-specific errors:
    ```bash
    cat test.log | grep "Error generating certificate"
    ```

### 5. Test Failures
**Symptoms**:
- Unit tests fail (e.g., `go test ./...` produces errors).
- `BenchmarkCreateSelfSigned` fails (currently deferred).

**Causes**:
- Missing dependencies.
- Database setup issues.
- Mock mismatches in tests.

**Solutions**:
- **Install Dependencies**:
  - Run:
    ```bash
    go mod tidy
    ```
- **Run Tests with Skip**:
  - Skip the failing benchmark:
    ```bash
    go test ./... -v -cover -skip BenchmarkCreateSelfSigned
    ```
- **Check Test Logs**:
  - Review `test.log` for test-specific errors:
    ```bash
    cat test.log | grep "FAIL"
    ```
- **Debug Mocks**:
  - For `BenchmarkCreateSelfSigned`, check mock expectations in `internal/certificates/certificates_test.go`.

## General Debugging Tips
- **Enable Debug Logging**:
  - Set `log.level` to `debug` in `config.yaml` or `PASSWORD_MANAGER_LOG_LEVEL=debug`.
- **Inspect Database**:
  - Use SQLite CLI to query tables:
    ```bash
    sqlite3 password_manager.db
    .tables
    SELECT * FROM audit_logs;
    ```
- **Clear Database**:
  - Reset the database for testing:
    ```bash
    rm password_manager.db
    ./password-manager setup --db-type sqlite --db-path ./password_manager.db
    ```
- **Check Dependencies**:
  - Verify Go version (1.24+):
    ```bash
    go version
    ```
  - Update dependencies:
    ```bash
    go get -u ./...
    ```

## Getting Help
If issues persist:
- Check the [GitHub Issues](https://github.com/snehal1112/password-manager/issues) for similar problems.
- Open a new issue with:
  - Error message and stack trace.
  - Contents of `test.log` (redact sensitive data).
  - Steps to reproduce the issue.
  - Output of `go version` and `go env`.

For configuration issues, see [configuration.md](configuration.md).