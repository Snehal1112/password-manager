# Configuration

This document outlines the configuration options for the Password Manager application, which uses `github.com/spf13/viper` to manage settings via environment variables or a configuration file.

## Overview
The Password Manager requires configuration for database connections, encryption keys, logging, and other operational parameters. Settings can be specified in a configuration file (e.g., `config.yaml`) or as environment variables.

## Configuration File
Create a `config.yaml` file in the project root or a specified directory. Example:

```yaml
database:
  type: sqlite
  connection: ./password_manager.db
  # For PostgreSQL:
  # type: postgres
  # connection: host=localhost user=postgres password=secret dbname=password_manager sslmode=disable
jwt_secret: test-jwt-secret
master_key: <base64-encoded-32-byte-key>
log:
  file: test.log
  level: debug
api:
  rate_limit: 10-M
```

To use the configuration file, set the `CONFIG_PATH` environment variable or specify it when running the application:

```bash
CONFIG_PATH=./config.yaml ./password-manager setup --db-type sqlite
```

## Environment Variables
Environment variables override configuration file settings. Use the following prefixes:

- `PASSWORD_MANAGER_DATABASE_TYPE`: Database type (`sqlite` or `postgres`).
- `PASSWORD_MANAGER_DATABASE_CONNECTION`: Database connection string.
- `PASSWORD_MANAGER_JWT_SECRET`: Secret for JWT signing.
- `PASSWORD_MANAGER_MASTER_KEY`: 32-byte base64-encoded key for encryption.
- `PASSWORD_MANAGER_LOG_FILE`: Log file path.
- `PASSWORD_MANAGER_LOG_LEVEL`: Log level (`debug`, `info`, `warn`, `error`).
- `PASSWORD_MANAGER_API_RATE_LIMIT`: API rate limit (e.g., `10-M` for 10 requests per minute).

Example:

```bash
export PASSWORD_MANAGER_DATABASE_TYPE=sqlite
export PASSWORD_MANAGER_DATABASE_CONNECTION=./password_manager.db
export PASSWORD_MANAGER_JWT_SECRET=test-jwt-secret
export PASSWORD_MANAGER_MASTER_KEY=$(openssl rand -base64 32)
export PASSWORD_MANAGER_LOG_FILE=test.log
export PASSWORD_MANAGER_LOG_LEVEL=debug
./password-manager setup
```

## Generating the Master Key
The `master_key` is a 256-bit (32-byte) key used for encrypting secrets, keys, and certificates. Generate it securely:

```bash
openssl rand -base64 32
```

Store the key securely (e.g., in a HashiCorp Vault instance or secure environment variable).

## Logging Configuration
- **Log File**: Logs are written to the specified file (e.g., `test.log`) in JSON format.
- **Log Level**: Set to `debug` for development, `info` for production.
- **Audit Logs**: Stored in the `audit_logs` table with a planned 90-day retention policy.

## Planned Configuration Options
- **Backup Settings**: Directory or S3-compatible storage for encrypted backups.
- **API Settings**: Port, TLS certificates, and rate limit thresholds.
- **Monitoring**: Prometheus endpoint and Slack webhook for alerts.
- **HSM**: PKCS#11 provider and credentials.

## Security Considerations
- Store `jwt_secret` and `master_key` in a secure location (e.g., environment variables, HashiCorp Vault).
- Restrict access to the configuration file (`config.yaml`) with file permissions (e.g., `chmod 600 config.yaml`).
- Use strong, unique database credentials for PostgreSQL in production.

For troubleshooting configuration issues, see [troubleshooting.md](troubleshooting.md).