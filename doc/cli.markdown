# CLI Documentation

This document provides detailed instructions for using the Password Manager’s command-line interface (CLI), built with `github.com/spf13/cobra`. The CLI allows users to manage users, cryptographic keys, and X.509 certificates securely.

## Overview
The CLI is the primary interface for interacting with the Password Manager. It supports commands for user registration, key management, and certificate management, with role-based access control (RBAC) and multi-factor authentication (MFA) using TOTP.

## Installation
See the [README](../README.md#installation) for installation instructions.

## Commands
### Setup
Initializes the database and admin user (not yet implemented).

```bash
./password-manager setup --db-type sqlite --db-path ./password_manager.db
```

**Flags**:
- `--db-type`: Database type (`sqlite` or `postgres`).
- `--db-path`: SQLite database file path (e.g., `./password_manager.db`).
- `--db-connection`: PostgreSQL connection string (e.g., `host=localhost user=postgres password=secret dbname=password_manager sslmode=disable`).

### Register
Registers a new user with a username, password, and role.

```bash
./password-manager register --username admin --password admin123 --role crypto_manager
```

**Flags**:
- `--username`: Username (required).
- `--password`: Password (required).
- `--role`: Role (`crypto_manager` or `user`, default: `user`).

### Keys
Manages cryptographic keys (RSA and ECDSA).

#### Generate
Generates a new key.

```bash
./password-manager keys generate --type rsa --name test-key --bits 2048 --tags prod --username admin --password admin123 --totp-code 123456
```

**Flags**:
- `--type`: Key type (`rsa` or `ecdsa`, required).
- `--name`: Key name (required).
- `--bits`: Key size for RSA (e.g., 2048, default: 2048).
- `--curve`: Curve for ECDSA (e.g., `P-256`, default: `P-256`).
- `--tags`: Comma-separated tags (e.g., `prod,api`).
- `--username`, `--password`, `--totp-code`: Authentication credentials.

#### Get
Retrieves a key by ID.

```bash
./password-manager keys get 1 --username admin --password admin123 --totp-code 123456
```

**Arguments**:
- `id`: Key ID (required).

#### List
Lists keys with optional tag filtering.

```bash
./password-manager keys list --type rsa --tags prod --username admin --password admin123 --totp-code 123456
```

**Flags**:
- `--type`: Filter by key type (`rsa` or `ecdsa`).
- `--tags`: Filter by tags (e.g., `prod`).

#### Rotate
Rotates a key by ID.

```bash
./password-manager keys rotate 1 --username admin --password admin123 --totp-code 123456
```

**Arguments**:
- `id`: Key ID (required).

#### Delete
Deletes a key by ID.

```bash
./password-manager keys delete 1 --username admin --password admin123 --totp-code 123456
```

**Arguments**:
- `id`: Key ID (required).

### Certificates
Manages X.509 certificates.

#### Generate
Generates a self-signed or CA-signed certificate.

```bash
./password-manager certificates generate --key-id 1 --name test-cert --validity-days 365 --tags prod,api --username admin --password admin123 --totp-code 123456
```

**Flags**:
- `--key-id`: ID of the private key (required).
- `--ca-cert-id`: ID of the CA certificate (omit for self-signed).
- `--name`: Certificate name (default: `cert-<userID>`).
- `--validity-days`: Validity period in days (default: 365).
- `--tags`: Comma-separated tags.
- `--username`, `--password`, `--totp-code`: Authentication credentials.

#### Get
Retrieves a certificate by ID.

```bash
./password-manager certificates get 1 --username admin --password admin123 --totp-code 123456
```

**Arguments**:
- `id`: Certificate ID (required).

#### List
Lists certificates with optional tag filtering.

```bash
./password-manager certificates list --tags prod --username admin --password admin123 --totp-code 123456
```

**Flags**:
- `--type`: Filter by certificate type (not yet implemented).
- `--tags`: Filter by tags.

#### Revoke
Revokes a certificate by ID.

```bash
./password-manager certificates revoke 1 123456789 test-cert --username admin --password admin123 --totp-code 123456
```

**Arguments**:
- `id`: Certificate ID (required).
- `serial-number`: Certificate serial number (required).
- `name`: Certificate name (required).

#### Delete
Deletes a certificate by ID.

```bash
./password-manager certificates delete 1 --username admin --password admin123 --totp-code 123456
```

**Arguments**:
- `id`: Certificate ID (required).

## Authentication
All commands except `setup` and `register` require authentication via `--username`, `--password`, and `--totp-code`. Users must have the `crypto_manager` role to perform key and certificate operations.

## Logging
CLI operations are logged to a file (default: `test.log`) and stdout in JSON format using `github.com/sirupsen/logrus`. Audit logs are stored in the `audit_logs` table.

## Planned Commands
- **Secrets Management**: Commands for secrets (`generate`, `get`, `list`, `delete`) with versioning and export/import.
- **Backup/Restore**: Commands for encrypted database backups and restores.
- **Password Generator**: Command to generate strong passwords with configurable parameters.

For troubleshooting CLI issues, see [troubleshooting.md](troubleshooting.md).