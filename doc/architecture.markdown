# Architecture

This document describes the architecture of the Password Manager application, a self-hosted, production-ready solution for secure storage and management of secrets, keys, and certificates. The architecture is designed to ensure security, scalability, and maintainability, drawing inspiration from Microsoft Azure Key Vault but implemented without cloud dependencies.

## Overview
The Password Manager is a Go-based application with a modular design, using a CLI interface for user interaction and a planned RESTful API for programmatic access. It leverages SQLite for development and supports PostgreSQL for production scalability, with encrypted storage for sensitive data.

## Components
The application is organized into the following components:

### CLI Interface
- **Purpose**: Provides a command-line interface for managing users, secrets, keys, and certificates.
- **Implementation**: Built with `github.com/spf13/cobra`, offering commands like `register`, `keys generate`, and `certificates list`.
- **Location**: `cmd/password-manager/`
- **Features**:
  - Role-based access control (RBAC) with `crypto_manager` and `user` roles.
  - Multi-factor authentication (MFA) using TOTP.
  - Tag-based filtering for keys and certificates (e.g., `--tags prod`).

### Database Layer
- **Purpose**: Manages persistent storage of users, secrets, keys, certificates, and audit logs.
- **Implementation**: Uses `database/sql` with `github.com/mattn/go-sqlite3` (development) and planned `github.com/lib/pq` (production).
- **Location**: `internal/db/`
- **Schema**:
  - `users`: Stores user credentials (username, password_hash, role, totp_secret).
  - `secrets`: Stores encrypted secrets (not yet implemented).
  - `keys`: Stores encrypted RSA/ECDSA keys with type and tags.
  - `certificates`: Stores encrypted X.509 certificates with tags.
  - `key_tags`, `certificate_tags`: Support tag-based filtering.
  - `crl`: Stores certificate revocation lists.
  - `audit_logs`: Tracks user actions for auditing.
- **Features**:
  - Encryption using `crypto/aes` for sensitive data.
  - Go Generics for type-safe repository operations (`tags.go`).

### Key Management
- **Purpose**: Handles generation, storage, and management of cryptographic keys.
- **Implementation**: Uses `crypto/rsa` and `crypto/ecdsa` for RSA and ECDSA keys.
- **Location**: `internal/keys/`
- **Features**:
  - Key generation with configurable parameters (e.g., `--bits 2048`).
  - CRUD operations, rotation, and tag support.
  - Planned HSM integration (placeholder `--hsm` flag).

### Certificate Management
- **Purpose**: Manages X.509 certificates, including self-signed and CA-signed options.
- **Implementation**: Uses `crypto/x509` for certificate operations.
- **Location**: `internal/certificates/`
- **Features**:
  - Certificate generation, revocation (CRL), and tag-based filtering.
  - CRUD operations with encrypted private key storage.

### Authentication and Authorization
- **Purpose**: Secures access to the application.
- **Implementation**: Uses `github.com/golang-jwt/jwt/v5` for JWT authentication and `github.com/pquerna/otp` for TOTP MFA.
- **Features**:
  - Password hashing with `golang.org/x/crypto/bcrypt`.
  - RBAC enforcement for CLI commands.
  - Audit logging of authentication events.

### Logging
- **Purpose**: Provides operational and audit logging.
- **Implementation**: Uses `github.com/sirupsen/logrus` with JSON output.
- **Location**: `internal/logging/` (assumed) and integrated across packages.
- **Features**:
  - Structured logging with fields (e.g., `user_id`, `operation`).
  - File output (e.g., `test.log`) with planned rotation (`github.com/natefinch/lumberjack`).

## Planned Components
- **RESTful API**: To be implemented with `github.com/gorilla/mux`, offering endpoints like `/v1/secrets`, `/v1/keys`, and `/v1/certificates`.
- **Monitoring**: Planned `/health` endpoint with Prometheus and OpenTelemetry integration.
- **Backup/Recovery**: Encrypted database backups with CLI restore tools.
- **HSM Integration**: Support for FIPS 140-2 Level 3 key storage via PKCS#11.
- **Secrets Management**: CRUD operations for secrets with versioning and export/import.

## Security Considerations
- **Encryption**: All sensitive data (keys, certificates) encrypted with `crypto/aes` (256-bit key).
- **Authentication**: JWT with short-lived tokens and TOTP MFA.
- **RBAC**: Restricts operations to authorized roles (e.g., `crypto_manager`).
- **Logging**: Audit logs stored in `audit_logs` table with integrity checks (planned).
- **Compliance**: Designed to support GDPR, SOC 2, ISO 27001, PCI DSS, and HIPAA (partial implementation).

## Scalability and Availability
- **Database**: SQLite for development; PostgreSQL planned for production with replication and connection pooling.
- **Caching**: Planned with `github.com/patrickmn/go-cache` for frequent queries.
- **Load Balancing**: Supports reverse proxy (e.g., Nginx) for planned multi-region deployment.
- **Uptime**: Designed for 99.99% uptime with health checks (planned).

## Folder Structure
```plaintext
password-manager/
├── cmd/
│   └── password-manager/
│       ├── certificates.go
│       ├── certificates_test.go
│       ├── keys.go
│       └── keys_test.go
├── internal/
│   ├── certificates/
│   │   ├── certificates.go
│   │   └── certificates_test.go
│   ├── db/
│   │   ├── db.go
│   │   └── tags.go
│   ├── keys/
│   │   ├── keys.go
│   │   └── keys_test.go
├── docs/
│   ├── architecture.md
│   ├── cli.md
│   ├── configuration.md
│   ├── security.md
│   └── troubleshooting.md
├── README.md
├── go.mod
└── go.sum
```

This architecture ensures modularity, security, and scalability, with ongoing development to address remaining features like secrets management, API, and monitoring.