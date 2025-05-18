# Security

This document describes the security features of the Password Manager application, designed to ensure the confidentiality, integrity, and availability of sensitive data (secrets, keys, and certificates).

## Overview
The Password Manager implements a Zero Trust security model with explicit verification, least privilege access, and assume-breach principles. It uses industry-standard cryptographic libraries and secure practices to protect data at rest and in transit.

## Authentication
- **JWT Authentication**: Uses `github.com/golang-jwt/jwt/v5` to issue short-lived (1-hour) JSON Web Tokens for user sessions. Tokens are signed with a secret (`jwt_secret`) stored in the configuration.
- **Multi-Factor Authentication (MFA)**: Implements TOTP MFA with `github.com/pquerna/otp`, requiring a valid TOTP code for all CLI operations except `setup` and `register`.
- **Password Hashing**: User passwords are hashed with `golang.org/x/crypto/bcrypt` using a high cost factor for resistance against brute-force attacks.

## Authorization
- **Role-Based Access Control (RBAC)**: Supports roles (`crypto_manager`, `user`) enforced in CLI commands. Only `crypto_manager` users can perform key and certificate operations.
- **Least Privilege**: Access is restricted to authorized users, with audit logging for all actions.

## Data Encryption
- **At Rest**: Secrets, keys, and certificate private keys are encrypted using `crypto/aes` with a 256-bit master key (`master_key`), stored securely in the configuration.
- **In Transit**: Planned TLS 1.3 support for RESTful API communications (not yet implemented).

## Cryptographic Operations
- **Key Generation**: Uses `crypto/rsa` and `crypto/ecdsa` for RSA and ECDSA keys, with secure random number generation via `crypto/rand`.
- **Certificate Management**: Generates X.509 certificates with `crypto/x509`, supporting self-signed and CA-signed options.
- **HSM Integration**: Planned support for FIPS 140-2 Level 3 hardware security modules via PKCS#11 (placeholder `--hsm` flag).

## Logging and Auditing
- **Operational Logging**: Uses `github.com/sirupsen/logrus` to log errors, operations, and security events in JSON format to a file (e.g., `test.log`).
- **Audit Logging**: Stores user actions (e.g., key generation, certificate revocation) in the `audit_logs` table with fields (`user_id`, `action`, `details`). Planned 90-day retention policy.
- **Security Events**: Logs authentication failures, unauthorized access attempts, and other critical events with `Warn` or `Error` levels.

## Planned Security Features
- **Rate Limiting**: Implement `github.com/ulule/limiter` to restrict authentication and API requests (e.g., 10 requests/minute per user).
- **TLS 1.3**: Secure API communications with `crypto/tls` and strong cipher suites.
- **Input Validation**: Sanitize CLI and API inputs to prevent injection attacks.
- **Compliance**:
  - **GDPR**: Support data encryption, user consent, and data subject access requests.
  - **SOC 2**: Implement audit logging, access controls, and control objectives.
  - **ISO 27001**: Establish an information security management system.
  - **PCI DSS**: Secure handling of payment-related secrets.
  - **HIPAA**: Protect health-related data.
- **Monitoring**: Add Prometheus metrics and Slack alerts for security incidents.

## Best Practices
- **Secure Configuration**: Store `jwt_secret` and `master_key` in a secure vault (e.g., HashiCorp Vault) or restricted environment variables.
- **Regular Updates**: Scan dependencies with `govulncheck` to address vulnerabilities.
- **Access Controls**: Restrict database access to authorized users and use strong credentials.
- **Backup Security**: Encrypt backups with `crypto/aes` and store in a secure location (planned).

For security-related issues, see [troubleshooting.md](troubleshooting.md).