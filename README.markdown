# Password Manager

A production-ready, self-hosted password manager application built in Go, designed to securely store and manage secrets, keys, and certificates. This application provides functionality equivalent to Microsoft Azure Key Vault but without relying on any cloud services.

## Table of Contents

- [Features](#features)
- [Documentation](#documentation)
- [API Endpoints](#api-endpoints)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Running Tests](#running-tests)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features

- Secure storage of secrets, keys, and certificates
- Role-based access control (RBAC) with JWT authentication and TOTP MFA
- CLI interface for managing secrets, keys, and certificates
- Support for RSA and ECDSA cryptographic keys
- X.509 certificate management with self-signed and CA-signed options
- Encrypted database storage (SQLite for development, PostgreSQL for production)
- Comprehensive logging and audit trails
- System health monitoring with memory, CPU, and database metrics
- RESTful API with health check endpoints
- Backup and recovery tools (coming soon)

## Documentation

- [API Specification (OpenAPI/Swagger)](docs/api-specification.yaml) - Complete OpenAPI 3.0 specification
- [API Developer Guide](docs/api-developer-guide.md) - Comprehensive guide for developers
- [Integration Examples](docs/integration-examples.md) - Real-world integration examples
- [API Documentation Validation](validate-api-docs.sh) - Script to validate documentation completeness and syntax
- [CLI Documentation](doc/cli.markdown) - Command-line interface guide
- [Architecture Documentation](doc/architecture.markdown) - System architecture overview
- [Configuration Guide](doc/configuration.markdown) - Configuration options and setup
- [Security Documentation](doc/security.markdown) - Security features and best practices
- [Setup Guide](doc/setup.md) - Installation and setup instructions
- [Troubleshooting Guide](doc/troubleshooting.markdown) - Common issues and solutions
- [Testing Guide](docs/testing-guide.md) - Testing procedures and guidelines

## API Endpoints

The Password Manager provides a comprehensive REST API for managing secrets, keys, certificates, and system health monitoring.

### Health Endpoints

- `GET /api/v1/health` - Comprehensive system health metrics
- `GET /api/v1/health/ready` - Readiness check
- `GET /api/v1/health/live` - Liveness check

### Vault Endpoints

- `GET /api/v1/vault/tenant` - Create new tenant
- `GET /api/v1/vault/tenant/{id}` - Get tenant by ID

### Secrets Endpoints

- `POST /api/v1/secrets/export` - Export secrets (authenticated)
- `POST /api/v1/secrets/import` - Import secrets (authenticated)
- `GET /api/v1/secrets/{id}/versions` - List secret versions (authenticated)
- `GET /api/v1/secrets/{id}/versions/{version}` - Get specific version (authenticated)
- `GET /api/v1/secrets/{id}/versions/latest` - Get latest version (authenticated)

### Authentication

All secrets endpoints require JWT authentication:

```
Authorization: Bearer <your-jwt-token>
```

For detailed API documentation, see the [API Developer Guide](docs/api-developer-guide.md) and [OpenAPI Specification](docs/api-specification.yaml).

## Prerequisites

- Go 1.24 or higher
- SQLite (for development) or PostgreSQL (for production)
- Git

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/snehal1112/password-manager.git
   cd password-manager
   ```

2. Install dependencies:

   ```bash
   go mod tidy
   ```

3. Build the application:

   ```bash
   go build -o password-manager ./cmd/password-manager
   ```

4. Initialize the database (for development):

   ```bash
   ./password-manager setup --db-type sqlite --db-path ./password_manager.db
   ```

   For production (PostgreSQL):

   ```bash
   ./password-manager setup --db-type postgres --db-connection "host=localhost user=postgres password=secret dbname=password_manager sslmode=disable"
   ```

## Usage

### Register a User

```bash
./password-manager register --username admin --password admin123 --role crypto_manager
```

### Generate a Key

```bash
./password-manager keys generate --type rsa --name test-key --bits 2048 --tags prod --username admin --password admin123 --totp-code <valid-totp-code>
```

### Generate a Certificate

```bash
./password-manager certificates generate --key-id 1 --name test-cert --validity-days 365 --tags prod,api --username admin --password admin123 --totp-code <valid-totp-code>
```

### Check System Health

```bash
./password-manager health
```

This command displays comprehensive system health metrics including memory usage, CPU statistics, database connection status, and query performance.

For more usage examples, refer to the [CLI documentation](docs/cli.md).

## Running Tests

To run unit tests:

```bash
go test ./... -v -cover
```

To skip benchmarks:

```bash
go test ./... -v -cover -skip BenchmarkCreateSelfSigned
```

## Deployment

### Using Docker

1. Build the Docker image:

   ```bash
   docker build -t password-manager .
   ```

2. Run the container:
   ```bash
   docker run -d -p 8080:8080 --name password-manager password-manager
   ```

For multi-container deployment with PostgreSQL, use `docker-compose`:

```bash
docker-compose up -d
```

Refer to the [deployment guide](docs/deployment.md) for more details.

## Contributing

Contributions are welcome! Please read the [contributing guidelines](CONTRIBUTING.md) before submitting pull requests.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contact

For questions or feedback, please open an issue on the [GitHub repository](https://github.com/snehal1112/password-manager).
