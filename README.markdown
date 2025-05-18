# Password Manager

A production-ready, self-hosted password manager application built in Go, designed to securely store and manage secrets, keys, and certificates. This application provides functionality equivalent to Microsoft Azure Key Vault but without relying on any cloud services.

## Table of Contents
- [Features](#features)
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
- Backup and recovery tools (coming soon)
- RESTful API (coming soon)

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