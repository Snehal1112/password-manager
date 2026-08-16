# Setup Instructions

## Prerequisites

- Go 1.24 or later
- SQLite (for development)
- PostgreSQL (for production, optional)

## Project Initialization

1.  Install Go 1.24:

    ```bash
    sudo apt-get install golang-1.24
    export PATH=$PATH:/usr/lib/go-1.24/bin
    ```

2.  Install SoftHSM for local testing:

    ```bash
     sudo apt-get install softhsm2

     softhsm2-util --init-token --slot 0 --label "MyToken" --pin 123456 --so-pin 123456
    ```

3.  Set up your local configuration:

    ```bash
    cp .rocketvault.yaml.example .rocketvault.yaml
    ```

    Then edit `.rocketvault.yaml` and replace both `GENERATE_WITH` placeholders
    (`master_key`, `bootstrap_token`) with real values from:

    ```bash
    openssl rand -base64 32
    ```

    Never commit `.rocketvault.yaml` — it is already in `.gitignore`.
