# RocketVault — How to Use the CLI

RocketVault is a secure place to store passwords, API keys, and other sensitive information. This guide walks you through everything step by step, from first-time setup to everyday use.

> **What is the CLI?**
> A CLI (Command Line Interface) means you type commands into a terminal window instead of clicking buttons. Every example in this guide is a command you can copy, paste, and run.

---

## Before You Start

You need three things:

1. **The RocketVault program** — confirm it works by running:
   ```
   go run main.go --help
   ```
   You should see a list of available commands. If you get an error, ask your administrator to set up the program first.

2. **A config file** — a file called `.rocketvault.yaml` must exist in the same folder you run commands from. Your administrator provides this file.

3. **An authenticator app** — RocketVault uses two-factor authentication (like Google Authenticator or Authy). You will need one of these apps on your phone.

---

## Understanding the Login Code (TOTP)

Almost every command requires **three things to prove who you are**:

- Your **username**
- Your **password**
- A **6-digit code** from your authenticator app (called a TOTP code)

The 6-digit code changes every 30 seconds. When a command asks for `--totp-code 123456`, replace `123456` with the current code shown in your authenticator app at that moment.

**Example of how credentials look in every command:**
```
--username admin --password admin123 --totp-code 123456
```

---

## How to Get Your 6-Digit TOTP Code

The TOTP code comes from an **authenticator app on your phone**. You set it up once — after that, the app always shows your current code.

### Step 1 — Install an authenticator app

Install one of these free apps on your phone:

| App | Android | iPhone |
|-----|---------|--------|
| Google Authenticator | Google Play | App Store |
| Microsoft Authenticator | Google Play | App Store |
| Authy | Google Play | App Store |

Any of these works. Google Authenticator is the most common.

### Step 2 — Find your TOTP secret

Your TOTP secret is shown **once** when your account is first created. It looks like this:

```
TOTP Secret: otpauth://totp/PasswordManager:admin?algorithm=SHA1&digits=6&issuer=PasswordManager&period=30&secret=CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ
```

The part you need is the value after `secret=` at the very end:

```
CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ
```

Copy this and keep it somewhere safe — you will need it in Step 3.

> If you missed it during account creation, ask your administrator to reset your account so a new TOTP secret is generated.

### Step 3 — Add your account to the authenticator app

**Using Google Authenticator:**

1. Open Google Authenticator on your phone.
2. Tap the **+** button (bottom right).
3. Tap **Enter a setup key**.
4. Fill in the form:
   - **Account name**: type anything, e.g. `RocketVault`
   - **Your key**: paste the secret from Step 2 (e.g. `CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ`)
   - **Type of key**: leave as **Time based**
5. Tap **Add**.

The app now shows a 6-digit code that refreshes every 30 seconds. That is your `--totp-code`.

**Using Microsoft Authenticator:**

1. Open the app and tap **+** → **Other account**.
2. Tap **OR ENTER CODE MANUALLY**.
3. Enter an account name (e.g. `RocketVault`) and paste the secret.
4. Tap the checkmark to save.

**Using Authy:**

1. Open Authy and tap **+**.
2. Tap **Enter key manually**.
3. Paste the secret into the **Account Key** field, give it a name, and tap **Add Account**.

### Step 4 — Use the code in a command

Open the authenticator app, find the RocketVault entry, and read the 6-digit number shown. Type it as `--totp-code` in your command:

```
go run main.go secrets list \
  --username admin \
  --password admin123 \
  --totp-code 847291
```

The code changes every 30 seconds. If you see a countdown timer nearly at zero, wait for it to refresh and use the new code — expired codes will be rejected.

> **Tip:** Most apps show a small circular countdown next to the code. If it is almost gone, wait 5 seconds for the next code before running your command.

---

## For Developers — Get TOTP Codes Without Your Phone

If you are running RocketVault locally for development, opening your phone every 30 seconds gets tedious. There is a script included in the project that generates TOTP codes directly in your terminal.

### One-time setup

Find your TOTP secret (the value after `secret=` shown when your account was created), then add it to your shell profile so you never have to type it again.

**For zsh (most Macs)** — open `~/.zshrc` in any text editor and add this line at the bottom:

```
export ROCKETVAULT_TOTP_SECRET="YOUR_SECRET_HERE"
```

**For bash (most Linux)** — open `~/.bashrc` and add the same line.

Replace `YOUR_SECRET_HERE` with your actual secret, for example:

```
export ROCKETVAULT_TOTP_SECRET="CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ"
```

After saving the file, reload your shell:

```
source ~/.zshrc
# or
source ~/.bashrc
```

You only need to do this once. The secret is stored in your shell environment and never typed again.

### Get your current code

Run this from the RocketVault project folder:

```
go run scripts/totp_generator.go
```

Output:

```
RocketVault TOTP — user: admin
─────────────────────────────────
Current code : 933563
Valid for    : 24s  [████████████░░░]
Time         : 14:30:36

Ready to use:
  --totp-code 933563

Full example:
  go run main.go secrets list --username admin --password <password> --totp-code 933563
```

Copy the code next to `--totp-code` and paste it into your command.

The bar `[████████████░░░]` shows how much time is left on the current code. If the bar is nearly empty, wait a few seconds for a fresh code before running your command.

### Watch mode — auto-refresh in a second terminal

If you are running many commands in a row, keep watch mode open in a side terminal. It automatically shows a new code every 30 seconds:

```
go run scripts/totp_generator.go -watch
```

Leave it running. Glance at it whenever you need a code — no phone needed.

### Use a different username

```
go run scripts/totp_generator.go -username=alice
```

### Pass the secret directly without the env var

If you have not set up the env var yet:

```
go run scripts/totp_generator.go -secret="CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ"
```

---

## Step 1 — First-Time Setup (Admins Only)

> Skip this section if someone else already set up the system. Jump to [Step 2 — Log In](#step-2--log-in).

### Start the server

Open a terminal and run:

```
go run main.go serve
```

Leave this terminal running. Open a second terminal for all other commands.

### Create the first admin account

You need the **bootstrap token** from the `.rocketvault.yaml` config file. Look for the line that says `bootstrap_token:` and copy its value.

```
go run main.go users admin \
  --admin-username admin \
  --admin-password admin123 \
  --bootstrap-token YOUR-BOOTSTRAP-TOKEN-HERE
```

Replace `YOUR-BOOTSTRAP-TOKEN-HERE` with the actual token from the config file.

**What you will see:**

```
Admin user admin created successfully with ID: 79ccfd7b-...
TOTP Secret: otpauth://totp/PasswordManager:admin?algorithm=SHA1&digits=6&issuer=PasswordManager&period=30&secret=CZCBJ5TMFMCUULZS4R7ZHV5JZRIFA7TZ
Configure the TOTP secret in your authenticator app for MFA.
```

**Important:** You must now add this account to your authenticator app before you can log in. See [How to Get Your 6-Digit TOTP Code](#how-to-get-your-6-digit-totp-code) for exact steps. The same section applies when any new user account is created.

---

## Step 2 — Log In

Run this to verify everything is working. Get the 6-digit code from your authenticator app first.

```
go run main.go users login \
  --username admin \
  --password admin123 \
  --totp-code 123456
```

If it works, you will see `Login successful` and a long token string. You are ready to use RocketVault.

---

## Managing Secrets

A **secret** is any piece of sensitive information: a password, an API key, a database connection string, etc.

### Save a new secret

```
go run main.go secrets create my-database-password "MySecretValue123" \
  --username admin --password admin123 --totp-code 123456
```

- `my-database-password` — a name you choose so you can find it later
- `"MySecretValue123"` — the actual secret value to store

**With labels (called tags) to help organise:**

```
go run main.go secrets create my-api-key "abc123xyz" \
  --username admin --password admin123 --totp-code 123456 \
  --tags production,api
```

Tags are optional keywords separated by commas. They make it easy to filter later.

### See all your secrets

```
go run main.go secrets list \
  --username admin --password admin123 --totp-code 123456
```

**Show only secrets with a specific tag:**

```
go run main.go secrets list \
  --username admin --password admin123 --totp-code 123456 \
  --tags production
```

### Look up a specific secret

Each secret has a unique ID (shown when you list them — looks like `9b8ead4b-7e88-430a-...`).

```
go run main.go secrets get 9b8ead4b-7e88-430a-982c-bec891eed705 \
  --username admin --password admin123 --totp-code 123456
```

Replace the long ID with the actual ID of the secret you want.

### Change a secret's value

```
go run main.go secrets update 9b8ead4b-7e88-430a-982c-bec891eed705 "NewSecretValue" \
  --username admin --password admin123 --totp-code 123456
```

### Delete a secret

```
go run main.go secrets delete 9b8ead4b-7e88-430a-982c-bec891eed705 \
  --username admin --password admin123 --totp-code 123456
```

### Declare the type of a secret (content type)

You can attach a media type to a secret so that any tool or service that reads it knows how to parse the value. This is optional — if you leave it out, the secret is stored without a declared type.

```
go run main.go secrets create my-pem-cert "-----BEGIN CERTIFICATE-----..." \
  --username admin --password admin123 --totp-code 123456 \
  --content-type application/x-pem-file
```

**Allowed content types:**

| Value | When to use |
|-------|-------------|
| `text/plain` | Plain text passwords, passphrases |
| `application/json` | JSON configuration blobs |
| `application/xml` | XML configuration |
| `application/x-pem-file` | PEM-encoded certificates or keys |
| `application/x-pkcs12` | PKCS#12 / .pfx certificate bundles |
| `application/octet-stream` | Binary data |

**Update the content type on an existing secret:**

```
go run main.go secrets update SECRET-ID-HERE \
  --username admin --password admin123 --totp-code 123456 \
  --content-type application/json
```

The content type is returned whenever you `get` or `list` a secret. RocketVault does not enforce that the value matches the declared type — it is purely informational for consumers.

### Generate a strong random password

Not sure what password to use? Let RocketVault create one for you:

```
go run main.go secrets generate-password \
  --username admin --password admin123 --totp-code 123456
```

**Custom length, no special characters:**

```
go run main.go secrets generate-password \
  --username admin --password admin123 --totp-code 123456 \
  --length 24 --special=false
```

### Back up all secrets to a file

```
go run main.go secrets export \
  --username admin --password admin123 --totp-code 123456 \
  --file ./my-secrets-backup.json
```

The file is encrypted automatically. Keep it somewhere safe.

**Export only secrets with a specific tag:**

```
go run main.go secrets export \
  --username admin --password admin123 --totp-code 123456 \
  --file ./production-secrets.json --tags production
```

### Restore secrets from a backup file

```
go run main.go secrets import \
  --username admin --password admin123 --totp-code 123456 \
  --file ./my-secrets-backup.json
```

---

## Automatic Secret Rotation

Secret rotation means automatically replacing a secret with a new value on a schedule — for example, changing a database password every 30 days. This reduces the risk if a secret is ever compromised.

### Create a rotation schedule (called a policy)

```
go run main.go secrets rotation create \
  --username admin --password admin123 --totp-code 123456 \
  --name "Monthly DB Password" \
  --interval 30 \
  --reminder 7 \
  --auto-rotate
```

- `--interval 30` — rotate every 30 days
- `--reminder 7` — warn you 7 days before rotation is due
- `--auto-rotate` — rotate automatically without manual action

### See all your rotation schedules

```
go run main.go secrets rotation list \
  --username admin --password admin123 --totp-code 123456
```

### Attach a rotation schedule to a secret

```
go run main.go secrets rotation assign \
  --username admin --password admin123 --totp-code 123456 \
  --policy-id POLICY-ID-HERE \
  --secret-id SECRET-ID-HERE
```

Replace `POLICY-ID-HERE` and `SECRET-ID-HERE` with the actual IDs shown when you list policies and secrets.

### Rotate a secret right now (manually)

```
go run main.go secrets rotation rotate \
  --username admin --password admin123 --totp-code 123456 \
  --secret-id SECRET-ID-HERE \
  --policy-id POLICY-ID-HERE
```

### Check what is due for rotation

```
go run main.go secrets rotation status \
  --username admin --password admin123 --totp-code 123456
```

### See the rotation history for a secret

```
go run main.go secrets rotation history \
  --username admin --password admin123 --totp-code 123456 \
  --secret-id SECRET-ID-HERE
```

---

## Managing Cryptographic Keys

> This section is for technical users who need to manage RSA or ECDSA keys. If you are not sure what these are, you likely do not need this section.

Requires admin or secrets_manager role.

### Create a key

**RSA key (most common):**

```
go run main.go keys create \
  --username admin --password admin123 --totp-code 123456 \
  --name my-rsa-key \
  --type RSA \
  --bits 2048
```

**ECDSA key:**

```
go run main.go keys create \
  --username admin --password admin123 --totp-code 123456 \
  --name my-ecdsa-key \
  --type ECDSA \
  --curve P-256
```

### See all keys

```
go run main.go keys list \
  --username admin --password admin123 --totp-code 123456
```

### Replace a key with a new one (rotate)

The old key is revoked and a fresh one is created automatically.

```
go run main.go keys rotate KEY-ID-HERE \
  --username admin --password admin123 --totp-code 123456
```

### Delete a key

```
go run main.go keys delete KEY-ID-HERE \
  --username admin --password admin123 --totp-code 123456
```

### Wrap a key (envelope encryption)

Key wrapping lets you encrypt a data encryption key (DEK) using a vault RSA key (the KEK — key encryption key). This is the standard way to protect keys at rest without exposing the vault key itself.

**Step 1 — Wrap your DEK:**

```
go run main.go keys wrap \
  --username admin --password admin123 --totp-code 123456 \
  --key-id KEY-ID-HERE \
  --key-material BASE64-ENCODED-DEK
```

- `--key-id` — the UUID of the RSA vault key to use as the KEK
- `--key-material` — your DEK encoded in base64 (e.g. a 32-byte AES key)

The command prints the wrapped key as a base64 string. Store it safely — it cannot be read without the vault key.

**Generate a random DEK and wrap it in one step:**

```
DEK=$(openssl rand -base64 32)
go run main.go keys wrap \
  --username admin --password admin123 --totp-code 123456 \
  --key-id KEY-ID-HERE \
  --key-material "$DEK"
```

**Step 2 — Unwrap it when you need the DEK back:**

```
go run main.go keys unwrap \
  --username admin --password admin123 --totp-code 123456 \
  --key-id KEY-ID-HERE \
  --wrapped-key BASE64-WRAPPED-KEY
```

The command prints the original DEK in base64.

> Only the owner of the vault key (or an admin) can wrap or unwrap with it. The algorithm used is RSA-OAEP with SHA-256.

---

## Managing Certificates

> This section is for technical users who need to manage X.509 certificates (used for TLS/HTTPS). Requires admin or certificate_manager role.

### Create a self-signed certificate

```
go run main.go certificate create \
  --username admin --password admin123 --totp-code 123456 \
  --name my-cert \
  --key-id KEY-ID-HERE \
  --validity-days 365
```

`--validity-days 365` means the certificate is valid for one year.

### Create a certificate with automatic renewal

Add `--auto-renew` so RocketVault renews the certificate automatically before it expires. `--renewal-days` controls how many days before expiry the renewal triggers (default: 30).

```
go run main.go certificate create \
  --username admin --password admin123 --totp-code 123456 \
  --name my-tls-cert \
  --key-id KEY-ID-HERE \
  --validity-days 365 \
  --auto-renew \
  --renewal-days 30
```

**How auto-renewal works:**
- Every 24 hours, RocketVault checks all certificates in the vault.
- If a certificate's expiry is within the `--renewal-days` window and `--auto-renew` is on, a new certificate is created automatically with the same validity period.
- If `--auto-renew` is off (the default), RocketVault instead logs a `cert_expiry_warning` entry — you still get notified, but renewal is manual.
- No action is needed from you once auto-renewal is enabled. Check server logs to see renewal activity.

### Create a certificate signed by a CA

```
go run main.go certificate create \
  --username admin --password admin123 --totp-code 123456 \
  --name my-signed-cert \
  --key-id KEY-ID-HERE \
  --validity-days 90 \
  --ca-cert-id CA-CERT-ID-HERE
```

### See all certificates

```
go run main.go certificate list \
  --username admin --password admin123 --totp-code 123456
```

The output includes `expires_at`, `auto_renew`, and `renewal_days` for each certificate.

### Enable or change auto-renewal on an existing certificate

```
go run main.go certificate update CERT-ID-HERE \
  --username admin --password admin123 --totp-code 123456 \
  --auto-renew \
  --renewal-days 14
```

**Disable auto-renewal (switch to warning-only mode):**

```
go run main.go certificate update CERT-ID-HERE \
  --username admin --password admin123 --totp-code 123456 \
  --auto-renew=false
```

### Renew a certificate manually

```
go run main.go certificate renew CERT-ID-HERE \
  --username admin --password admin123 --totp-code 123456 \
  --validity-days 365
```

### Delete a certificate

```
go run main.go certificate delete CERT-ID-HERE \
  --username admin --password admin123 --totp-code 123456
```

---

## Managing Users (Admins Only)

### Add a new user

```
go run main.go users create \
  --username admin --password admin123 --totp-code 123456 \
  --new-username alice \
  --new-password alicepassword \
  --new-role user
```

The output will include a `TOTP Secret` line for the new user. That person must add it to their authenticator app before they can log in. Share the secret with them securely and point them to [How to Get Your 6-Digit TOTP Code](#how-to-get-your-6-digit-totp-code).

Available roles and what they can do:

| Role                  | What they can access                          |
|-----------------------|-----------------------------------------------|
| `admin`               | Everything                                    |
| `secrets_manager`     | Create and manage secrets and keys            |
| `crypto_manager`      | Create and manage cryptographic keys          |
| `certificate_manager` | Create and manage certificates                |
| `user`                | Only their own secrets and account            |

### See all users

```
go run main.go users list \
  --username admin --password admin123 --totp-code 123456
```

### Change a user's password or role

```
go run main.go users update USER-ID-HERE \
  --username admin --password admin123 --totp-code 123456 \
  --new-password newpassword123
```

### Remove a user

```
go run main.go users delete USER-ID-HERE \
  --username admin --password admin123 --totp-code 123456
```

---

## Database Backups

No login required for backup commands.

### Create a backup

```
go run main.go backup create --output ./backups/my-backup.backup
```

The backup is encrypted by default. Store the file somewhere safe.

### See available backups

```
go run main.go backup list --dir ./backups
```

### Restore from a backup

```
go run main.go backup restore --file ./backups/my-backup.backup
```

You will be asked to type `yes` to confirm. This replaces all current data with the backup.

---

## Health Check

Check that the system is running correctly:

```
go run main.go health
```

No login required. Shows memory, database, and performance information.

---

## Common Questions

**Q: What is a UUID / ID?**
It is a long unique identifier that looks like `9b8ead4b-7e88-430a-982c-bec891eed705`. RocketVault assigns one to every secret, user, key, and certificate. Use `list` commands to find them.

**Q: Why does the command keep asking for `--totp-code`?**
The 6-digit code from your authenticator app changes every 30 seconds. You need to enter the current code each time you run a command.

**Q: I got "authentication failed" — what do I do?**
- Check your username and password are correct.
- Make sure the 6-digit code from your app is current (it expires every 30 seconds — try again with a fresh code).
- If your phone clock is wrong (even by a minute), the codes will not match. Check that your phone time is set to automatic/network time.

**Q: I lost or deleted my authenticator app entry — what do I do?**
The TOTP secret is only shown once at account creation and is not stored anywhere you can retrieve it. Ask your administrator to delete your account and create it again. You will get a new TOTP secret to set up.

**Q: I never set up the authenticator app and cannot log in — what do I do?**
Same answer as above — ask your administrator to recreate your account. This time, follow the steps in [How to Get Your 6-Digit TOTP Code](#how-to-get-your-6-digit-totp-code) immediately after the account is created.

**Q: What does the backslash `\` mean at the end of a line?**
It means the command continues on the next line. You can type the whole command on one line if you prefer, just remove the `\` characters.

**Q: I do not have an authenticator app — which should I use?**
Any TOTP-compatible app works: Google Authenticator, Microsoft Authenticator, or Authy are all free and easy to set up on iOS or Android.
