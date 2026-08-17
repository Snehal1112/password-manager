# Runbook: Rotating the RocketVault Master Key

The master key seals, with AES-256-GCM, everything RocketVault stores as a secret:

| Table | Column | Contents |
|---|---|---|
| `secrets` | `value` | Secret values |
| `secret_versions` | `value` | Secret version history |
| `keys` | `value` | Software (non-HSM) RSA/ECDSA private key PEMs, including the JWT signing key |
| `key_versions` | `value` | Key rotation history |
| `certificates` | `private_key` | Certificate private key PEMs, including CA keys |

Changing `master_key` in the configuration **without** running this procedure makes every one of
those rows permanently undecryptable. PKCS#11/HSM keys (`pkcs11:`-prefixed values) are unaffected —
their material never leaves the token. User passwords and OAuth2 client secrets are bcrypt hashes
and are also unaffected.

Rotation is an **offline** operation. Plan a maintenance window.

## 1. Generate the new key

```bash
export NEW_MASTER_KEY="$(openssl rand -base64 32)"
```

Store it in your secret store **now**. If it is lost after step 5, every secret in the vault is
unrecoverable.

Do not name this variable `MASTER_KEY`: Viper gives environment variables precedence over the
configuration file, so an exported `MASTER_KEY` would make the tool's "old key from config" default
resolve to the new key. The command detects this and refuses to run, but naming it clearly avoids
the detour.

## 2. Stop the server

Concurrent writes are detected and abort the run. Stop RocketVault first.

## 3. Back up the database

```bash
cp ./dev-rocketvault.db ./dev-rocketvault.db.pre-rotation   # SQLite
pg_dump "$DATABASE_URL" > rocketvault-pre-rotation.sql      # PostgreSQL
```

This backup plus the old key is your rollback.

## 4. Log in and dry-run

```bash
./rocketvault users login --username admin --password '<password>' --totp-code <code>
./rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run
```

Check the report before continuing:

- Per-table row counts match what you expect for this deployment.
- `ALREADY NEW KEY` is `0` on a first run.
- `SKIPPED (HSM)` is `0` unless the deployment uses PKCS#11.
- No errors.

## 5. Run the rotation

```bash
./rocketvault master-key rotate --new-key-env NEW_MASTER_KEY
```

Confirm at the prompt (or pass `--yes` in scripted maintenance). If the command is interrupted, run
it again with the same keys — rows already on the new key are detected and skipped, and nothing is
double-encrypted.

## 6. Update the configuration

Either set `master_key` in `.rocketvault.yaml` to the value of `$NEW_MASTER_KEY`, or — preferred —
export it as the `MASTER_KEY` environment variable of the server process and remove the key from the
file entirely. The environment value takes precedence over the file.

## 7. Restart and verify

```bash
./rocketvault serve
./rocketvault secrets list --vault default
```

`secrets list` decrypts every secret value in the vault, so a successful read is real proof the
rotation and the configuration agree. Don't use `certificates list` for this check — `ListCertificates`
and `GetCertificate` never touch `private_key` at all, so a successful `certificates list` proves
nothing about the master key (only certificate create-CA-signed and renew operations decrypt a
private key). The server also refuses to start at all on a key that fails validation (wrong length,
the old committed placeholder, or obviously non-random), so a successful start is itself part of the
verification.

## 8. Deal with old backups

Backup files created by `rocketvault backup create` before the rotation are encrypted with the
**old** key and can only be restored with it. Either archive the old key for the backups' retention
period, clearly labelled restore-only and compromised, or take a fresh backup now and delete the
old ones.

## If something goes wrong

| Symptom | Cause | Action |
|---|---|---|
| `value decrypts with neither the old nor the new master key` | Wrong old key | No rows in that table were written. Fix `--old-key-env` and re-run. |
| `row ... changed while the rotation was running` | The server is still running | Stop it and re-run; already-migrated rows are skipped. |
| `the new master key is identical to the old one` | `MASTER_KEY` exported in the shell shadows the config value | Unset it, use a differently named variable. |
| Server logs "could not decrypt stored key, regenerating" after restart | The configuration was updated **before** the rotation ran, on a `jwt.key_source: self_pki` deployment — a new JWT signing key was generated and all sessions were invalidated | Restore the old key in the configuration, restart from step 4, then update the configuration again. |
| Secret reads fail after restart | Configuration and database disagree on the key | Confirm the configuration holds the same key the rotation used; re-run the rotation if it was interrupted before completing. |
