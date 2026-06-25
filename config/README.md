# `config/` — Application Configuration

This folder holds MediShield's configuration.

| File | Committed? | Purpose |
|------|:----------:|---------|
| `config.sample.php` | ✅ Yes | Template config returning a settings array (DB creds, crypto keys, session/auth policy). Safe defaults for XAMPP localhost. |
| `config.php` | ❌ No (git-ignored) | The **real** config used at runtime. Created from the sample by `scripts\setup-db.ps1`. Holds the live encryption + HMAC keys. |

## How it works
Both files simply `return` a PHP associative array. The application loads it via
`includes/bootstrap.php`, which calls `require config/config.php`.

## Setup
You normally don't create `config.php` by hand — `scripts\setup-db.ps1` copies the
sample for you. To do it manually:

```powershell
Copy-Item config\config.sample.php config\config.php
```

Then generate fresh keys and paste them into `config.php`:

```powershell
php -r "echo 'enc='.bin2hex(random_bytes(32)).\"`n\".'hmac='.bin2hex(random_bytes(32));"
```

## Security rules
- **Never commit `config.php`** (enforced by `.gitignore`).
- `encryption_key_hex` and `audit_hmac_key_hex` must be **different** 32-byte keys.
- The sample keys are for development only — replace them anywhere real data lives.
