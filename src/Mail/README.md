# `src/Mail/` — Email delivery

A tiny abstraction so the rest of MediShield can "send an email" (OTP codes,
account-activation links) without caring about the transport.

| File | Responsibility |
|------|----------------|
| `Mailer.php` | Interface: `send($toEmail, $toName, $subject, $textBody): bool`. |
| `LogMailer.php` | **Dev/test** transport. Writes each message to a file in a dump dir (default `logs/mail/`) instead of using SMTP, so OTP/activation work on a localhost/XAMPP machine with no email account or network. Integration tests assert delivery by reading the file. |
| `SmtpMailer.php` | **Production** transport. Sends over SMTP via PHPMailer. Every credential comes from config (`mail.smtp.*`) — no secrets in code. |

## Choosing a transport

`bootstrap.php` exposes `ms_mailer()`, which builds the transport named by
`mail.transport` in `config/config.php`:

- `'log'` (default) → `LogMailer` (dump to `logs/mail/`).
- `'smtp'` → `SmtpMailer` (real email; set `mail.smtp.host/username/password/...`).

```php
ms_mailer()->send('alice@gmail.com', 'Alice', 'Your MediShield code', 'Code: AB12CD');
```

## Why an interface?

The security-critical OTP and activation **logic** (`src/Auth/OtpService.php`,
`src/Auth/ActivationService.php`) accepts a `Mailer` in its constructor. Tests
inject `tests/Support/FakeMailer.php` (in-memory) to assert what would be sent,
with no file system or SMTP server involved.

## Security notes

- Dump files contain OTP codes / activation links → the dump dir lives under
  `logs/` (git-ignored) and **must not be web-accessible**.
- `SmtpMailer` never logs credentials and returns `false` (logging a generic
  error) on failure, so pages can show a generic message.
