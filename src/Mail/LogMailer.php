<?php

declare(strict_types=1);

namespace MediShield\Mail;

use MediShield\Support\Clock;

/**
 * LogMailer
 * ---------
 * Development / testing mail transport. Instead of contacting an SMTP server it
 * writes each message to a timestamped `.txt` file in a "mail dump" directory
 * (default: logs/mail/). This means:
 *
 *   - The OTP and account-activation flows can be demonstrated and graded on a
 *     localhost / XAMPP machine with NO email account, SMTP server, or network.
 *   - Integration tests can assert that an email "was sent" by reading the file.
 *
 * It is intentionally NOT used in production (see SmtpMailer). The transport is
 * selected by config (`mail.transport`).
 *
 * Security note: these dump files contain OTP codes and activation links, so the
 * dump directory lives under logs/ (git-ignored) and must not be web-accessible.
 */
final class LogMailer implements Mailer
{
    public function __construct(
        private string $dumpDir,
        private Clock $clock
    ) {
    }

    public function send(string $toEmail, string $toName, string $subject, string $textBody): bool
    {
        if (!is_dir($this->dumpDir)) {
            // 0700: only the owner may read dumped codes/links.
            @mkdir($this->dumpDir, 0700, true);
        }

        $now      = $this->clock->now();
        $filename = $now->format('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.txt';
        $path     = rtrim($this->dumpDir, "/\\") . DIRECTORY_SEPARATOR . $filename;

        $contents = "Date: " . $now->format('Y-m-d H:i:s') . " UTC\n"
            . "To: " . $toName . " <" . $toEmail . ">\n"
            . "Subject: " . $subject . "\n"
            . "----------------------------------------------------------------\n"
            . $textBody . "\n";

        return file_put_contents($path, $contents, LOCK_EX) !== false;
    }
}
