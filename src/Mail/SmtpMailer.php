<?php

declare(strict_types=1);

namespace MediShield\Mail;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;

/**
 * SmtpMailer
 * ----------
 * Production mail transport. Sends real email over SMTP using the PHPMailer
 * library. Every connection detail (host, port, username, password, encryption,
 * from-address) comes from configuration — there are NO hardcoded credentials,
 * satisfying the rule "do not hardcode real email/app passwords; use config".
 *
 * For local development use {@see LogMailer} instead (selected by config), so the
 * OTP/activation flows work without an email account.
 *
 * This class is a thin adapter and is not unit-tested (it needs a live SMTP
 * server); the security-critical OTP/activation LOGIC is tested separately
 * against the in-memory LogMailer / a fake mailer.
 *
 * @param array{host:string,port:int,username:string,password:string,encryption:string} $smtp
 */
final class SmtpMailer implements Mailer
{
    /**
     * @param array<string,mixed> $smtp      SMTP connection settings from config (mail.smtp).
     * @param string              $fromEmail Envelope/From address (mail.from_email).
     * @param string              $fromName  From display name (mail.from_name).
     */
    public function __construct(
        private array $smtp,
        private string $fromEmail,
        private string $fromName
    ) {
    }

    public function send(string $toEmail, string $toName, string $subject, string $textBody): bool
    {
        $mail = new PHPMailer(true); // true => throw exceptions, which we catch below

        try {
            $mail->isSMTP();
            $mail->Host       = (string) ($this->smtp['host'] ?? '');
            $mail->Port       = (int) ($this->smtp['port'] ?? 587);
            $mail->SMTPAuth   = true;
            $mail->Username   = (string) ($this->smtp['username'] ?? '');
            $mail->Password   = (string) ($this->smtp['password'] ?? '');

            // 'tls' => STARTTLS on 587; 'ssl' => implicit TLS on 465.
            $encryption = (string) ($this->smtp['encryption'] ?? 'tls');
            if ($encryption === 'ssl') {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
            } elseif ($encryption === 'tls') {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            }

            $mail->setFrom($this->fromEmail, $this->fromName);
            $mail->addAddress($toEmail, $toName);
            $mail->Subject = $subject;
            $mail->Body    = $textBody;
            $mail->isHTML(false);

            $mail->send();
            return true;
        } catch (PHPMailerException $e) {
            // Never leak SMTP details to the user; log and let the caller show a
            // generic message.
            error_log('[mail] SMTP send failed: ' . $e->getMessage());
            return false;
        }
    }
}
