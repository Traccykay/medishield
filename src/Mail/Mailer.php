<?php

declare(strict_types=1);

namespace MediShield\Mail;

/**
 * Mailer
 * ------
 * Tiny abstraction over "send an email", so the rest of the application
 * (OTP delivery, activation links) does not care HOW mail is delivered.
 *
 * Two implementations exist:
 *   - {@see LogMailer}  : development/testing — writes the message to a file
 *                         under logs/mail/ instead of contacting a real server.
 *                         This lets the OTP/activation flows be demonstrated and
 *                         tested without SMTP credentials or network access.
 *   - {@see SmtpMailer} : production — sends over SMTP using PHPMailer, driven
 *                         entirely by config (no credentials in code).
 *
 * The concrete instance is chosen in bootstrap.php (`ms_mailer()`) from the
 * `mail.transport` config value. Services that send mail accept a Mailer in their
 * constructor so tests can inject a fake.
 */
interface Mailer
{
    /**
     * Deliver a message. Returns true on success.
     *
     * Implementations must never throw on a delivery problem in a way that takes
     * down a page — the caller decides how to react to a false return (the OTP
     * and activation pages log it and show a generic message).
     *
     * @param string $toEmail  Recipient address.
     * @param string $toName   Recipient display name (may be empty).
     * @param string $subject  Subject line.
     * @param string $textBody Plain-text body (always provided).
     */
    public function send(string $toEmail, string $toName, string $subject, string $textBody): bool;
}
