<?php

declare(strict_types=1);

namespace MediShield\Tests\Support;

use MediShield\Mail\Mailer;

/**
 * FakeMailer
 * ----------
 * In-memory {@see Mailer} for tests. Records every message it is asked to send so
 * a test can assert that, e.g., an OTP email went to the right address and capture
 * the body — without any file system or SMTP server.
 */
final class FakeMailer implements Mailer
{
    /** @var list<array{to:string,name:string,subject:string,body:string}> */
    public array $sent = [];

    /** When false, send() returns false to simulate a delivery failure. */
    public bool $shouldSucceed = true;

    public function send(string $toEmail, string $toName, string $subject, string $textBody): bool
    {
        $this->sent[] = [
            'to'      => $toEmail,
            'name'    => $toName,
            'subject' => $subject,
            'body'    => $textBody,
        ];
        return $this->shouldSucceed;
    }

    /** The most recently sent message, or null if none. */
    public function last(): ?array
    {
        return $this->sent === [] ? null : $this->sent[count($this->sent) - 1];
    }
}
