<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Mail\LogMailer;
use MediShield\Support\Clock;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for LogMailer — the dev/test mail transport that writes messages to
 * a dump directory instead of using SMTP.
 */
final class LogMailerTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ms_mail_' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        if (is_dir($this->dir)) {
            foreach (glob($this->dir . DIRECTORY_SEPARATOR . '*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($this->dir);
        }
    }

    public function testWritesMessageToDumpDirectory(): void
    {
        $clock  = new Clock(static fn () => new \DateTimeImmutable('2026-02-03 04:05:06', new \DateTimeZone('UTC')));
        $mailer = new LogMailer($this->dir, $clock);

        $ok = $mailer->send('alice@gmail.com', 'Alice', 'Your code', 'Code: ABC123');

        self::assertTrue($ok);
        $files = glob($this->dir . DIRECTORY_SEPARATOR . '*.txt') ?: [];
        self::assertCount(1, $files);

        $body = file_get_contents($files[0]);
        self::assertStringContainsString('alice@gmail.com', $body);
        self::assertStringContainsString('Your code', $body);
        self::assertStringContainsString('Code: ABC123', $body);
    }

    public function testCreatesDirectoryIfMissing(): void
    {
        self::assertDirectoryDoesNotExist($this->dir);

        $clock  = new Clock();
        $mailer = new LogMailer($this->dir, $clock);
        $mailer->send('bob@gmail.com', 'Bob', 'Hi', 'Body');

        self::assertDirectoryExists($this->dir);
    }
}
