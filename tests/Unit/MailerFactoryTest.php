<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Mail\LogMailer;
use MediShield\Mail\MailerFactory;
use MediShield\Mail\SmtpMailer;
use MediShield\Support\BootstrapConfigValidator;
use MediShield\Support\Clock;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MailerFactoryTest extends TestCase
{
    public function testFromConfig_DevelopmentLogTransport_ReturnsLogMailer(): void
    {
        $mailer = MailerFactory::fromConfig([
            'environment' => 'development',
            'mail' => [
                'transport' => 'log',
                'dump_dir' => __DIR__,
            ],
        ], new Clock());

        self::assertInstanceOf(LogMailer::class, $mailer);
    }

    public function testFromConfig_ProductionSmtpTransport_ReturnsSmtpMailer(): void
    {
        $mailer = MailerFactory::fromConfig($this->validProductionConfig(), new Clock());

        self::assertInstanceOf(SmtpMailer::class, $mailer);
    }

    #[DataProvider('rejectedTransportProvider')]
    public function testFromConfig_UnsafeOrUnknownTransport_ThrowsInsteadOfFallingBackToLog(
        array $config
    ): void {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage(BootstrapConfigValidator::FAILURE_MESSAGE);

        MailerFactory::fromConfig($config, new Clock());
    }

    /**
     * @return iterable<string, array{0:array<string,mixed>}>
     */
    public static function rejectedTransportProvider(): iterable
    {
        yield 'production log' => [[
            'environment' => 'production',
            'mail' => ['transport' => 'log'],
        ]];
        yield 'development unknown' => [[
            'environment' => 'development',
            'mail' => ['transport' => 'sendmail'],
        ]];
        yield 'development missing' => [[
            'environment' => 'development',
            'mail' => [],
        ]];
    }

    /**
     * @return array<string,mixed>
     */
    private function validProductionConfig(): array
    {
        return [
            'environment' => 'production',
            'mail' => [
                'transport' => 'smtp',
                'from_email' => 'no-reply@example.test',
                'from_name' => 'MediShield',
                'app_base_url' => 'https://medishield.example.test',
                'smtp' => [
                    'host' => 'smtp.example.test',
                    'port' => 587,
                    'encryption' => 'tls',
                    'username' => 'mailer@example.test',
                    'password' => 'not-a-real-secret',
                    'timeout' => 15,
                ],
            ],
        ];
    }
}
