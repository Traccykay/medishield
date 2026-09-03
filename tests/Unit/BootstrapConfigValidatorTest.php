<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Support\BootstrapConfigValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class BootstrapConfigValidatorTest extends TestCase
{
    public function testValidate_MissingEnvironmentWithExplicitLogTransport_AcceptsDevelopmentDefault(): void
    {
        $config = $this->validProductionConfig();
        unset($config['environment']);
        $config['mail']['transport'] = 'log';

        BootstrapConfigValidator::validate($config);

        self::addToAssertionCount(1);
    }

    public function testValidate_TestEnvironmentWithExplicitLogTransport_RemainsAccepted(): void
    {
        $config = $this->validProductionConfig();
        $config['environment'] = 'test';
        $config['mail']['transport'] = 'log';

        BootstrapConfigValidator::validate($config);

        self::addToAssertionCount(1);
    }

    public function testValidate_ProductionWithCompleteSmtpAndHttpsConfiguration_Accepts(): void
    {
        BootstrapConfigValidator::validate($this->validProductionConfig());

        self::addToAssertionCount(1);
    }

    public function testValidate_ReusedAuditAndThrottleKeys_FailsClosed(): void
    {
        $config = $this->validProductionConfig();
        $config['request_throttle_hmac_key_hex'] = $config['audit_hmac_key_hex'];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage(BootstrapConfigValidator::FAILURE_MESSAGE);
        BootstrapConfigValidator::validate($config);
    }

    public function testValidate_ShortAuditKey_FailsClosed(): void
    {
        $config = $this->validProductionConfig();
        $config['audit_hmac_key_hex'] = str_repeat('ab', 31);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage(BootstrapConfigValidator::FAILURE_MESSAGE);
        BootstrapConfigValidator::validate($config);
    }

    public function testValidate_AnchorPathResolvingInsidePublicRoot_FailsClosed(): void
    {
        $config = $this->validProductionConfig();
        $config['audit_anchor_path'] = dirname(__DIR__, 2)
            . '/var/../public/audit-anchor.jsonl';

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage(BootstrapConfigValidator::FAILURE_MESSAGE);
        BootstrapConfigValidator::validate($config);
    }

    #[DataProvider('unsupportedTransportProvider')]
    public function testValidate_UnsupportedTransportInAnyEnvironment_ThrowsSanitizedDiagnostic(
        array $config
    ): void {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage(BootstrapConfigValidator::FAILURE_MESSAGE);

        BootstrapConfigValidator::validate($config);
    }

    /**
     * @return iterable<string, array{0:array<string,mixed>}>
     */
    public static function unsupportedTransportProvider(): iterable
    {
        yield 'development unknown' => [[
            'environment' => 'development',
            'mail' => ['transport' => 'filesystem-secret-value'],
        ]];
        yield 'test unknown' => [[
            'environment' => 'test',
            'mail' => ['transport' => 'SMTP'],
        ]];
        yield 'development missing' => [[
            'environment' => 'development',
            'mail' => [],
        ]];
        yield 'development non-string' => [[
            'environment' => 'development',
            'mail' => ['transport' => ['log']],
        ]];
    }

    #[DataProvider('unsafeProductionConfigurationProvider')]
    public function testValidate_UnsafeProductionConfiguration_ThrowsSameSanitizedDiagnostic(
        array $config
    ): void {
        try {
            BootstrapConfigValidator::validate($config);
            self::fail('Unsafe production configuration was accepted.');
        } catch (\RuntimeException $exception) {
            self::assertSame(BootstrapConfigValidator::FAILURE_MESSAGE, $exception->getMessage());
            self::assertStringNotContainsString('production-secret', $exception->getMessage());
            self::assertStringNotContainsString('smtp.identity@example.test', $exception->getMessage());
        }
    }

    /**
     * @return iterable<string, array{0:array<string,mixed>}>
     */
    public static function unsafeProductionConfigurationProvider(): iterable
    {
        $base = self::productionConfigFixture();

        $config = $base;
        $config['mail']['transport'] = 'log';
        yield 'log transport' => [$config];

        $config = $base;
        unset($config['mail']['transport']);
        yield 'missing transport' => [$config];

        $config = $base;
        $config['mail']['transport'] = 'sendmail';
        yield 'unknown transport' => [$config];

        $config = $base;
        $config['mail']['app_base_url'] = 'http://medishield.example.test/production-secret';
        yield 'plaintext application URL' => [$config];

        $config = $base;
        $config['mail']['app_base_url'] = 'https://user:production-secret@medishield.example.test';
        yield 'application URL containing credentials' => [$config];

        $config = $base;
        $config['mail']['app_base_url'] = 'https://medishield.example.test/app?token=production-secret';
        yield 'application URL containing query data' => [$config];

        $config = $base;
        $config['mail']['from_name'] = '';
        yield 'missing sender name' => [$config];

        $config = $base;
        unset($config['mail']['smtp']);
        yield 'missing SMTP settings' => [$config];

        foreach ([
            'missing host' => ['host', ''],
            'host containing whitespace' => ['host', 'smtp example.test'],
            'invalid port' => ['port', 0],
            'boolean port' => ['port', true],
            'unknown encryption' => ['encryption', 'none'],
            'missing username' => ['username', ''],
            'missing password' => ['password', ''],
            'whitespace password' => ['password', '   '],
            'invalid timeout' => ['timeout', 0],
            'boolean timeout' => ['timeout', true],
        ] as $label => [$key, $value]) {
            $config = $base;
            $config['mail']['smtp'][$key] = $value;
            yield $label => [$config];
        }

        $config = $base;
        $config['mail']['from_email'] = 'smtp.identity@example.test' . "\r\nBcc: attacker@example.test";
        yield 'invalid from address' => [$config];
    }

    /**
     * @return array<string,mixed>
     */
    private function validProductionConfig(): array
    {
        return self::productionConfigFixture();
    }

    /**
     * @return array<string,mixed>
     */
    private static function productionConfigFixture(): array
    {
        return [
            'environment' => 'production',
            'encryption_key_hex' => str_repeat('11', 32),
            'audit_hmac_key_hex' => str_repeat('22', 32),
            'audit_key_id' => 'audit-primary-2026',
            'audit_anchor_hmac_key_hex' => str_repeat('33', 32),
            'audit_anchor_key_id' => 'anchor-primary-2026',
            'audit_anchor_path' => dirname(__DIR__, 2) . '/var/audit-chain-anchors.jsonl',
            'request_throttle_hmac_key_hex' => str_repeat('44', 32),
            'mail' => [
                'transport' => 'smtp',
                'from_email' => 'smtp.identity@example.test',
                'from_name' => 'MediShield',
                'app_base_url' => 'https://medishield.example.test/app',
                'smtp' => [
                    'host' => 'smtp.example.test',
                    'port' => 587,
                    'encryption' => 'tls',
                    'username' => 'smtp.identity@example.test',
                    'password' => 'production-secret',
                    'timeout' => 15,
                ],
            ],
        ];
    }
}
