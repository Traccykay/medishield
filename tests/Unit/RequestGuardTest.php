<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Subprocess tests for the terminating HTTP request guard.
 */
final class RequestGuardTest extends TestCase
{
    private string $probe;

    protected function setUp(): void
    {
        $this->probe = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Support'
            . DIRECTORY_SEPARATOR . 'request_guard_probe.php';
    }

    /**
     * @return iterable<string,array{string}>
     */
    public static function rejectedTokenProvider(): iterable
    {
        yield 'missing token' => ['missing'];
        yield 'wrong token' => ['wrong'];
        yield 'array token' => ['array'];
    }

    #[DataProvider('rejectedTokenProvider')]
    public function testRequestPostGuard_InvalidToken_RejectsAndAuditsExactlyOnce(string $variant): void
    {
        $result = $this->runProbe($variant, 'authenticated', 'audit-ok');

        self::assertSame(403, $result['status']);
        self::assertFalse($result['mutated']);
        self::assertCount(1, $result['audit_events']);
        self::assertSame([
            'user_id' => 42,
            'user_role' => 'admin',
            'action' => 'CSRF_REJECTED',
            'module' => 'patients',
            'status' => 'BLOCKED',
            'anomaly_flag' => 'SUSPICIOUS',
        ], $result['audit_events'][0]);
    }

    public function testRequestPostGuard_AuditStorageFailure_StillRejectsBeforeMutation(): void
    {
        $result = $this->runProbe('wrong', 'authenticated', 'audit-fails');

        self::assertSame(403, $result['status']);
        self::assertFalse($result['mutated']);
        self::assertCount(1, $result['audit_events']);
    }

    #[DataProvider('attackProvider')]
    public function testRequestPostGuard_AttackPayload_RejectsAndAuditsHighRisk(string $variant, string $action): void
    {
        $result = $this->runProbe($variant, 'authenticated', 'audit-ok');

        self::assertSame(403, $result['status']);
        self::assertFalse($result['mutated']);
        self::assertCount(1, $result['audit_events']);
        self::assertSame($action, $result['audit_events'][0]['action']);
        self::assertSame('BLOCKED', $result['audit_events'][0]['status']);
        self::assertSame('HIGH_RISK', $result['audit_events'][0]['anomaly_flag']);
    }

    /** @return iterable<string,array{string,string}> */
    public static function attackProvider(): iterable
    {
        yield 'SQL injection' => ['sql-attack', 'SQL_INJECTION_ATTEMPT'];
        yield 'cross-site scripting' => ['xss-attack', 'XSS_ATTEMPT'];
    }

    public function testRequestPostGuard_PostOnlyGet_RejectsWithoutCsrfAudit(): void
    {
        $result = $this->runProbe('get', 'authenticated', 'audit-ok');

        self::assertSame(405, $result['status']);
        self::assertFalse($result['mutated']);
        self::assertSame([], $result['audit_events']);
    }

    public function testRequestPostGuard_UnsupportedMethodOnMixedPage_RejectsWithoutCsrfAudit(): void
    {
        $result = $this->runProbe('put', 'authenticated', 'audit-ok');

        self::assertSame(405, $result['status']);
        self::assertFalse($result['mutated']);
        self::assertSame([], $result['audit_events']);
    }

    public function testRequestPostGuard_HeadOnMixedPage_UsesReadPath(): void
    {
        $result = $this->runProbe('head', 'authenticated', 'audit-ok');

        self::assertFalse($result['status']);
        self::assertTrue($result['mutated']);
        self::assertSame([], $result['audit_events']);
    }

    /**
     * @return array{
     *     status:int|false,
     *     audit_events:list<array<string,mixed>>,
     *     mutated:bool
     * }
     */
    private function runProbe(string $variant, string $actor, string $audit): array
    {
        $command = escapeshellarg(PHP_BINARY)
            . ' ' . escapeshellarg($this->probe)
            . ' ' . escapeshellarg($variant)
            . ' ' . escapeshellarg($actor)
            . ' ' . escapeshellarg($audit);
        exec($command, $output, $exitCode);

        self::assertSame(0, $exitCode, implode("\n", $output));
        $text = implode("\n", $output);
        $marker = 'REQUEST_GUARD_PROBE:';
        $position = strrpos($text, $marker);
        self::assertNotFalse($position, $text);

        $decoded = json_decode(substr($text, $position + strlen($marker)), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        return $decoded;
    }
}
