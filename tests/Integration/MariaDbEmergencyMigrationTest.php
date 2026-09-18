<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Auth\EmergencyAccess;
use MediShield\Auth\UserRepository;
use MediShield\Patient\PatientRepository;
use MediShield\Security\Crypto;
use MediShield\Support\Clock;
use PHPUnit\Framework\TestCase;

/** Opt-in upgrade/fresh-schema parity proof, restricted to the disposable account-test DB. */
final class MariaDbEmergencyMigrationTest extends TestCase
{
    public function testUpgradeAndFreshSchemaMatchAndGrantWorksOnMariaDb(): void
    {
        if (getenv('MEDISHIELD_MARIADB_EMERGENCY_TEST') !== '1') {
            self::markTestSkipped('Real MariaDB migration test is opt-in.');
        }
        $pdo = new \PDO('mysql:host=127.0.0.1;charset=utf8mb4', 'root', '', [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        ]);
        $reset = static function () use ($pdo): void {
            $pdo->exec('DROP DATABASE IF EXISTS medishield_ui_account_test');
            $pdo->exec('CREATE DATABASE medishield_ui_account_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
            $pdo->exec('USE medishield_ui_account_test');
        };
        $root = dirname(__DIR__, 2);
        $schema = file_get_contents($root . '/sql/schema.sql');
        $migration = file_get_contents($root . '/sql/migrations/2026-09-16_emergency_access.sql');
        $position = strpos($schema, '-- Temporary read-only emergency grants.');
        self::assertNotFalse($position);
        try {
            $reset();
            // The pre-feature schema differs only by the new table appended at this marker.
            $pdo->exec(substr($schema, 0, $position));
            $clock = new Clock();
            $users = new UserRepository($pdo, $clock);
            $doctor = $users->create('Upgrade doctor', 'upgrade@example.test', password_hash('Str0ng!Pass1', PASSWORD_DEFAULT), 'doctor', false);
            $patient = (new PatientRepository($pdo, $clock))->create([
                'user_id' => null, 'patient_number' => 'MSH-1234567890123456', 'full_name' => 'Upgrade patient',
                'date_of_birth' => '1990-01-01', 'gender' => 'female', 'phone' => null, 'address' => null, 'emergency_contact' => null,
            ]);
            $pdo->exec($migration);
            $pdo->exec($migration);
            self::assertSame(1, (int) $pdo->query('SELECT COUNT(*) FROM patients')->fetchColumn());
            $upgradeDdl = $pdo->query('SHOW CREATE TABLE emergency_access_grants')->fetch()['Create Table'];
            $service = new EmergencyAccess($pdo, $clock, new Crypto(str_repeat('a', 32)), str_repeat('b', 64), static fn (array $event): bool => true);
            $actor = ['user_id' => $doctor, 'role' => 'doctor', 'auth_version' => 1];
            $grant = $service->request($actor, $patient, 'Str0ng!Pass1', 'Emergency migration test', 'migration-session', '127.0.0.1');
            self::assertIsInt($grant);
            self::assertTrue($service->canRead($actor, $grant, $patient, 'migration-session'));
            self::assertSame([], $pdo->query('SHOW WARNINGS')->fetchAll());
            $reset();
            $pdo->exec($schema);
            $pdo->exec($migration);
            $freshDdl = $pdo->query('SHOW CREATE TABLE emergency_access_grants')->fetch()['Create Table'];
            self::assertSame($upgradeDdl, $freshDdl);
        } finally {
            $pdo->exec('DROP DATABASE IF EXISTS medishield_ui_account_test');
        }
    }
}
