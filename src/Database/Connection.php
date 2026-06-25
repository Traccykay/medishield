<?php

declare(strict_types=1);

namespace MediShield\Database;

use PDO;

/**
 * Connection
 * ----------
 * Factory that builds a configured PDO connection to the MediShield MySQL/MariaDB
 * database (the engine XAMPP ships).
 *
 * Centralising PDO construction guarantees every connection uses the same safe
 * defaults:
 *   - ERRMODE_EXCEPTION    : errors throw, so we never silently ignore failures.
 *   - DEFAULT_FETCH_MODE   : associative arrays.
 *   - EMULATE_PREPARES off : real server-side prepared statements (genuine
 *                            protection against SQL injection, correct types).
 *   - time_zone '+00:00'   : the DB session runs in UTC to match the app (§10.1).
 *
 * The data-access classes (e.g. UserRepository) accept a PDO instance rather than
 * calling this factory themselves, so tests can inject an in-memory SQLite PDO.
 */
final class Connection
{
    /**
     * Create a PDO from the application config array (see config/config.sample.php).
     *
     * @param array{db: array{host:string, port?:int, name:string, user:string, pass:string, charset?:string}} $config
     */
    public static function fromConfig(array $config): PDO
    {
        $db = $config['db'];
        return self::mysql(
            $db['host'],
            $db['name'],
            $db['user'],
            $db['pass'],
            (int) ($db['port'] ?? 3306),
            $db['charset'] ?? 'utf8mb4'
        );
    }

    /**
     * Create a PDO connection to a MySQL/MariaDB database with MediShield defaults.
     */
    public static function mysql(
        string $host,
        string $dbName,
        string $user,
        string $pass,
        int $port = 3306,
        string $charset = 'utf8mb4'
    ): PDO {
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $host, $port, $dbName, $charset);

        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);

        // Keep the database session in UTC so timestamps match the application.
        $pdo->exec("SET time_zone = '+00:00'");

        return $pdo;
    }
}
