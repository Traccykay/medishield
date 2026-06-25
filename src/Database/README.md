# `src/Database/` — Database Connectivity

| Class | Responsibility |
|-------|----------------|
| `Connection` | Factory that builds a PDO connection to MySQL/MariaDB with MediShield's safe defaults (exceptions on error, real prepared statements, UTC session time). |

## Why a factory?
Every connection should share the same hardened settings. Data-access classes
(e.g. `Auth\UserRepository`) take a `PDO` as a constructor argument instead of
building their own — this is dependency injection, and it lets the test suite hand
them an **in-memory SQLite** PDO so integration tests run with no MySQL server.

```php
$pdo = \MediShield\Database\Connection::fromConfig($config);
$users = new \MediShield\Auth\UserRepository($pdo, new \MediShield\Support\Clock());
```
