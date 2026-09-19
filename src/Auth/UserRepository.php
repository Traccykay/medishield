<?php

declare(strict_types=1);

namespace MediShield\Auth;

use MediShield\Support\Clock;
use PDO;

/**
 * UserRepository
 * --------------
 * The only place that reads/writes the `users` table. All SQL here uses PDO
 * prepared statements with bound parameters — never string concatenation — which
 * is our primary defence against SQL injection (spec §16).
 *
 * The SQL is deliberately portable (standard INSERT/SELECT/UPDATE, no MySQL-only
 * functions) so the exact same repository works against MySQL/MariaDB in
 * production AND against in-memory SQLite in the integration tests.
 *
 * A {@see Clock} is injected so created_at/updated_at and lockout timestamps are
 * deterministic under test.
 *
 * Returned rows are associative arrays mirroring the `users` columns:
 *   user_id, full_name, email, password_hash, role, status,
 *   failed_login_count, locked_until, must_change_password, auth_version,
 *   created_at, updated_at
 */
final class UserRepository
{
    public function __construct(
        private PDO $pdo,
        private Clock $clock
    ) {
    }

    /** Find a user by email, or null if none. */
    public function findByEmail(string $email): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $email]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** Find a user by primary key, or null if none. */
    public function findById(int $userId, bool $lockForUpdate = false): ?array
    {
        $sql = 'SELECT * FROM users WHERE user_id = :id LIMIT 1';
        if ($lockForUpdate && $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
            $sql .= ' FOR UPDATE';
        }
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':id' => $userId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** True if an account already exists with this email (case-insensitive in MySQL collation). */
    public function emailExists(string $email): bool
    {
        $stmt = $this->pdo->prepare('SELECT 1 FROM users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $email]);
        return $stmt->fetchColumn() !== false;
    }

    /**
     * Check whether a role already exists. Initial-admin provisioning requests a
     * locking read so concurrent MySQL bootstrap attempts cannot both pass.
     */
    public function roleExists(string $role, bool $lockForUpdate = false): bool
    {
        $sql = 'SELECT 1 FROM users WHERE role = :role LIMIT 1';
        if ($lockForUpdate && $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
            $sql .= ' FOR UPDATE';
        }

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':role' => $role]);
        return $stmt->fetchColumn() !== false;
    }

    /**
     * Insert a new user and return its new user_id.
     *
     * @param bool $mustChangePassword When true (default) the user is forced to set
     *                                 a new password at first login. Admin-created
     *                                 accounts always start this way (spec §9.2).
     * @param string $status Initial account status. Defaults to 'active'. Accounts
     *                       created via the activation-link flow start 'inactive'
     *                       and are flipped to 'active' by {@see activate()} once the
     *                       user follows the emailed link and sets a password.
     */
    public function create(
        string $fullName,
        string $email,
        string $passwordHash,
        string $role,
        bool $mustChangePassword = true,
        string $status = 'active'
    ): int {
        $now = $this->clock->nowString();
        $sql = 'INSERT INTO users
                    (full_name, email, password_hash, role, status,
                     failed_login_count, locked_until, must_change_password,
                     created_at, updated_at)
                VALUES
                    (:full_name, :email, :password_hash, :role, :status,
                     0, NULL, :must_change, :created_at, :updated_at)';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':full_name'     => $fullName,
            ':email'         => $email,
            ':password_hash' => $passwordHash,
            ':role'          => $role,
            ':status'        => $status,
            ':must_change'   => $mustChangePassword ? 1 : 0,
            ':created_at'    => $now,
            ':updated_at'    => $now,
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Activate a pending account: set its (freshly chosen) password hash, flip the
     * status to 'active' and clear the must_change_password flag. This is the final
     * step of the account-activation-link flow — the only place a pending account
     * gains a usable password. The caller hashes the password with password_hash().
     */
    public function activatePendingAccount(int $userId, string $passwordHash): bool
    {
        return $this->transactional(function () use ($userId, $passwordHash): bool {
            $stmt = $this->pdo->prepare(
                'UPDATE users
                    SET password_hash = :hash, status = :status,
                        must_change_password = 0,
                        auth_version = auth_version + 1,
                        updated_at = :now
                  WHERE user_id = :id AND status = :inactive_status
                    AND password_hash = :pending_password AND must_change_password = 0'
            );
            $stmt->execute([
                ':hash'   => $passwordHash,
                ':status' => 'active',
                ':now'    => $this->clock->nowString(),
                ':id'     => $userId,
                ':inactive_status' => 'inactive',
                ':pending_password' => UserService::PENDING_ACTIVATION_SENTINEL,
            ]);
            if ($stmt->rowCount() !== 1) {
                return false;
            }
            $this->invalidateOutstandingOtps($userId);
            return true;
        });
    }

    /** Reset credentials only while the account remains active. */
    public function resetActiveAccountPassword(int $userId, string $passwordHash): bool
    {
        return $this->transactional(function () use ($userId, $passwordHash): bool {
            $stmt = $this->pdo->prepare(
                'UPDATE users
                   SET password_hash = :hash, must_change_password = 0,
                       auth_version = auth_version + 1, updated_at = :now
                  WHERE user_id = :id AND status = :active_status'
            );
            $stmt->execute([
                ':hash' => $passwordHash,
                ':now' => $this->clock->nowString(),
                ':id' => $userId,
                ':active_status' => 'active',
            ]);
            if ($stmt->rowCount() !== 1) {
                return false;
            }
            $this->invalidateOutstandingOtps($userId);
            return true;
        });
    }

    /** All users (for the admin user-list page), newest first. */
    public function listAll(): array
    {
        $stmt = $this->pdo->query(
            'SELECT user_id, full_name, email, role, status,
                    failed_login_count, locked_until, must_change_password, created_at
             FROM users ORDER BY user_id DESC'
        );
        return $stmt->fetchAll();
    }

    /**
     * List users whose role is in the provided set. Used by patient assignment and
     * optional patient-login linkage pages. Role values are whitelisted by the
     * caller/service layer, but still bound as parameters for consistency.
     *
     * @param string[] $roles
     * @return array<int,array<string,mixed>>
     */
    public function listByRoles(array $roles, bool $activeOnly = true): array
    {
        if ($roles === []) {
            return [];
        }

        $placeholders = [];
        $params = [];
        foreach (array_values($roles) as $idx => $role) {
            $key = ':role' . $idx;
            $placeholders[] = $key;
            $params[$key] = $role;
        }

        $statusSql = $activeOnly ? ' AND status = :status' : '';
        if ($activeOnly) {
            $params[':status'] = 'active';
        }

        $stmt = $this->pdo->prepare(
            'SELECT user_id, full_name, email, role, status
               FROM users
              WHERE role IN (' . implode(',', $placeholders) . ')' . $statusSql . '
              ORDER BY role, full_name'
        );
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    /**
     * Increment the failed-login counter for a user and return the NEW count.
     * Used by the lockout logic in {@see AuthService}.
     */
    public function incrementFailedLogin(int $userId): int
    {
        $now = $this->clock->nowString();
        $this->pdo->prepare(
            'UPDATE users
                SET failed_login_count = failed_login_count + 1, updated_at = :now
              WHERE user_id = :id'
        )->execute([':now' => $now, ':id' => $userId]);

        $stmt = $this->pdo->prepare('SELECT failed_login_count FROM users WHERE user_id = :id');
        $stmt->execute([':id' => $userId]);
        return (int) $stmt->fetchColumn();
    }

    /** Reset failed-login count to 0 and clear any lock (on successful login). */
    public function resetFailedAndUnlock(int $userId): void
    {
        $this->pdo->prepare(
            'UPDATE users
                SET failed_login_count = 0, locked_until = NULL, updated_at = :now
              WHERE user_id = :id'
        )->execute([':now' => $this->clock->nowString(), ':id' => $userId]);
    }

    /** Lock an account until the given UTC datetime string ('Y-m-d H:i:s'). */
    public function lockUntil(int $userId, string $untilUtc): void
    {
        $this->pdo->prepare(
            'UPDATE users SET locked_until = :until, updated_at = :now WHERE user_id = :id'
        )->execute([
            ':until' => $untilUtc,
            ':now'   => $this->clock->nowString(),
            ':id'    => $userId,
        ]);
    }

    /** Change account status: 'active' or 'inactive' (spec §25). */
    public function setStatus(int $userId, string $status): void
    {
        if (!in_array($status, ['active', 'inactive'], true)) {
            throw new \InvalidArgumentException('Unsupported account status.');
        }

        $this->transactional(function () use ($userId, $status): void {
            if ($status === 'inactive') {
                $this->pdo->prepare(
                    'UPDATE account_activations SET used_at = :now
                       WHERE user_id = :user_id AND used_at IS NULL'
                )->execute([
                    ':now' => $this->clock->nowString(),
                    ':user_id' => $userId,
                ]);
            }

            $mustChangeSql = $status === 'inactive' ? ', must_change_password = 1' : '';
            $this->pdo->prepare(
                'UPDATE users
                    SET status = :status' . $mustChangeSql . ',
                        auth_version = auth_version + 1,
                        updated_at = :now
                  WHERE user_id = :id'
            )->execute([
                ':status' => $status,
                ':now' => $this->clock->nowString(),
                ':id' => $userId,
            ]);
            $this->invalidateOutstandingOtps($userId);
        });
    }

    /**
     * Change the authoritative role and revoke every pending or authenticated
     * session created under the previous privilege set.
     */
    public function setRole(int $userId, string $role): void
    {
        if (!Rbac::isValidRole($role)) {
            throw new \InvalidArgumentException('Unsupported account role.');
        }

        $this->transactional(function () use ($userId, $role): void {
            $this->pdo->prepare(
                'UPDATE users
                    SET role = :role, auth_version = auth_version + 1, updated_at = :now
                  WHERE user_id = :id'
            )->execute([
                ':role' => $role,
                ':now' => $this->clock->nowString(),
                ':id' => $userId,
            ]);
            $this->invalidateOutstandingOtps($userId);
        });
    }

    /**
     * Replace a user's password hash and clear the must_change_password flag.
     * Called after a user chooses a new password (e.g. the forced change at first
     * login). The caller is responsible for hashing with password_hash().
     */
    public function updatePassword(int $userId, string $passwordHash): void
    {
        $this->transactional(function () use ($userId, $passwordHash): void {
            $this->pdo->prepare(
                'UPDATE users
                    SET password_hash = :hash, must_change_password = 0,
                        auth_version = auth_version + 1, updated_at = :now
                  WHERE user_id = :id'
            )->execute([
                ':hash' => $passwordHash,
                ':now'  => $this->clock->nowString(),
                ':id'   => $userId,
            ]);
            $this->invalidateOutstandingOtps($userId);
        });
    }

    private function invalidateOutstandingOtps(int $userId): void
    {
        $this->pdo->prepare(
            'UPDATE otp_codes
                SET used_at = :now
              WHERE user_id = :user_id AND used_at IS NULL'
        )->execute([
            ':now' => $this->clock->nowString(),
            ':user_id' => $userId,
        ]);
    }

    private function transactional(callable $operation): mixed
    {
        $ownsTransaction = !$this->pdo->inTransaction();
        if ($ownsTransaction) {
            $this->pdo->beginTransaction();
        }
        try {
            $result = $operation();
            if ($ownsTransaction) {
                $this->pdo->commit();
            }
            return $result;
        } catch (\Throwable $error) {
            if ($ownsTransaction && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }
}
