<?php

declare(strict_types=1);

namespace MediShield\Auth;

use MediShield\Mail\Mailer;
use PDO;

/**
 * Creates the first administrator without ever generating a shared password.
 *
 * The administrator is stored as an inactive pending account and receives the
 * existing expiring, single-use activation link. The database transaction is
 * kept open through delivery so a failed delivery cannot leave an unreachable
 * bootstrap account that blocks a safe retry.
 */
final class InitialAdminProvisioner
{
    public function __construct(
        private PDO $pdo,
        private UserRepository $users,
        private UserService $userService,
        private ActivationService $activations,
        private Mailer $mailer,
        private string $appBaseUrl,
        private int $ttlHours = 48
    ) {
    }

    /**
     * @return array{ok:bool, created:bool, user_id:?int, errors:string[]}
     */
    public function provision(string $fullName, string $email): array
    {
        if ($this->pdo->inTransaction()) {
            throw new \LogicException('Initial administrator provisioning requires its own transaction.');
        }

        $this->beginWriteTransaction();
        try {
            if ($this->users->roleExists('admin', true)) {
                $this->pdo->rollBack();
                return ['ok' => true, 'created' => false, 'user_id' => null, 'errors' => []];
            }

            $created = $this->userService->createPendingUser($fullName, $email, 'admin');
            if (!$created['ok']) {
                $this->pdo->rollBack();
                return [
                    'ok' => false,
                    'created' => false,
                    'user_id' => null,
                    'errors' => $created['errors'],
                ];
            }

            $userId = (int) $created['user_id'];
            $token = $this->activations->issueFor($userId);
            $link = rtrim($this->appBaseUrl, '/') . '/activate.php?token=' . rawurlencode($token);
            $delivered = $this->mailer->send(
                trim($email),
                trim($fullName),
                'Activate your MediShield administrator account',
                "Hello " . trim($fullName) . ",\n\n"
                . "An initial MediShield administrator account has been created for you.\n"
                . "Open this link to choose your password and activate the account:\n\n"
                . $link . "\n\n"
                . "This single-use link expires in " . max(1, $this->ttlHours) . " hours.\n"
            );

            if (!$delivered) {
                $this->pdo->rollBack();
                return [
                    'ok' => false,
                    'created' => false,
                    'user_id' => null,
                    'errors' => ['The activation link could not be delivered.'],
                ];
            }

            $this->pdo->commit();
            return ['ok' => true, 'created' => true, 'user_id' => $userId, 'errors' => []];
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * SQLite needs an immediate transaction for deterministic test locking;
     * MySQL uses a locking role lookup inside a normal transaction.
     */
    private function beginWriteTransaction(): void
    {
        if ($this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
            $this->pdo->exec('BEGIN IMMEDIATE');
            return;
        }

        $this->pdo->beginTransaction();
    }
}
