<?php

declare(strict_types=1);

namespace MediShield\Audit;

/** Audit before rendering PHI. A failed append stops disclosure, unlike post-write logging. */
final class ReadAudit
{
    public function __construct(private \Closure $append)
    {
    }

    /** Identifiers must come from authorized query results, never raw query parameters. */
    public function records(array $actor, string $module, array $ids, string $action = 'PATIENT_VIEW'): void
    {
        $ids = array_values(array_unique(array_map('strval', $ids)));
        foreach ($ids === [] ? [null] : $ids as $id) {
            $this->event([
                'user_id' => (int) $actor['user_id'],
                'user_role' => (string) $actor['role'],
                'action' => $action,
                'module' => $module,
                'affected_record_id' => $id,
                'status' => 'SUCCESS',
            ]);
        }
    }

    public function event(array $event): void
    {
        if (($this->append)($event) !== true) {
            throw new \RuntimeException('Sensitive read audit unavailable.');
        }
    }
}
