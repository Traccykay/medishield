<?php

declare(strict_types=1);

namespace MediShield\Support;

/** Centralizes explicit acknowledgement for consequential UI actions. */
final class ActionConfirmation
{
    public static function allows(string $action, mixed $confirmed): bool
    {
        return !in_array($action, ['refused', 'revoke'], true) || $confirmed === '1';
    }
}
