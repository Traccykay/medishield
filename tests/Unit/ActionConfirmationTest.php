<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Support\ActionConfirmation;
use PHPUnit\Framework\TestCase;

final class ActionConfirmationTest extends TestCase
{
    public function testConsequentialActionsRequireExactConfirmation(): void
    {
        self::assertFalse(ActionConfirmation::allows('refused', null));
        self::assertFalse(ActionConfirmation::allows('revoke', 'yes'));
        self::assertTrue(ActionConfirmation::allows('revoke', '1'));
    }

    public function testRoutineActionsDoNotRequireConfirmation(): void
    {
        self::assertTrue(ActionConfirmation::allows('dispensed', null));
        self::assertTrue(ActionConfirmation::allows('review', null));
    }
}
