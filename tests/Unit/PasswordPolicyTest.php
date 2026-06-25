<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Security\PasswordPolicy;
use PHPUnit\Framework\TestCase;

/** Tests for the password strength rules (spec §9.1). */
final class PasswordPolicyTest extends TestCase
{
    private PasswordPolicy $policy;

    protected function setUp(): void
    {
        $this->policy = new PasswordPolicy();
    }

    public function testAcceptsAStrongPassword(): void
    {
        self::assertTrue($this->policy->isValid('Str0ng!Pass1', 'jane@example.com'));
        self::assertSame([], $this->policy->validate('Str0ng!Pass1', 'jane@example.com'));
    }

    public function testRejectsTooShort(): void
    {
        $errors = $this->policy->validate('Ab1!xyz', 'a@b.com'); // 7 chars
        self::assertNotEmpty($errors);
    }

    public function testRequiresEachCharacterClass(): void
    {
        self::assertFalse($this->policy->isValid('alllowercase1!', 'a@b.com')); // no uppercase
        self::assertFalse($this->policy->isValid('ALLUPPERCASE1!', 'a@b.com')); // no lowercase
        self::assertFalse($this->policy->isValid('NoDigitsHere!!', 'a@b.com')); // no digit
        self::assertFalse($this->policy->isValid('NoSymbols12345', 'a@b.com')); // no symbol
    }

    public function testRejectsPasswordEqualToEmailLocalPart(): void
    {
        // local part "Administrator1!" used as the password
        self::assertFalse($this->policy->isValid('Administrator1!', 'Administrator1!@hospital.org'));
    }
}
