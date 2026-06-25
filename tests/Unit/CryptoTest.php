<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Security\Crypto;
use PHPUnit\Framework\TestCase;

/** Tests for AES-256-GCM authenticated encryption (spec §11). */
final class CryptoTest extends TestCase
{
    private Crypto $crypto;

    protected function setUp(): void
    {
        // 32-byte key (64 hex chars).
        $this->crypto = Crypto::fromHexKey(str_repeat('ab', 32));
    }

    public function testEncryptThenDecryptRoundTrips(): void
    {
        $plain = 'Diagnosis: Type 2 Diabetes Mellitus';
        $cipher = $this->crypto->encrypt($plain);

        self::assertNotSame($plain, $cipher);
        self::assertSame($plain, $this->crypto->decrypt($cipher));
    }

    public function testSamePlaintextProducesDifferentCiphertexts(): void
    {
        // Random IV per encryption means no two ciphertexts match.
        self::assertNotSame(
            $this->crypto->encrypt('same input'),
            $this->crypto->encrypt('same input')
        );
    }

    public function testTamperedCiphertextFailsToDecrypt(): void
    {
        $cipher = $this->crypto->encrypt('sensitive lab result');
        $raw = base64_decode($cipher, true);
        $raw[strlen($raw) - 1] = $raw[strlen($raw) - 1] ^ "\x01"; // flip a bit in the ciphertext
        $tampered = base64_encode($raw);

        $this->expectException(\RuntimeException::class);
        $this->crypto->decrypt($tampered);
    }

    public function testRejectsWrongKeyLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Crypto('too-short-key');
    }

    public function testDecryptRejectsMalformedInput(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->crypto->decrypt('!!!not-base64-or-too-short!!!');
    }
}
