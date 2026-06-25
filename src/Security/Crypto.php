<?php

declare(strict_types=1);

namespace MediShield\Security;

/**
 * Crypto
 * ------
 * Authenticated encryption for sensitive clinical fields (diagnosis, treatment
 * notes, lab results, medication, dosage, instructions) — spec §11.
 *
 * Algorithm: AES-256-GCM.
 *   - GCM is *authenticated*: tampering with the stored ciphertext makes
 *     decryption fail (the auth tag won't verify), which is exactly the integrity
 *     property a medical record needs. (This is why we use GCM, not CBC.)
 *   - A fresh random 12-byte IV is generated per encryption, so encrypting the
 *     same plaintext twice yields different ciphertexts.
 *
 * Stored format (a single TEXT column):
 *     base64( iv (12 bytes) || tag (16 bytes) || ciphertext )
 *
 * The key is 32 raw bytes. In the app it comes from config (`encryption_key_hex`).
 */
final class Crypto
{
    private const CIPHER  = 'aes-256-gcm';
    private const IV_LEN  = 12;
    private const TAG_LEN = 16;
    private const KEY_LEN = 32;

    /**
     * @param string $key 32 raw bytes of key material.
     * @throws \InvalidArgumentException if the key is the wrong length.
     */
    public function __construct(private string $key)
    {
        if (strlen($this->key) !== self::KEY_LEN) {
            throw new \InvalidArgumentException(
                'Encryption key must be exactly ' . self::KEY_LEN . ' bytes.'
            );
        }
    }

    /**
     * Build a Crypto instance from a 64-character hex key string (as stored in config).
     */
    public static function fromHexKey(string $hex): self
    {
        $raw = @hex2bin($hex);
        if ($raw === false) {
            throw new \InvalidArgumentException('Encryption key hex is invalid.');
        }
        return new self($raw);
    }

    /**
     * Encrypt a plaintext string.
     *
     * @return string base64( iv || tag || ciphertext )
     */
    public function encrypt(string $plaintext): string
    {
        $iv  = random_bytes(self::IV_LEN);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LEN
        );
        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed.');
        }
        return base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * Decrypt a value produced by {@see encrypt()}.
     *
     * @throws \RuntimeException if the data is malformed or the auth tag fails
     *                           (i.e. the ciphertext was tampered with).
     */
    public function decrypt(string $stored): string
    {
        $raw = base64_decode($stored, true);
        if ($raw === false || strlen($raw) < self::IV_LEN + self::TAG_LEN) {
            throw new \RuntimeException('Invalid ciphertext.');
        }
        $iv         = substr($raw, 0, self::IV_LEN);
        $tag        = substr($raw, self::IV_LEN, self::TAG_LEN);
        $ciphertext = substr($raw, self::IV_LEN + self::TAG_LEN);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        if ($plaintext === false) {
            throw new \RuntimeException('Decryption/integrity failure.');
        }
        return $plaintext;
    }
}
