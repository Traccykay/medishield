-- Add encrypted staging columns to the pre-encryption vitals table.
-- scripts/migrate-vitals-encryption.php encrypts existing rows with Crypto and
-- removes the plaintext source columns immediately after this script runs.
ALTER TABLE vitals
    ADD COLUMN IF NOT EXISTS temperature_encrypted TEXT NULL AFTER nurse_id,
    ADD COLUMN IF NOT EXISTS systolic_encrypted TEXT NULL AFTER temperature_encrypted,
    ADD COLUMN IF NOT EXISTS diastolic_encrypted TEXT NULL AFTER systolic_encrypted,
    ADD COLUMN IF NOT EXISTS pulse_encrypted TEXT NULL AFTER diastolic_encrypted,
    ADD COLUMN IF NOT EXISTS weight_encrypted TEXT NULL AFTER pulse_encrypted,
    ADD COLUMN IF NOT EXISTS symptoms_encrypted TEXT NULL AFTER weight_encrypted;
