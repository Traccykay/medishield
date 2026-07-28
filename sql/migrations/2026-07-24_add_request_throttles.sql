-- Adds persisted, HMAC-scoped fixed-window request budgets for unauthenticated
-- login, OTP verification, and password-reset actions. It retains no raw IP.
CREATE TABLE IF NOT EXISTS request_throttles (
    scope_hash        CHAR(64) PRIMARY KEY,
    attempt_count     INT UNSIGNED NOT NULL,
    window_started_at DATETIME NOT NULL,
    INDEX idx_throttle_window (window_started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
