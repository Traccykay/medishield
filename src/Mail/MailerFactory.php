<?php

declare(strict_types=1);

namespace MediShield\Mail;

use MediShield\Support\BootstrapConfigValidator;
use MediShield\Support\Clock;

/**
 * Constructs only explicitly selected, environment-safe mail transports.
 */
final class MailerFactory
{
    /**
     * @param array<string,mixed> $config
     */
    public static function fromConfig(array $config, Clock $clock): Mailer
    {
        BootstrapConfigValidator::validate($config);

        /** @var array<string,mixed> $mail */
        $mail = $config['mail'];
        $transport = $mail['transport'];

        if ($transport === 'smtp') {
            return new SmtpMailer(
                (array) ($mail['smtp'] ?? []),
                (string) ($mail['from_email'] ?? 'no-reply@medishield.local'),
                (string) ($mail['from_name'] ?? 'MediShield')
            );
        }

        if ($transport === 'log' && ($config['environment'] ?? 'development') !== 'production') {
            return new LogMailer(
                (string) ($mail['dump_dir'] ?? (
                    dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'logs'
                    . DIRECTORY_SEPARATOR . 'mail'
                )),
                $clock
            );
        }

        throw new \RuntimeException(BootstrapConfigValidator::FAILURE_MESSAGE);
    }
}
