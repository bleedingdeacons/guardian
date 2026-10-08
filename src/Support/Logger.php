<?php

declare(strict_types=1);

namespace Guardian\Support;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Logs to a consumer's own Sentinel channel, or nowhere.
 *
 * An instance rather than the suite's static HasLogger trait, because the
 * channel is the consumer's: a JWT refusal during a Reach sign-in belongs in
 * Reach's log, and the same refusal during a Fellowship enrolment belongs in
 * Fellowship's. A static channel would put both under one name that no admin
 * screen shows.
 *
 * Sentinel is optional. Without wp_log() every call is a no-op.
 *
 * @internal
 */
final class Logger
{
    public function __construct(private readonly string $channel)
    {
    }

    /** @param array<string, mixed> $context */
    public function warning(string $message, array $context = []): void
    {
        if (!function_exists('wp_log')) {
            return;
        }

        wp_log($this->channel)->warning($message, $context);
    }
}
