<?php

declare(strict_types=1);

namespace Guardian\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * What a device's ID token proves: Google signed these claims for this project.
 *
 * Not that the device is still allowed. See {@see FirebaseDeviceTokenVerifier}.
 */
final class VerifiedDeviceToken
{
    /**
     * @param string               $uid      The Firebase user id.
     * @param int                  $authTime When it signed in, which a silent refresh doesn't move.
     * @param array<string, mixed> $claims   Every claim, custom ones included.
     */
    public function __construct(
        public readonly string $uid,
        public readonly int $authTime,
        public readonly array $claims,
    ) {
    }
}
