<?php

declare(strict_types=1);

namespace Guardian\Credentials;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Where a consumer keeps the client ids and secrets it registered with each
 * provider.
 *
 * Deliberately owned by the consumer, not by Guardian. Each plugin registers
 * its own redirect URI with each provider, may hold a different client for
 * it, and already encrypts its secrets its own way; one shared store would
 * mean one plugin's Google client could break another's sign-in, and a
 * re-encryption migration to get there.
 *
 * `$provider` is a provider's {@see \Guardian\Providers\OAuthProvider::name()},
 * lower-case. An unset value reads as the empty string, never null.
 */
interface CredentialStore
{
    public function getClientId(string $provider): string;

    public function setClientId(string $provider, string $value): void;

    /** The plaintext secret, or '' when none is stored. */
    public function getClientSecret(string $provider): string;

    /** Store a secret, or clear it with ''. */
    public function setClientSecret(string $provider, string $value): void;
}
