<?php

declare(strict_types=1);

namespace Guardian\Tests\Support;

use Guardian\Credentials\CredentialStore;

/**
 * A CredentialStore that is two arrays, for tests that care what the
 * providers and the admin section read and write rather than how a consumer
 * encrypts it.
 */
final class InMemoryCredentialStore implements CredentialStore
{
    /**
     * @param array<string, string> $ids
     * @param array<string, string> $secrets
     */
    public function __construct(
        public array $ids = [],
        public array $secrets = [],
    ) {
    }

    public function getClientId(string $provider): string
    {
        return $this->ids[$provider] ?? '';
    }

    public function setClientId(string $provider, string $value): void
    {
        $this->ids[$provider] = $value;
    }

    public function getClientSecret(string $provider): string
    {
        return $this->secrets[$provider] ?? '';
    }

    public function setClientSecret(string $provider, string $value): void
    {
        $this->secrets[$provider] = $value;
    }
}
