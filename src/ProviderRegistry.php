<?php

declare(strict_types=1);

namespace Guardian;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\Providers\OAuthProvider;

/**
 * The providers a consumer will accept a sign-in from.
 *
 * Registration is the permission model: a provider that is not in here is
 * not merely unconfigured, it is unreachable. A controller answers an unknown
 * name with a 400 and there is no second check downstream, so offering a new
 * provider is a wiring change and nothing else.
 *
 * <b>Not final, on purpose and temporarily.</b> Fellowship keeps its old
 * `Fellowship\Auth\ProviderRegistry` as an empty subclass while Freedom's test
 * harness still builds one under that name; once Freedom has moved over, the
 * subclass goes. Nothing else should extend this.
 */
class ProviderRegistry
{
    /** @var array<string, OAuthProvider> */
    private array $providers = [];

    public function register(OAuthProvider $provider): void
    {
        $this->providers[strtolower($provider->name())] = $provider;
    }

    public function get(string $name): ?OAuthProvider
    {
        return $this->providers[strtolower($name)] ?? null;
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->providers);
    }
}
