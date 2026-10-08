<?php

declare(strict_types=1);

namespace Guardian\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\Providers\AppleProvider;
use Guardian\Providers\FacebookProvider;
use Guardian\Providers\GoogleProvider;
use Guardian\Providers\MicrosoftProvider;

/**
 * One provider's block in {@see ProviderCredentialsSection}.
 *
 * The named constructors carry the wording every consumer would otherwise
 * repeat — Entra's "personal accounts only", Facebook's permissions — so a
 * consumer usually only says which providers it offers and where each one
 * comes back to.
 */
final class ProviderField
{
    /**
     * @param string $provider    The provider's name(), lower-case.
     * @param bool   $hasSecret   False for a client-side provider (Apple),
     *                            which has an audience and no secret.
     * @param string $redirectUri Shown with a copy button, for registering with
     *                            the provider. '' shows none.
     */
    public function __construct(
        public readonly string $provider,
        public readonly string $label,
        public readonly bool $hasSecret = true,
        public readonly string $redirectUri = '',
        public readonly string $idLabel = '',
        public readonly string $secretLabel = '',
        public readonly string $help = '',
    ) {
    }

    public static function google(string $redirectUri): self
    {
        return new self(
            GoogleProvider::PROVIDER_NAME,
            __('Google', 'guardian'),
            redirectUri: $redirectUri,
        );
    }

    public static function microsoft(string $redirectUri): self
    {
        return new self(
            MicrosoftProvider::PROVIDER_NAME,
            __('Microsoft', 'guardian'),
            redirectUri: $redirectUri,
            idLabel: __('Application (client) ID', 'guardian'),
            help: __('Register the app in Entra as "Personal Microsoft accounts only". Work and school accounts are refused on purpose: only the consumer tenant guarantees the address in the token is one Microsoft verified.', 'guardian'),
        );
    }

    public static function facebook(string $redirectUri): self
    {
        return new self(
            FacebookProvider::PROVIDER_NAME,
            __('Facebook', 'guardian'),
            redirectUri: $redirectUri,
            idLabel: __('App ID', 'guardian'),
            secretLabel: __('App secret', 'guardian'),
            help: __('Facebook Login must have the "openid" and "email" permissions. Nothing else is requested.', 'guardian'),
        );
    }

    /**
     * @param string $redirectUri Only for a browser sign-in through Apple's JS
     *                            SDK, which redirects to a page; a native app
     *                            signs in on the device and needs none.
     */
    public static function apple(string $redirectUri = '', string $help = ''): self
    {
        return new self(
            AppleProvider::PROVIDER_NAME,
            __('Apple', 'guardian'),
            hasSecret: false,
            redirectUri: $redirectUri,
            idLabel: __('Service ID (audience)', 'guardian'),
            help: $help !== ''
                ? $help
                : __('Apple signs in on the device itself, so no client secret is needed here — only the identifier the ID token is issued for.', 'guardian'),
        );
    }
}
