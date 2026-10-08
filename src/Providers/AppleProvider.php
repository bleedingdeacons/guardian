<?php

declare(strict_types=1);

namespace Guardian\Providers;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\Credentials\CredentialStore;
use Guardian\Jwt\JwtVerifier;
use Guardian\VerifiedIdentity;

/**
 * Sign in with Apple — the client-side flow.
 *
 * The client obtains a signed ID token itself — iOS from its system sheet, a
 * browser from Apple's JS SDK — and posts it to the consumer, which verifies
 * it here against Apple's JWKS. No browser leg, no authorization code, and no
 * client secret, which spares the server-side flow's six-monthly re-minting of
 * a JWT client secret from a downloaded .p8 key.
 *
 * Apple has shipped `email_verified` as both a JSON boolean and the string
 * "true" depending on the token surface, so both are accepted. An absent
 * claim is refused.
 *
 * <b>Private relay addresses are accepted.</b> An `@privaterelay.appleid.com`
 * forwarding address is a real, verified Apple address. It will simply match
 * nobody a consumer knows, and that consumer's own gate is the place to say
 * so, with the context to explain it.
 */
final class AppleProvider implements OAuthProvider
{
    public const PROVIDER_NAME = 'apple';

    private const ISSUER = 'https://appleid.apple.com';
    private const JWKS_URL = 'https://appleid.apple.com/auth/keys';

    public function __construct(
        private readonly CredentialStore $credentials,
        private readonly JwtVerifier $verifier,
    ) {
    }

    public function name(): string
    {
        return self::PROVIDER_NAME;
    }

    public function isServerSide(): bool
    {
        return false;
    }

    public function requiresPkce(): bool
    {
        // Moot: PKCE protects an authorization code in transit, and this
        // flow never mints one.
        return false;
    }

    public function getAuthorizationUrl(
        string $state,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): string {
        throw new \LogicException('Apple uses the client-side flow; getAuthorizationUrl does not apply.');
    }

    public function handleCallback(
        string $code,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): ?VerifiedIdentity {
        throw new \LogicException('Apple uses the client-side flow; handleCallback does not apply.');
    }

    public function verifyIdToken(string $idToken, string $nonce): ?VerifiedIdentity
    {
        $claims = $this->verifier->verify(
            $idToken,
            self::JWKS_URL,
            self::ISSUER,
            $this->credentials->getClientId(self::PROVIDER_NAME),
            $nonce,
        );

        if ($claims === null) {
            return null;
        }

        if (empty($claims['email']) || !is_string($claims['email'])) {
            return null;
        }

        $verified = $claims['email_verified'] ?? null;
        if ($verified !== true && $verified !== 'true') {
            return null;
        }

        return new VerifiedIdentity(
            strtolower($claims['email']),
            self::PROVIDER_NAME,
            (string) ($claims['sub'] ?? ''),
        );
    }
}
