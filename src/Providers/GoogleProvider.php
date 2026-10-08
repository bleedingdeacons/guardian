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
 * Sign in with Google — the OpenID Connect authorisation-code flow.
 *
 * The browser goes to Google, comes back to the consumer's callback with a
 * code, and this exchanges it. The client secret stays on the server; the
 * browser only ever sees a one-time code.
 *
 * The ID token from the token endpoint is the trust anchor: its signature,
 * issuer, audience and nonce are verified before any claim is read, and
 * `email_verified` must be true. An absent claim is refused as firmly as a
 * false one — OIDC requires it, so a token without it is non-compliant or
 * doctored.
 */
final class GoogleProvider implements OAuthProvider
{
    use ExchangesCode;

    public const PROVIDER_NAME = 'google';

    private const ISSUER = 'https://accounts.google.com';
    private const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
    private const TOKEN_URL = 'https://oauth2.googleapis.com/token';
    private const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

    public function __construct(
        private readonly CredentialStore $credentials,
        private readonly JwtVerifier $verifier,
        private readonly string $userAgent,
    ) {
    }

    public function name(): string
    {
        return self::PROVIDER_NAME;
    }

    public function isServerSide(): bool
    {
        return true;
    }

    public function requiresPkce(): bool
    {
        return false;
    }

    public function getAuthorizationUrl(
        string $state,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): string {
        $params = [
            'client_id'     => $this->credentials->getClientId(self::PROVIDER_NAME),
            'redirect_uri'  => $redirectUri,
            'response_type' => 'code',
            // Only what a sign-in needs. Nothing in the suite reads a mailbox,
            // a profile or a contact list, and asking for scopes it does not
            // use is a worse consent screen and a larger token to lose.
            'scope'         => 'openid email',
            'state'         => $state,
            'nonce'         => $nonce,
            // A device is often shared or has several accounts on it, and
            // silently reusing whichever Google saw last would sign the wrong
            // person in.
            'prompt'        => 'select_account',
        ];

        return self::AUTH_URL . '?' . http_build_query($params);
    }

    public function handleCallback(
        string $code,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): ?VerifiedIdentity {
        $idToken = $this->idTokenFrom($this->postToTokenEndpoint(self::TOKEN_URL, [
            'code'          => $code,
            'client_id'     => $this->credentials->getClientId(self::PROVIDER_NAME),
            'client_secret' => $this->credentials->getClientSecret(self::PROVIDER_NAME),
            'redirect_uri'  => $redirectUri,
            'grant_type'    => 'authorization_code',
        ]));
        if ($idToken === null) {
            return null;
        }

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

        if (($claims['email_verified'] ?? null) !== true) {
            return null;
        }

        return new VerifiedIdentity(
            strtolower($claims['email']),
            self::PROVIDER_NAME,
            (string) ($claims['sub'] ?? ''),
        );
    }

    public function verifyIdToken(string $idToken, string $nonce): ?VerifiedIdentity
    {
        throw new \LogicException('Google uses the server-side flow; verifyIdToken does not apply.');
    }
}
