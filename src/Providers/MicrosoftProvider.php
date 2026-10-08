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
 * Sign in with Microsoft, through the Entra v2.0 `consumers` tenant.
 *
 * <b>Personal accounts only, and that is a security property.</b> On the
 * `common` endpoint any tenant admin can mint a token asserting any address,
 * which would be an impersonation route straight past every gate a consumer
 * runs. The consumers tenant has one fixed issuer, pinned below rather than
 * parsed from the token, and on a token from it the address is one Microsoft
 * verified the user controls. The matching Entra registration is "Personal
 * Microsoft accounts only".
 *
 * A consumer token carries no `email_verified` claim, so requiring one would
 * refuse every sign-in; the pinned issuer stands in its place. The address is
 * read from `email`, falling back to `preferred_username` when that is itself
 * an address — which is why `profile` is in the scope.
 */
final class MicrosoftProvider implements OAuthProvider
{
    use ExchangesCode;

    public const PROVIDER_NAME = 'microsoft';

    private const AUTH_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize';
    private const TOKEN_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token';
    private const JWKS_URL = 'https://login.microsoftonline.com/consumers/discovery/v2.0/keys';

    /** The MSA consumer tenant — a fixed, well-known constant, not per-tenant. */
    private const ISSUER = 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0';

    private const SCOPE = 'openid email profile';

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
            'response_mode' => 'query',
            'scope'         => self::SCOPE,
            'state'         => $state,
            'nonce'         => $nonce,
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
            'client_id'     => $this->credentials->getClientId(self::PROVIDER_NAME),
            'client_secret' => $this->credentials->getClientSecret(self::PROVIDER_NAME),
            'code'          => $code,
            'redirect_uri'  => $redirectUri,
            'grant_type'    => 'authorization_code',
            'scope'         => self::SCOPE,
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

        $email = $this->emailFrom($claims);
        if ($email === '') {
            return null;
        }

        return new VerifiedIdentity(
            strtolower($email),
            self::PROVIDER_NAME,
            (string) ($claims['sub'] ?? ''),
        );
    }

    public function verifyIdToken(string $idToken, string $nonce): ?VerifiedIdentity
    {
        throw new \LogicException('Microsoft uses the server-side flow; verifyIdToken does not apply.');
    }

    /**
     * `preferred_username` is a display handle by specification, so it is
     * used only when it is itself an address; anything else would match
     * nobody, in a way nothing explains.
     *
     * @param array<string, mixed> $claims
     */
    private function emailFrom(array $claims): string
    {
        if (!empty($claims['email']) && is_string($claims['email'])) {
            return $claims['email'];
        }

        $username = $claims['preferred_username'] ?? null;
        if (is_string($username) && $username !== '' && is_email($username)) {
            return $username;
        }

        return '';
    }
}
