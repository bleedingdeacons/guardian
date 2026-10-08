<?php

declare(strict_types=1);

namespace Guardian\Providers;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\Credentials\CredentialStore;
use Guardian\Jwt\JwtVerifier;
use Guardian\Support\Base64Url;
use Guardian\VerifiedIdentity;

/**
 * Facebook Login, through the OpenID Connect authorisation-code flow with
 * PKCE.
 *
 * Closer to Google than to Apple: a server-side redirect, and a token
 * endpoint that answers an `id_token` verified against Facebook's JWKS. What
 * differs:
 *
 * - <b>PKCE is required.</b> Without a `code_challenge` on the authorise leg
 *   and the matching `code_verifier` on the token leg, the token endpoint
 *   refuses. The client secret is still sent — this is a confidential client
 *   — and PKCE is layered on top.
 * - <b>The version segment is required</b> in both endpoint paths. v21 is a
 *   long-lived Graph API version; moving it is a one-line change here.
 *
 * Scopes are `openid email`, as Google's. `public_profile` is not asked for.
 */
final class FacebookProvider implements OAuthProvider
{
    use Base64Url;
    use ExchangesCode;

    public const PROVIDER_NAME = 'facebook';

    private const ISSUER = 'https://www.facebook.com';
    private const AUTH_URL = 'https://www.facebook.com/v21.0/dialog/oauth';
    private const TOKEN_URL = 'https://graph.facebook.com/v21.0/oauth/access_token';
    private const JWKS_URL = 'https://www.facebook.com/.well-known/oauth/openid/jwks/';

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
        return true;
    }

    public function getAuthorizationUrl(
        string $state,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): string {
        if ($codeVerifier === null || $codeVerifier === '') {
            // Loud rather than silent: a URL built without a challenge would
            // produce a token exchange that fails much later, with an error
            // naming neither this call nor the omission.
            throw new \LogicException('Facebook requires a PKCE code verifier.');
        }

        $params = [
            'client_id'             => $this->credentials->getClientId(self::PROVIDER_NAME),
            'redirect_uri'          => $redirectUri,
            'response_type'         => 'code',
            'scope'                 => 'openid email',
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => $this->codeChallenge($codeVerifier),
            'code_challenge_method' => 'S256',
        ];

        return self::AUTH_URL . '?' . http_build_query($params);
    }

    public function handleCallback(
        string $code,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): ?VerifiedIdentity {
        // Null rather than the exception above: by the callback a browser is
        // waiting and the state is already spent, so this has to become a
        // refusal the consumer can route rather than a 500.
        if ($codeVerifier === null || $codeVerifier === '') {
            return null;
        }

        $idToken = $this->idTokenFrom($this->postToTokenEndpoint(
            self::TOKEN_URL,
            [
                'client_id'     => $this->credentials->getClientId(self::PROVIDER_NAME),
                'client_secret' => $this->credentials->getClientSecret(self::PROVIDER_NAME),
                'redirect_uri'  => $redirectUri,
                'code'          => $code,
                'code_verifier' => $codeVerifier,
            ],
            ['Content-Type' => 'application/x-www-form-urlencoded'],
        ));
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
        throw new \LogicException('Facebook uses the server-side flow; verifyIdToken does not apply.');
    }

    /** The S256 challenge from RFC 7636: base64url of the verifier's SHA-256, unpadded. */
    private function codeChallenge(string $verifier): string
    {
        return $this->base64UrlEncode(hash('sha256', $verifier, true));
    }
}
