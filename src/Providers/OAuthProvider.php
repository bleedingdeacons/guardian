<?php

declare(strict_types=1);

namespace Guardian\Providers;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\VerifiedIdentity;

/**
 * One identity provider a consumer can sign in through.
 *
 * <b>Two flows, and {@see isServerSide()} says which.</b> Google, Microsoft
 * and Facebook send a browser through {@see getAuthorizationUrl()} and back to
 * a callback with a code, which {@see handleCallback()} exchanges for an ID
 * token — the client secret never leaves the server. Apple is different: the
 * platform's own sheet (or Apple's JS SDK) hands the client a signed ID token
 * directly, and {@see verifyIdToken()} checks it. No browser leg, no code.
 *
 * Calling the wrong half throws rather than returning null. A provider asked
 * for an authorization URL it does not have is a wiring mistake in the
 * consumer, not a failed sign-in, and it should be loud in development rather
 * than quietly answering "no" in production.
 *
 * <b>`$codeVerifier` is optional because only Facebook needs it.</b> It is
 * defaulted rather than split into a second interface: one provider requiring
 * PKCE does not justify splitting the contract every other provider
 * satisfies, and a verifier a provider ignores costs nothing.
 * {@see \Guardian\State\StateStore} carries it between the two legs.
 */
interface OAuthProvider
{
    public function name(): string;

    /** True for the code-exchange flow, false for a client-supplied ID token. */
    public function isServerSide(): bool;

    /** True when this provider's token endpoint requires PKCE. */
    public function requiresPkce(): bool;

    /**
     * The URL the browser is sent to. Server-side flow only.
     *
     * @throws \LogicException On a client-side provider, or on a PKCE
     *                         provider given no verifier.
     */
    public function getAuthorizationUrl(
        string $state,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): string;

    /**
     * Exchange the callback's code, verify the ID token that comes back, and
     * answer the proven identity — or null. Server-side flow only.
     *
     * @throws \LogicException On a client-side provider.
     */
    public function handleCallback(
        string $code,
        string $nonce,
        string $redirectUri,
        ?string $codeVerifier = null
    ): ?VerifiedIdentity;

    /**
     * Verify an ID token the client obtained itself. Client-side flow only.
     *
     * @throws \LogicException On a server-side provider.
     */
    public function verifyIdToken(string $idToken, string $nonce): ?VerifiedIdentity;
}
