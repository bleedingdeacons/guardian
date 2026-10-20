<?php

declare(strict_types=1);

namespace Guardian\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\Jwt\JwtVerifier;
use Guardian\Support\Logger;
use Guardian\VerifiedIdentity;

/**
 * Verifies a Firebase Authentication ID token a handset obtained natively.
 *
 * The apps sign in with Google through the platform's own account picker —
 * Credential Manager on Android, GoogleSignIn on iOS — hand the Google
 * credential to Firebase Auth, and post the Firebase ID token that comes
 * back. There is no browser leg and no callback, so there is no state and
 * no nonce of ours for the token to carry. This is the check that stands in
 * for them.
 *
 * What it refuses, beyond what {@see JwtVerifier} already does:
 *
 * - <b>Another Firebase project.</b> Issuer and audience are both pinned to
 *   the consumer's own project id. A token from any other project — every
 *   Firebase app on earth can mint one — fails here.
 * - <b>Any sign-in method but the one asked for.</b> `firebase.sign_in_provider`
 *   must match. Firebase also mints tokens for anonymous users, custom tokens
 *   and email links, none of which prove an address.
 * - <b>An unverified or missing email.</b> As for every provider.
 * - <b>A stale sign-in.</b> `auth_time` is when the person actually signed
 *   in, as opposed to `iat`, which Firebase moves forward on every silent
 *   refresh. A handset exchanges its token seconds after the picker closes,
 *   so anything older than {@see MAX_AUTH_AGE_SECONDS} is a token being
 *   reused rather than a sign-in happening.
 * - <b>The same token twice.</b> Remembered in a transient for the rest of
 *   its life. Without a nonce, single use is what stops a captured token
 *   enrolling a second handset.
 */
final class FirebaseIdTokenVerifier
{
    /** Google's key set for every Firebase project's ID tokens. */
    public const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

    /** The value Firebase puts in `firebase.sign_in_provider` for Google. */
    public const GOOGLE = 'google.com';

    private const ISSUER_PREFIX = 'https://securetoken.google.com/';

    /** How long after the picker closes a token may still enrol a handset. */
    private const MAX_AUTH_AGE_SECONDS = 5 * MINUTE_IN_SECONDS;

    /** Matches JwtVerifier: drift between this server and Google. */
    private const CLOCK_SKEW_SECONDS = 60;

    private const SPENT_PREFIX = 'guardian_firebase_spent_';

    /** The `provider` a VerifiedIdentity carries, per Firebase sign-in method. */
    private const PROVIDER_NAMES = [
        self::GOOGLE => 'google',
    ];

    private readonly Logger $logger;

    /**
     * @param string $logChannel The consumer's Sentinel channel.
     */
    public function __construct(
        private readonly JwtVerifier $verifier,
        string $logChannel = 'guardian',
    ) {
        $this->logger = new Logger($logChannel);
    }

    /**
     * @param string $projectId      The consumer's Firebase project id — the
     *                               `project_id` of the service account it
     *                               already holds for FCM.
     * @param string $signInProvider Which `firebase.sign_in_provider` to accept.
     */
    public function verify(
        string $idToken,
        string $projectId,
        string $signInProvider = self::GOOGLE,
    ): ?VerifiedIdentity {
        $provider = self::PROVIDER_NAMES[$signInProvider] ?? null;
        if ($projectId === '' || $provider === null) {
            return null;
        }

        $claims = $this->verifier->verify(
            $idToken,
            self::JWKS_URL,
            self::ISSUER_PREFIX . $projectId,
            $projectId,
        );
        if ($claims === null) {
            return null;
        }

        // Firebase documents sub as the uid: non-empty, at most 128 chars.
        $sub = $claims['sub'] ?? null;
        if (!is_string($sub) || $sub === '' || strlen($sub) > 128) {
            return null;
        }

        $authTime = $claims['auth_time'] ?? null;
        if (!is_numeric($authTime)) {
            return null;
        }
        $now = time();
        if ((int) $authTime > $now + self::CLOCK_SKEW_SECONDS
            || $now - (int) $authTime > self::MAX_AUTH_AGE_SECONDS + self::CLOCK_SKEW_SECONDS) {
            $this->logger->warning('Firebase: sign-in too old to enrol with');
            return null;
        }

        $firebase = $claims['firebase'] ?? null;
        if (!is_array($firebase) || ($firebase['sign_in_provider'] ?? null) !== $signInProvider) {
            return null;
        }

        if (empty($claims['email']) || !is_string($claims['email'])) {
            return null;
        }
        if (($claims['email_verified'] ?? null) !== true) {
            return null;
        }

        // JwtVerifier has already insisted exp is numeric; read here only to
        // know how long to remember the token.
        $exp = $claims['exp'] ?? null;
        if (!is_numeric($exp) || !$this->spend($idToken, (int) $exp)) {
            $this->logger->warning('Firebase: ID token presented twice');
            return null;
        }

        return new VerifiedIdentity(
            strtolower($claims['email']),
            $provider,
            $this->providerSubject($firebase, $signInProvider) ?? $sub,
        );
    }

    /**
     * Mark a token used, answering false if it already was.
     *
     * Kept until the token would have expired anyway, plus the skew the
     * verifier allows, after which the expiry check refuses it on its own.
     */
    private function spend(string $idToken, int $exp): bool
    {
        $key = self::SPENT_PREFIX . hash('sha256', $idToken);
        if (get_transient($key) !== false) {
            return false;
        }

        set_transient($key, 1, max(1, $exp - time() + self::CLOCK_SKEW_SECONDS));

        return true;
    }

    /**
     * The provider's own subject — Google's `sub` — when Firebase passes it on.
     *
     * Preferred over the Firebase uid so that the identity has the same
     * `sub` whichever way the person signed in with Google.
     *
     * @param array<mixed> $firebase
     */
    private function providerSubject(array $firebase, string $signInProvider): ?string
    {
        $identities = $firebase['identities'] ?? null;
        if (!is_array($identities)) {
            return null;
        }

        $ids = $identities[$signInProvider] ?? null;
        $first = is_array($ids) ? ($ids[0] ?? null) : null;

        return is_string($first) && $first !== '' ? $first : null;
    }
}
