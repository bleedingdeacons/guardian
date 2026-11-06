<?php

declare(strict_types=1);

namespace Guardian\Firebase;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\Jwt\JwtVerifier;

/**
 * Verifies the Firebase ID token of a device signed in with a custom token.
 *
 * {@see FirebaseIdTokenVerifier} is for a person signing in: it proves an email
 * address, and accepts a token once, within minutes of the sign-in. This is for
 * something already enrolled, which presents its token on every request until it
 * expires. So what that class requires, this one can't:
 *
 * - <b>No email.</b> A device is a Firebase user with an id and custom claims, and
 *   nothing else.
 * - <b>No limit on how old the sign-in is.</b> A device signs in once and then
 *   refreshes silently for months.
 * - <b>Not single use.</b> The same token is sent until it expires.
 *
 * <b>This says only that Google signed the token for this project.</b> It doesn't
 * say the device is still allowed. Firebase doesn't check revocation inside an ID
 * token, which lasts up to an hour, so the consumer must check its own record of
 * the device, and compare {@see VerifiedDeviceToken::$authTime} with whenever it
 * last cut that device off.
 *
 * A class of its own rather than a method on {@see FirebaseIdTokenVerifier}, because
 * whichever plugin's autoloader asks first supplies Guardian to the others. A new
 * method could be missing from an older copy that won the race. A new class is
 * found in whichever copy has it.
 */
final class FirebaseDeviceTokenVerifier
{
    /** What Firebase puts in `firebase.sign_in_provider` for a custom token. */
    public const CUSTOM = 'custom';

    private const ISSUER_PREFIX = 'https://securetoken.google.com/';

    /** Matches JwtVerifier: drift between this server and Google. */
    private const CLOCK_SKEW_SECONDS = 60;

    public function __construct(private readonly JwtVerifier $verifier)
    {
    }

    /**
     * @param string $projectId The consumer's Firebase project id.
     */
    public function verify(string $idToken, string $projectId): ?VerifiedDeviceToken
    {
        if ($projectId === '' || $idToken === '') {
            return null;
        }

        $claims = $this->verifier->verify(
            $idToken,
            FirebaseIdTokenVerifier::JWKS_URL,
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
        if (!is_numeric($authTime) || (int) $authTime > time() + self::CLOCK_SKEW_SECONDS) {
            return null;
        }

        // Every other sign-in method has its token refused here. A person's Google
        // sign-in in the same project must not pass as a device.
        $firebase = $claims['firebase'] ?? null;
        if (!is_array($firebase) || ($firebase['sign_in_provider'] ?? null) !== self::CUSTOM) {
            return null;
        }

        return new VerifiedDeviceToken($sub, (int) $authTime, $claims);
    }
}
