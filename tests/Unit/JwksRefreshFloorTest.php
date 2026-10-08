<?php

declare(strict_types=1);

namespace Guardian\Tests\Unit;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Guardian\Jwt\JwtVerifier;
use Guardian\Tests\Support\Tokens;

/**
 * The floor under the verifier's cache-busting JWKS refetch.
 *
 * An unknown `kid` makes verify() retry with the cache busted, and that path
 * is reachable by anyone: a client-side flow accepts any ID token, and reading
 * its header costs nothing. Before the floor, a token with a random kid forced
 * an outbound HTTPS call on every request.
 *
 * Deliberately built without openssl_pkey_new(). These assertions are about
 * how many times the key set is fetched, not about signatures — the kid lookup
 * happens before any signature check — so they run even where the RSA tests
 * skip for want of an openssl.cnf.
 */

covers(JwtVerifier::class);

const FLOOR_JWKS_URL = 'https://example.test/jwks.json';

beforeEach(function () {
    FakeWpHttp::reset();
    WpState::reset();
});

test('an unknown kid does not refetch the key set on every request', function () {
    serveKeySetWithout(40);

    $verifier = new JwtVerifier('Consumer/1.0 (test)');
    for ($i = 0; $i < 20; $i++) {
        $verifier->verify(tokenWithKid('bogus-kid-' . $i), FLOOR_JWKS_URL, 'https://issuer.test', 'client-abc');
    }

    // One fetch to populate the cache, and at most one cache-busting refetch
    // within the floor. Without the floor this was two per request, so 40.
    expect(FakeWpHttp::callCount())->toBeLessThanOrEqual(2);
});

test('the first unknown kid still gets one refetch', function () {
    // The floor throttles the refetch; it must not remove it. A genuine key
    // rotation is exactly this case, so the first miss has to reach the
    // provider.
    serveKeySetWithout(2);

    (new JwtVerifier('Consumer/1.0 (test)'))->verify(tokenWithKid('rotated-in'), FLOOR_JWKS_URL, 'https://issuer.test', 'client-abc');

    expect(FakeWpHttp::callCount())->toBe(2);
});

test('the floor is per key set not global', function () {
    // One provider's misses must not deny another provider its refetch.
    $other = 'https://other.test/jwks.json';
    serveKeySetWithout(4);

    $verifier = new JwtVerifier('Consumer/1.0 (test)');
    $verifier->verify(tokenWithKid('x'), FLOOR_JWKS_URL, 'https://issuer.test', 'client-abc');
    $verifier->verify(tokenWithKid('x'), $other, 'https://issuer.test', 'client-abc');

    $fetched = array_map(static fn (array $sent): string => $sent['url'], FakeWpHttp::$sent);

    expect(array_count_values($fetched))->toBe([FLOOR_JWKS_URL => 2, $other => 2]);
});

test('the floor is shared by every verifier instance', function () {
    // Each consumer builds its own verifier. The floor lives in a transient,
    // so a second instance — another plugin on the same request, or the next
    // request — is held by the same floor.
    serveKeySetWithout(4);

    (new JwtVerifier('A/1.0'))->verify(tokenWithKid('one'), FLOOR_JWKS_URL, 'https://issuer.test', 'client-abc');
    (new JwtVerifier('B/1.0', 'another-channel'))->verify(tokenWithKid('two'), FLOOR_JWKS_URL, 'https://issuer.test', 'client-abc');

    expect(FakeWpHttp::callCount())->toBe(2);
});

/**
 * A structurally valid RS256 token with the given kid and a nonsense
 * signature — the kid lookup comes before any signature check.
 */
function tokenWithKid(string $kid): string
{
    return Tokens::encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid])
        . '.' . Tokens::encode(['iss' => 'https://issuer.test', 'aud' => 'client-abc', 'iat' => time(), 'exp' => time() + 3600])
        . '.' . Tokens::base64Url('not-a-real-signature');
}

/** Queue a key set that never contains the kid under test, so every lookup misses. */
function serveKeySetWithout(int $times): void
{
    for ($i = 0; $i < $times; $i++) {
        FakeWpHttp::pushResponse(200, Tokens::jwksBody([
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => 'a-kid-that-is-never-asked-for',
            'n'   => 'AQAB',
            'e'   => 'AQAB',
        ]));
    }
}
