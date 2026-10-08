<?php

declare(strict_types=1);

namespace Guardian\Tests\Unit;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Guardian\Jwt\JwtVerifier;
use Guardian\Tests\Support\Tokens;

/**
 * The code that decides whether a stranger's claim about their own email
 * address is true.
 *
 * Everything downstream — every member gate, device row and session in the
 * consumers — rests on this refusing a token it should refuse. So the tests
 * forge: each mints a real RS256 token with a real keypair, serves a real
 * JWKS through the fake HTTP transport, and breaks exactly one thing. The
 * positive case exists to prove the negatives fail for the reason claimed
 * rather than because the fixture never worked.
 *
 * Merged from Fellowship's and Reach's suites when the two verifiers became
 * this one.
 */

covers(JwtVerifier::class, \Guardian\Support\Logger::class, \Guardian\Support\Base64Url::class);

const JWT_ISSUER = 'https://appleid.apple.com';
const JWT_JWKS_URL = 'https://appleid.apple.com/auth/keys';
const JWT_AUDIENCE = 'org.aa-bristol.link';
const JWT_KID = 'test-key-1';
const JWT_NONCE = 'the-issued-nonce';

beforeEach(function () {
    FakeWpHttp::reset();
    WpState::reset();

    $this->key = Tokens::keyOrSkip();
});

test('a well formed token verifies', function () {
    serveJwks();

    $claims = verifyJwt(jwt());

    expect($claims)->toBeArray();
    expect($claims['email'])->toBe('member@example.org');
    expect($claims['sub'])->toBe('000123.abc.456');
});

test('the JWKS fetch carries the consumer user agent', function () {
    serveJwks();

    verifyJwt(jwt());

    expect(FakeWpHttp::sentArgs(0)['user-agent'] ?? null)->toBe('Consumer/1.0 (test)');
});

test('an unsigned token is rejected', function () {
    // The textbook forgery: claim no algorithm and hope the verifier takes
    // the payload's word for itself.
    serveJwks();

    $header = Tokens::encode(['alg' => 'none', 'kid' => JWT_KID, 'typ' => 'JWT']);

    expect(verifyJwt($header . '.' . Tokens::encode(jwtClaims()) . '.'))->toBeNull();
});

test('an hmac signed token is rejected', function () {
    // HS256 signed with the public key, which is published and therefore
    // known to everybody. A verifier that dispatched on the header's alg
    // would accept it.
    serveJwks();

    $header = Tokens::encode(['alg' => 'HS256', 'kid' => JWT_KID, 'typ' => 'JWT']);
    $payload = Tokens::encode(jwtClaims());
    $signature = Tokens::base64Url(hash_hmac('sha256', $header . '.' . $payload, Tokens::publicPem($this->key), true));

    expect(verifyJwt($header . '.' . $payload . '.' . $signature))->toBeNull();
});

test('a token signed by the wrong key is rejected', function () {
    serveJwks();

    expect(verifyJwt(Tokens::sign(Tokens::keyOrSkip(), jwtClaims(), JWT_KID)))->toBeNull();
});

test('a tampered payload is rejected', function () {
    serveJwks();

    [$header, , $signature] = explode('.', jwt());
    $forged = Tokens::encode(['email' => 'someone-else@example.org'] + jwtClaims());

    expect(verifyJwt($header . '.' . $forged . '.' . $signature))->toBeNull();
});

test('a token for another audience is rejected', function () {
    // What stops a token minted for somebody else's app being replayed here.
    serveJwks();

    expect(verifyJwt(jwt(['aud' => 'com.example.someone-else'])))->toBeNull();
});

test('an audience list containing ours is accepted', function () {
    serveJwks();

    expect(verifyJwt(jwt(['aud' => ['someone-else', JWT_AUDIENCE]])))->toBeArray();
});

test('a token from another issuer is rejected', function () {
    serveJwks();

    expect(verifyJwt(jwt(['iss' => 'https://accounts.google.com'])))->toBeNull();
});

test('a replayed nonce is rejected', function () {
    // What stops a token minted for this app being used twice.
    serveJwks();

    expect(verifyJwt(jwt(['nonce' => 'a-different-nonce'])))->toBeNull();
});

test('no expected nonce skips the nonce check', function () {
    serveJwks();

    $claims = (new JwtVerifier('Consumer/1.0 (test)'))->verify(
        jwt(remove: ['nonce']),
        JWT_JWKS_URL,
        JWT_ISSUER,
        JWT_AUDIENCE,
    );

    expect($claims)->toBeArray();
});

test('an expired token is rejected', function () {
    serveJwks();

    // Well past the 60-second skew allowance.
    expect(verifyJwt(jwt(['exp' => time() - 3600])))->toBeNull();
});

test('a token expired within the skew allowance is accepted', function () {
    serveJwks();

    expect(verifyJwt(jwt(['exp' => time() - 30])))->toBeArray();
});

test('a token issued in the future is rejected', function () {
    serveJwks();

    expect(verifyJwt(jwt(['iat' => time() + 3600])))->toBeNull();
});

test('a token with no expiry is rejected', function () {
    // Would otherwise verify forever.
    serveJwks();

    expect(verifyJwt(jwt(remove: ['exp'])))->toBeNull();
});

test('a token with no issued at is rejected', function () {
    serveJwks();

    expect(verifyJwt(jwt(remove: ['iat'])))->toBeNull();
});

test('a token with no key id is rejected without a fetch', function () {
    $header = Tokens::encode(['alg' => 'RS256', 'typ' => 'JWT']);

    expect(verifyJwt($header . '.' . Tokens::encode(jwtClaims()) . '.sig'))->toBeNull();
    expect(FakeWpHttp::callCount())->toBe(0);
});

test('an unknown key id is retried once then rejected', function () {
    // A provider that has just rotated leaves the cached JWKS without the new
    // kid. The verifier busts the cache and refetches once rather than failing
    // every sign-in for the cache's whole hour — so two fetches, then refusal.
    serveJwks();
    serveJwks();

    expect(verifyJwt(Tokens::sign($this->key, jwtClaims(), 'a-kid-nobody-published')))->toBeNull();
    expect(FakeWpHttp::callCount())->toBe(2);
});

test('a freshly rotated key is found on the second fetch', function () {
    // The retry has to actually succeed when the key really is new.
    WpState::$transients['guardian_jwks_' . md5(JWT_JWKS_URL)] = [
        'keys' => [Tokens::jwk($this->key, 'a-stale-kid')],
    ];

    serveJwks();

    expect(verifyJwt(jwt()))->toBeArray();
    expect(FakeWpHttp::callCount())->toBe(1);
});

test('a cached key set is not fetched again', function () {
    serveJwks();

    expect(verifyJwt(jwt()))->toBeArray();
    expect(verifyJwt(jwt()))->toBeArray();
    expect(FakeWpHttp::callCount())->toBe(1);
});

test('a malformed token is rejected without a fetch', function () {
    expect(verifyJwt('not-a-jwt'))->toBeNull();
    expect(verifyJwt('only.two'))->toBeNull();
    expect(verifyJwt('!!!.@@@.###'))->toBeNull();
    expect(FakeWpHttp::callCount())->toBe(0, 'A malformed token must not cost a JWKS fetch.');
});

test('a JWKS that answers an error status is rejected', function () {
    FakeWpHttp::pushResponse(500, 'upstream is having a day');

    expect(verifyJwt(jwt()))->toBeNull();
});

test('a JWKS that is not JSON is rejected', function () {
    FakeWpHttp::pushResponse(200, '<html>not json</html>');
    FakeWpHttp::pushResponse(200, '<html>not json</html>');

    expect(verifyJwt(jwt()))->toBeNull();
});

test('an unreachable JWKS is rejected', function () {
    FakeWpHttp::push(new \WP_Error('http_request_failed', 'offline'));
    FakeWpHttp::push(new \WP_Error('http_request_failed', 'offline'));

    expect(verifyJwt(jwt()))->toBeNull();
});

test('a key that is not RSA is rejected', function () {
    FakeWpHttp::pushResponse(200, (string) json_encode(['keys' => [['kty' => 'EC', 'kid' => JWT_KID]]]));

    expect(verifyJwt(jwt()))->toBeNull();
});

test('an empty key id is rejected without a fetch', function () {
    $header = Tokens::encode(['alg' => 'RS256', 'kid' => '', 'typ' => 'JWT']);

    expect(verifyJwt($header . '.' . Tokens::encode(jwtClaims()) . '.sig'))->toBeNull();
    expect(FakeWpHttp::callCount())->toBe(0);
});

test('a key set whose keys are not a list is rejected', function () {
    FakeWpHttp::pushResponse(200, '{"keys":"not-a-list"}');
    FakeWpHttp::pushResponse(200, '{"keys":"not-a-list"}');

    expect(verifyJwt(jwt()))->toBeNull();
});

test('an RSA key missing its modulus is rejected', function () {
    // The DER is built from n and e; with either empty there is no key to
    // build, and handing OpenSSL a half-made one would be worse than refusing.
    $jwks = (string) json_encode(['keys' => [['kid' => JWT_KID, 'kty' => 'RSA', 'n' => '', 'e' => '']]]);
    FakeWpHttp::pushResponse(200, $jwks);
    FakeWpHttp::pushResponse(200, $jwks);

    expect(verifyJwt(jwt()))->toBeNull();
});

/**
 * @param array<string, mixed> $overrides
 * @param list<string>         $remove
 */
function jwt(array $overrides = [], array $remove = []): string
{
    $claims = array_merge(jwtClaims(), $overrides);

    foreach ($remove as $claim) {
        unset($claims[$claim]);
    }

    return Tokens::sign(test()->key, $claims, JWT_KID);
}

/** @return array<string, mixed> */
function jwtClaims(): array
{
    return [
        'iss'            => JWT_ISSUER,
        'aud'            => JWT_AUDIENCE,
        'sub'            => '000123.abc.456',
        'email'          => 'member@example.org',
        'email_verified' => 'true',
        'nonce'          => JWT_NONCE,
        'iat'            => time(),
        'exp'            => time() + 600,
    ];
}

/** @return array<string, mixed>|null */
function verifyJwt(string $jwt): ?array
{
    return (new JwtVerifier('Consumer/1.0 (test)'))->verify($jwt, JWT_JWKS_URL, JWT_ISSUER, JWT_AUDIENCE, JWT_NONCE);
}

function serveJwks(): void
{
    FakeWpHttp::pushResponse(200, Tokens::jwksBody(Tokens::jwk(test()->key, JWT_KID)));
}
