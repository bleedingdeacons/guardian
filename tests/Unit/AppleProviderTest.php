<?php

declare(strict_types=1);

namespace Guardian\Tests\Unit;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Guardian\Jwt\JwtVerifier;
use Guardian\Providers\AppleProvider;
use Guardian\Tests\Support\InMemoryCredentialStore;
use Guardian\Tests\Support\Tokens;
use Guardian\VerifiedIdentity;

/**
 * Sign in with Apple, from the token inwards.
 *
 * <b>The provider is thin on purpose and that is why it needs testing.</b>
 * Everything hard lives in the verifier, so what is left here is a short list
 * of decisions about the claims — and a short list of decisions is where a
 * wrong one hides best. Accepting an unverified address, or forgetting to
 * lower-case one, would produce a gate that matches the wrong person or
 * nobody, in a way that looks like a data problem rather than a code one.
 *
 * A real verifier rather than a stub, because the two are only correct
 * together.
 */

covers(AppleProvider::class);

const APPLE_AUDIENCE = 'org.aa-bristol.link';
const APPLE_NONCE = 'the-issued-nonce';
const APPLE_KID = 'apple-key-1';

beforeEach(function () {
    FakeWpHttp::reset();
    WpState::reset();

    $this->key = Tokens::keyOrSkip();
});

test('a valid token yields the verified identity', function () {
    $identity = appleVerify(appleToken());

    expect($identity?->email)->toBe('member@example.org');
    expect($identity?->provider)->toBe('apple');
    expect($identity?->sub)->toBe('000123.abc.456');
});

test('the token is checked against Apple and the configured audience', function () {
    appleVerify(appleToken());

    expect(FakeWpHttp::sentUrl(0))->toBe('https://appleid.apple.com/auth/keys');
});

test('the email is lower cased', function () {
    expect(appleVerify(appleToken(['email' => 'Member@Example.ORG']))?->email)->toBe('member@example.org');
});

test('an unverified email is refused', function () {
    expect(appleVerify(appleToken(['email_verified' => 'false'])))->toBeNull();
    expect(appleVerify(appleToken(['email_verified' => false])))->toBeNull();
});

test('a missing email verified claim is refused', function () {
    expect(appleVerify(appleToken(remove: ['email_verified'])))->toBeNull();
});

test('a boolean true is accepted as well as the string', function () {
    // Apple has shipped this claim as both, depending on the token surface.
    expect(appleVerify(appleToken(['email_verified' => true])))->not->toBeNull();
});

test('a token with no email is refused', function () {
    expect(appleVerify(appleToken(remove: ['email'])))->toBeNull();
    expect(appleVerify(appleToken(['email' => ''])))->toBeNull();
});

test('a private relay address is accepted here', function () {
    // A forwarding address is a real, verified Apple address. The consumer's
    // own gate is where it stops, with the context to explain why.
    expect(appleVerify(appleToken(['email' => 'xyz@privaterelay.appleid.com']))?->email)
        ->toBe('xyz@privaterelay.appleid.com');
});

test('a token for another audience is refused', function () {
    expect(appleVerify(appleToken(['aud' => 'com.example.someone-else'])))->toBeNull();
});

test('a token from another issuer is refused', function () {
    expect(appleVerify(appleToken(['iss' => 'https://accounts.google.com'])))->toBeNull();
});

test('Apple is client side and needs no PKCE', function () {
    expect(appleProvider()->isServerSide())->toBeFalse();
    expect(appleProvider()->requiresPkce())->toBeFalse();
    expect(appleProvider()->name())->toBe('apple');
});

test('building an authorization URL is refused outright', function () {
    appleProvider()->getAuthorizationUrl('state', 'nonce', 'https://example.org/callback');
})->throws(\LogicException::class);

test('handling a callback is refused outright', function () {
    // Apple has no browser leg. Reaching this would mean a client-side
    // provider was dispatched down the server-side path — a wiring fault.
    appleProvider()->handleCallback('code', 'nonce', 'https://example.org/callback');
})->throws(\LogicException::class);

function appleProvider(): AppleProvider
{
    return new AppleProvider(
        new InMemoryCredentialStore(['apple' => APPLE_AUDIENCE]),
        new JwtVerifier('Consumer/1.0 (test)'),
    );
}

function appleVerify(string $jwt): ?VerifiedIdentity
{
    FakeWpHttp::pushResponse(200, Tokens::jwksBody(Tokens::jwk(test()->key, APPLE_KID)));

    return appleProvider()->verifyIdToken($jwt, APPLE_NONCE);
}

/**
 * @param array<string, mixed> $overrides
 * @param list<string>         $remove
 */
function appleToken(array $overrides = [], array $remove = []): string
{
    $claims = array_merge([
        'iss'            => 'https://appleid.apple.com',
        'aud'            => APPLE_AUDIENCE,
        'sub'            => '000123.abc.456',
        'email'          => 'member@example.org',
        'email_verified' => 'true',
        'nonce'          => APPLE_NONCE,
        'iat'            => time(),
        'exp'            => time() + 600,
    ], $overrides);

    foreach ($remove as $claim) {
        unset($claims[$claim]);
    }

    return Tokens::sign(test()->key, $claims, APPLE_KID);
}
