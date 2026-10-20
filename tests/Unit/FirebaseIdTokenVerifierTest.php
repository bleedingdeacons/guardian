<?php

declare(strict_types=1);

namespace Guardian\Tests\Unit;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Guardian\Firebase\FirebaseIdTokenVerifier;
use Guardian\Jwt\JwtVerifier;
use Guardian\Tests\Support\Tokens;
use Guardian\VerifiedIdentity;

/**
 * A Firebase ID token from a handset's native Google sign-in.
 *
 * <b>No nonce, so the rest has to hold.</b> The other providers bind a token
 * to one sign-in with a nonce the server issued. Here nothing of ours goes
 * into the token, so the project pin, the sign-in method, the age of the
 * sign-in and single use are the whole of the defence, and each is tested
 * on its own.
 */

covers(FirebaseIdTokenVerifier::class);

const FIREBASE_PROJECT = 'sentinel-67404';
const FIREBASE_KID = 'firebase-key-1';

beforeEach(function () {
    FakeWpHttp::reset();
    WpState::reset();

    $this->key = Tokens::keyOrSkip();
});

test('a valid token yields the verified identity', function () {
    $identity = firebaseVerify(firebaseToken());

    expect($identity?->email)->toBe('member@example.org');
    expect($identity?->provider)->toBe('google');
});

test('the Google subject is preferred over the Firebase uid', function () {
    expect(firebaseVerify(firebaseToken())?->sub)->toBe('110248495921238986420');
});

test('the Firebase uid is used when no Google subject is passed on', function () {
    $token = firebaseToken(['firebase' => ['sign_in_provider' => 'google.com', 'identities' => []]]);

    expect(firebaseVerify($token)?->sub)->toBe('firebase-uid-1');
});

test('the token is checked against the Firebase key set', function () {
    firebaseVerify(firebaseToken());

    expect(FakeWpHttp::sentUrl(0))->toBe(FirebaseIdTokenVerifier::JWKS_URL);
});

test('the email is lower cased', function () {
    expect(firebaseVerify(firebaseToken(['email' => 'Member@Example.ORG']))?->email)->toBe('member@example.org');
});

test('a token from another Firebase project is refused', function () {
    $token = firebaseToken([
        'iss' => 'https://securetoken.google.com/someone-else',
        'aud' => 'someone-else',
    ]);

    expect(firebaseVerify($token))->toBeNull();
});

test('a token for another audience is refused', function () {
    expect(firebaseVerify(firebaseToken(['aud' => 'someone-else'])))->toBeNull();
});

test('a token from another issuer is refused', function () {
    expect(firebaseVerify(firebaseToken(['iss' => 'https://accounts.google.com'])))->toBeNull();
});

test('an empty project id refuses everything', function () {
    FakeWpHttp::pushResponse(200, Tokens::jwksBody(Tokens::jwk(test()->key, FIREBASE_KID)));

    expect(firebaseVerifier()->verify(firebaseToken(), ''))->toBeNull();
});

test('another sign-in method is refused', function (string $method) {
    $token = firebaseToken(['firebase' => ['sign_in_provider' => $method]]);

    expect(firebaseVerify($token))->toBeNull();
})->with(['anonymous', 'custom', 'password', 'emailLink', 'apple.com']);

test('a token with no firebase claim is refused', function () {
    expect(firebaseVerify(firebaseToken(remove: ['firebase'])))->toBeNull();
});

test('an unsupported sign-in method cannot be asked for', function () {
    FakeWpHttp::pushResponse(200, Tokens::jwksBody(Tokens::jwk(test()->key, FIREBASE_KID)));

    $token = firebaseToken(['firebase' => ['sign_in_provider' => 'anonymous']]);

    expect(firebaseVerifier()->verify($token, FIREBASE_PROJECT, 'anonymous'))->toBeNull();
});

test('an unverified email is refused', function () {
    expect(firebaseVerify(firebaseToken(['email_verified' => false])))->toBeNull();
    expect(firebaseVerify(firebaseToken(['email_verified' => 'true'])))->toBeNull();
});

test('a missing email verified claim is refused', function () {
    expect(firebaseVerify(firebaseToken(remove: ['email_verified'])))->toBeNull();
});

test('a token with no email is refused', function () {
    expect(firebaseVerify(firebaseToken(remove: ['email'])))->toBeNull();
    expect(firebaseVerify(firebaseToken(['email' => ''])))->toBeNull();
});

test('a token with no subject is refused', function () {
    expect(firebaseVerify(firebaseToken(remove: ['sub'])))->toBeNull();
    expect(firebaseVerify(firebaseToken(['sub' => ''])))->toBeNull();
    expect(firebaseVerify(firebaseToken(['sub' => str_repeat('a', 129)])))->toBeNull();
});

test('a sign-in older than five minutes is refused', function () {
    // iat is recent: Firebase refreshed the token silently. auth_time is
    // when the person last actually chose an account.
    expect(firebaseVerify(firebaseToken(['auth_time' => time() - 7 * 60])))->toBeNull();
});

test('a sign-in a few minutes old is accepted', function () {
    expect(firebaseVerify(firebaseToken(['auth_time' => time() - 4 * 60])))->not->toBeNull();
});

test('a sign-in in the future is refused', function () {
    expect(firebaseVerify(firebaseToken(['auth_time' => time() + 5 * 60])))->toBeNull();
});

test('a token with no auth time is refused', function () {
    expect(firebaseVerify(firebaseToken(remove: ['auth_time'])))->toBeNull();
});

test('the same token is accepted only once', function () {
    $token = firebaseToken();

    expect(firebaseVerify($token))->not->toBeNull();
    expect(firebaseVerify($token))->toBeNull();
});

test('a refused token is not spent', function () {
    // Spending before the claims are checked would let anyone burn a
    // token they had only seen, by presenting it to the wrong project.
    $token = firebaseToken();

    FakeWpHttp::pushResponse(200, Tokens::jwksBody(Tokens::jwk(test()->key, FIREBASE_KID)));
    expect(firebaseVerifier()->verify($token, 'someone-else'))->toBeNull();

    expect(firebaseVerify($token))->not->toBeNull();
});

function firebaseVerifier(): FirebaseIdTokenVerifier
{
    return new FirebaseIdTokenVerifier(new JwtVerifier('Consumer/1.0 (test)'));
}

function firebaseVerify(string $jwt): ?VerifiedIdentity
{
    FakeWpHttp::pushResponse(200, Tokens::jwksBody(Tokens::jwk(test()->key, FIREBASE_KID)));

    return firebaseVerifier()->verify($jwt, FIREBASE_PROJECT);
}

/**
 * @param array<string, mixed> $overrides
 * @param list<string>         $remove
 */
function firebaseToken(array $overrides = [], array $remove = []): string
{
    $claims = array_merge([
        'iss'            => 'https://securetoken.google.com/' . FIREBASE_PROJECT,
        'aud'            => FIREBASE_PROJECT,
        'sub'            => 'firebase-uid-1',
        'user_id'        => 'firebase-uid-1',
        'email'          => 'member@example.org',
        'email_verified' => true,
        'auth_time'      => time() - 5,
        'iat'            => time(),
        'exp'            => time() + 3600,
        'firebase'       => [
            'sign_in_provider' => 'google.com',
            'identities'       => [
                'google.com' => ['110248495921238986420'],
                'email'      => ['member@example.org'],
            ],
        ],
    ], $overrides);

    foreach ($remove as $claim) {
        unset($claims[$claim]);
    }

    return Tokens::sign(test()->key, $claims, FIREBASE_KID);
}
