<?php

declare(strict_types=1);

namespace Guardian\Tests\Unit;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Guardian\Firebase\FirebaseDeviceTokenVerifier;
use Guardian\Firebase\FirebaseIdTokenVerifier;
use Guardian\Firebase\VerifiedDeviceToken;
use Guardian\Jwt\JwtVerifier;
use Guardian\Tests\Support\Tokens;

/**
 * The ID token of a device signed in with a custom token.
 *
 * <b>The opposite of a person's sign-in on three points.</b> No email, no limit on
 * how old the sign-in is, and the same token is accepted every time. What must not
 * change is that the signature and project are checked, and that nothing but a
 * custom sign-in passes.
 */

covers(FirebaseDeviceTokenVerifier::class, VerifiedDeviceToken::class);

const DEVICE_PROJECT = 'sentinel-67404';
const DEVICE_KID = 'firebase-key-1';

beforeEach(function () {
    FakeWpHttp::reset();
    WpState::reset();

    $this->key = Tokens::keyOrSkip();
});

test('a valid token yields the device and its claims', function () {
    $authTime = time() - 100;

    $device = deviceVerify(deviceToken(['auth_time' => $authTime]));

    expect($device?->uid)->toBe('d_abc');
    expect($device?->authTime)->toBe($authTime);
    expect($device?->claims['memberId'])->toBe(7);
    expect($device?->claims['kind'])->toBe('device');
});

test('the token is checked against the Firebase key set', function () {
    deviceVerify(deviceToken());

    expect(FakeWpHttp::sentUrl(0))->toBe(FirebaseIdTokenVerifier::JWKS_URL);
});

test('no email is needed', function () {
    expect(deviceVerify(deviceToken(remove: ['email', 'email_verified'])))->not->toBeNull();
});

test('a sign-in from months ago is accepted', function () {
    // A device signs in once. iat moves on each refresh, and auth_time doesn't.
    expect(deviceVerify(deviceToken(['auth_time' => time() - 90 * 86400])))->not->toBeNull();
});

test('the same token is accepted every time', function () {
    $token = deviceToken();

    expect(deviceVerify($token))->not->toBeNull();
    expect(deviceVerify($token))->not->toBeNull();
});

test('a token from another Firebase project is refused', function () {
    $token = deviceToken([
        'iss' => 'https://securetoken.google.com/someone-else',
        'aud' => 'someone-else',
    ]);

    expect(deviceVerify($token))->toBeNull();
});

test('a token for another audience is refused', function () {
    expect(deviceVerify(deviceToken(['aud' => 'someone-else'])))->toBeNull();
});

test('a token from another issuer is refused', function () {
    expect(deviceVerify(deviceToken(['iss' => 'https://accounts.google.com'])))->toBeNull();
});

test('an expired token is refused', function () {
    expect(deviceVerify(deviceToken(['exp' => time() - 3600])))->toBeNull();
});

test('a token signed with another key is refused', function () {
    $stranger = Tokens::keyOrSkip();
    $forged = Tokens::sign($stranger, deviceClaims(), DEVICE_KID);

    expect(deviceVerify($forged))->toBeNull();
});

test('an empty project id or token refuses everything', function () {
    expect(deviceVerifier()->verify(deviceToken(), ''))->toBeNull();
    expect(deviceVerifier()->verify('', DEVICE_PROJECT))->toBeNull();
});

test('any other sign-in method is refused', function (string $method) {
    // A person's Google sign-in in the same project must not pass as a device.
    expect(deviceVerify(deviceToken(['firebase' => ['sign_in_provider' => $method]])))->toBeNull();
})->with(['google.com', 'apple.com', 'anonymous', 'password', 'emailLink']);

test('a token with no firebase claim is refused', function () {
    expect(deviceVerify(deviceToken(remove: ['firebase'])))->toBeNull();
    expect(deviceVerify(deviceToken(['firebase' => 'custom'])))->toBeNull();
});

test('a token with no usable subject is refused', function () {
    expect(deviceVerify(deviceToken(remove: ['sub'])))->toBeNull();
    expect(deviceVerify(deviceToken(['sub' => ''])))->toBeNull();
    expect(deviceVerify(deviceToken(['sub' => str_repeat('a', 129)])))->toBeNull();
});

test('a token with no auth time is refused', function () {
    expect(deviceVerify(deviceToken(remove: ['auth_time'])))->toBeNull();
    expect(deviceVerify(deviceToken(['auth_time' => 'yesterday'])))->toBeNull();
});

test('a sign-in in the future is refused', function () {
    expect(deviceVerify(deviceToken(['auth_time' => time() + 5 * 60])))->toBeNull();
});

test('a person verifier still refuses a device token', function () {
    // The two must not overlap, in either direction.
    FakeWpHttp::pushResponse(200, Tokens::jwksBody(Tokens::jwk(test()->key, DEVICE_KID)));

    $verifier = new FirebaseIdTokenVerifier(new JwtVerifier('Consumer/1.0 (test)'));

    expect($verifier->verify(deviceToken(), DEVICE_PROJECT))->toBeNull();
});

function deviceVerifier(): FirebaseDeviceTokenVerifier
{
    return new FirebaseDeviceTokenVerifier(new JwtVerifier('Consumer/1.0 (test)'));
}

function deviceVerify(string $jwt): ?VerifiedDeviceToken
{
    FakeWpHttp::pushResponse(200, Tokens::jwksBody(Tokens::jwk(test()->key, DEVICE_KID)));

    return deviceVerifier()->verify($jwt, DEVICE_PROJECT);
}

/**
 * @param array<string, mixed> $overrides
 * @param list<string>         $remove
 *
 * @return array<string, mixed>
 */
function deviceClaims(array $overrides = [], array $remove = []): array
{
    $claims = array_merge([
        'iss'       => 'https://securetoken.google.com/' . DEVICE_PROJECT,
        'aud'       => DEVICE_PROJECT,
        'sub'       => 'd_abc',
        'user_id'   => 'd_abc',
        'memberId'  => 7,
        'kind'      => 'device',
        'auth_time' => time() - 5,
        'iat'       => time(),
        'exp'       => time() + 3600,
        'firebase'  => ['sign_in_provider' => 'custom', 'identities' => []],
    ], $overrides);

    foreach ($remove as $claim) {
        unset($claims[$claim]);
    }

    return $claims;
}

/**
 * @param array<string, mixed> $overrides
 * @param list<string>         $remove
 */
function deviceToken(array $overrides = [], array $remove = []): string
{
    return Tokens::sign(test()->key, deviceClaims($overrides, $remove), DEVICE_KID);
}
