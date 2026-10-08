<?php

declare(strict_types=1);

namespace Guardian\Tests\Unit;

use BleedingDeacons\WpMocks\Doubles\FakeWpHttp;
use BleedingDeacons\WpMocks\WpState;
use Guardian\Jwt\JwtVerifier;
use Guardian\Providers\FacebookProvider;
use Guardian\Providers\GoogleProvider;
use Guardian\Providers\MicrosoftProvider;
use Guardian\Providers\OAuthProvider;
use Guardian\Tests\Support\InMemoryCredentialStore;
use Guardian\Tests\Support\Tokens;
use Guardian\VerifiedIdentity;

/**
 * The three browser-leg providers, from the callback inwards.
 *
 * <b>Each exchanges a code and then decides whether to believe the address
 * in the token that comes back.</b> They differ in exactly one respect that
 * matters, and it is the respect a copy-paste between them would destroy:
 *
 *  - <b>Google and Facebook require `email_verified`</b>, and reject an
 *    absent claim as firmly as a false one.
 *  - <b>Microsoft has no such claim on a consumer token</b>, so requiring it
 *    would refuse every sign-in. The pinned consumer-tenant issuer stands in
 *    its place.
 *
 * Every test mints a real RS256 token and serves a real JWKS, so what is
 * exercised is the provider's decision rather than a stubbed answer about it.
 */

covers(
    GoogleProvider::class,
    MicrosoftProvider::class,
    FacebookProvider::class,
    \Guardian\Providers\ExchangesCode::class,
    VerifiedIdentity::class,
);

const SERVER_REDIRECT = 'https://aa-bristol.org/wp-json/consumer/v1/auth/callback';
const SERVER_NONCE = 'the-issued-nonce';
const SERVER_KID = 'test-key-1';
const MSA_ISSUER = 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0';
const SERVER_UA = 'Consumer/1.0 (test)';

beforeEach(function () {
    FakeWpHttp::reset();
    WpState::reset();

    $this->credentials = new InMemoryCredentialStore(
        ['google' => 'google-client-id', 'microsoft' => 'ms-client-id', 'facebook' => 'fb-app-id'],
        ['google' => 'google-secret', 'microsoft' => 'ms-secret', 'facebook' => 'fb-secret'],
    );
});

// ── Google ────────────────────────────────────────────────────────

test('Google accepts a verified address', function () {
    $identity = serverExchange(serverGoogle(), ['iss' => 'https://accounts.google.com', 'aud' => 'google-client-id']);

    expect($identity)->toBeInstanceOf(VerifiedIdentity::class);
    expect($identity?->email)->toBe('member@example.org');
    expect($identity?->provider)->toBe('google');
    expect($identity?->sub)->toBe('sub-1');
    expect($identity?->providerEmail)->toBeNull();
});

test('Google refuses an unverified address', function () {
    expect(serverExchange(serverGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'google-client-id',
        'email_verified' => false,
    ]))->toBeNull();
});

test('Google refuses the string true where OIDC says boolean', function () {
    // Apple is the one provider that ships the string; Google never has, so
    // accepting it here would be accepting something Google did not send.
    expect(serverExchange(serverGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'google-client-id',
        'email_verified' => 'true',
    ]))->toBeNull();
});

test('Google refuses a token with no verified claim at all', function () {
    expect(serverExchange(serverGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'google-client-id',
    ], remove: ['email_verified']))->toBeNull();
});

test('Google refuses a token with no address', function () {
    expect(serverExchange(serverGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'google-client-id',
    ], remove: ['email']))->toBeNull();
});

test('Google refuses a token for another client', function () {
    expect(serverExchange(serverGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'somebody-elses-client',
    ]))->toBeNull();
});

test('Google lowers the address', function () {
    $identity = serverExchange(serverGoogle(), [
        'iss' => 'https://accounts.google.com',
        'aud' => 'google-client-id',
        'email' => 'Member@Example.ORG',
    ]);

    expect($identity?->email)->toBe('member@example.org');
});

test('Google asks for nothing beyond an address', function () {
    expect(serverQuery(serverGoogle()->getAuthorizationUrl('state-1', SERVER_NONCE, SERVER_REDIRECT)))->toMatchArray([
        'client_id'     => 'google-client-id',
        'redirect_uri'  => SERVER_REDIRECT,
        'response_type' => 'code',
        'scope'         => 'openid email',
        'state'         => 'state-1',
        'nonce'         => SERVER_NONCE,
        // A device is often shared or carries several accounts.
        'prompt'        => 'select_account',
    ]);
});

test('Google sends the code and the secret to the token endpoint', function () {
    serverExchange(serverGoogle(), ['iss' => 'https://accounts.google.com', 'aud' => 'google-client-id']);

    expect(FakeWpHttp::sentUrl(0))->toBe('https://oauth2.googleapis.com/token');
    expect(FakeWpHttp::sentArgs(0)['body'])->toMatchArray([
        'code'          => 'a-code',
        'client_id'     => 'google-client-id',
        'client_secret' => 'google-secret',
        'redirect_uri'  => SERVER_REDIRECT,
        'grant_type'    => 'authorization_code',
    ]);
    expect(FakeWpHttp::sentArgs(0)['user-agent'] ?? null)->toBe(SERVER_UA);
});

// ── Microsoft ─────────────────────────────────────────────────────

test('Microsoft accepts a consumer token', function () {
    $identity = serverExchange(serverMicrosoft(), ['iss' => MSA_ISSUER, 'aud' => 'ms-client-id'], remove: ['email_verified']);

    expect($identity?->email)->toBe('member@example.org');
    expect($identity?->provider)->toBe('microsoft');
});

test('Microsoft refuses a token from another tenant', function () {
    // The property the pinned issuer exists for: on the common endpoint any
    // tenant admin can mint a token asserting any address.
    expect(serverExchange(serverMicrosoft(), [
        'iss' => 'https://login.microsoftonline.com/some-other-tenant-guid/v2.0',
        'aud' => 'ms-client-id',
    ], remove: ['email_verified']))->toBeNull();
});

test('Microsoft falls back to preferred username', function () {
    $identity = serverExchange(serverMicrosoft(), [
        'iss' => MSA_ISSUER,
        'aud' => 'ms-client-id',
        'preferred_username' => 'Member@Example.org',
    ], remove: ['email', 'email_verified']);

    expect($identity?->email)->toBe('member@example.org');
});

test('Microsoft refuses a preferred username that is not an address', function () {
    expect(serverExchange(serverMicrosoft(), [
        'iss' => MSA_ISSUER,
        'aud' => 'ms-client-id',
        'preferred_username' => 'DaveP',
    ], remove: ['email', 'email_verified']))->toBeNull();
});

test('Microsoft pins the consumer tenant and asks for profile', function () {
    $url = serverMicrosoft()->getAuthorizationUrl('state-1', SERVER_NONCE, SERVER_REDIRECT);

    expect($url)->toStartWith('https://login.microsoftonline.com/consumers/');
    expect($url)->not->toContain('/common/');

    // Without `profile`, Microsoft will not populate preferred_username, the
    // fallback the address is read from.
    expect(serverQuery($url))->toMatchArray([
        'scope'         => 'openid email profile',
        'response_mode' => 'query',
        'prompt'        => 'select_account',
    ]);
});

// ── Facebook ──────────────────────────────────────────────────────

test('Facebook accepts a verified address', function () {
    $identity = serverExchange(serverFacebook(), ['iss' => 'https://www.facebook.com', 'aud' => 'fb-app-id'], verifier: 'the-code-verifier');

    expect($identity?->provider)->toBe('facebook');
});

test('Facebook refuses an unverified address', function () {
    expect(serverExchange(serverFacebook(), [
        'iss' => 'https://www.facebook.com',
        'aud' => 'fb-app-id',
        'email_verified' => false,
    ], verifier: 'the-code-verifier'))->toBeNull();
});

test('Facebook sends the verifier on the exchange', function () {
    serverExchange(serverFacebook(), ['iss' => 'https://www.facebook.com', 'aud' => 'fb-app-id'], verifier: 'the-code-verifier');

    expect(FakeWpHttp::sentUrl(0))->toBe('https://graph.facebook.com/v21.0/oauth/access_token');
    expect(FakeWpHttp::sentArgs(0)['body']['code_verifier'] ?? null)->toBe('the-code-verifier');
});

test('Facebook refuses a callback with no verifier without calling out', function () {
    // Null rather than an exception: by the callback a browser is waiting and
    // the state is spent, so this has to become a routable refusal.
    expect(serverFacebook()->handleCallback('a-code', SERVER_NONCE, SERVER_REDIRECT))->toBeNull();
    expect(serverFacebook()->handleCallback('a-code', SERVER_NONCE, SERVER_REDIRECT, ''))->toBeNull();
    expect(FakeWpHttp::callCount())->toBe(0);
});

test('the Facebook authorization URL carries the challenge and not the verifier', function () {
    $verifier = 'a-verifier-nobody-outside-this-server-should-see';
    $url = serverFacebook()->getAuthorizationUrl('state-1', 'nonce-1', SERVER_REDIRECT, $verifier);

    expect(serverQuery($url))->toMatchArray([
        'scope'                 => 'openid email',
        'code_challenge_method' => 'S256',
        'code_challenge'        => Tokens::base64Url(hash('sha256', $verifier, true)),
    ]);
    expect($url)->not->toContain($verifier);
});

test('Facebook refuses to build a URL with no verifier', function () {
    serverFacebook()->getAuthorizationUrl('state-1', 'nonce-1', SERVER_REDIRECT);
})->throws(\LogicException::class);

test('only Facebook asks for PKCE', function () {
    expect(serverFacebook()->requiresPkce())->toBeTrue();
    expect(serverMicrosoft()->requiresPkce())->toBeFalse();
    expect(serverGoogle()->requiresPkce())->toBeFalse();
});

// ── What they all share ───────────────────────────────────────────

test('the client secret is sent in the body and never the URL', function (string $which, string $iss, string $aud) {
    serverExchange(serverProvider($which), ['iss' => $iss, 'aud' => $aud], verifier: 'v');

    expect(FakeWpHttp::sentUrl(0))->not->toContain('secret');
    expect(FakeWpHttp::sentArgs(0)['body'])->toHaveKey('client_secret');
})->with([
    'google'    => ['google', 'https://accounts.google.com', 'google-client-id'],
    'microsoft' => ['microsoft', MSA_ISSUER, 'ms-client-id'],
    'facebook'  => ['facebook', 'https://www.facebook.com', 'fb-app-id'],
]);

test('a token endpoint that answers no id token is refused', function (string $which) {
    FakeWpHttp::pushResponse(200, '{"access_token":"ya29.x"}');

    expect(serverProvider($which)->handleCallback('a-code', SERVER_NONCE, SERVER_REDIRECT, 'v'))->toBeNull();
})->with(['google', 'microsoft', 'facebook']);

test('a refused exchange is refused', function (string $which) {
    FakeWpHttp::pushResponse(400, '{"error":"invalid_grant"}');

    expect(serverProvider($which)->handleCallback('a-code', SERVER_NONCE, SERVER_REDIRECT, 'v'))->toBeNull();
})->with(['google', 'microsoft', 'facebook']);

test('an unreachable token endpoint is refused', function (string $which) {
    FakeWpHttp::push(new \WP_Error('http_request_failed', 'offline'));

    expect(serverProvider($which)->handleCallback('a-code', SERVER_NONCE, SERVER_REDIRECT, 'v'))->toBeNull();
})->with(['google', 'microsoft', 'facebook']);

test('a server side provider refuses a client supplied token', function (string $which) {
    $provider = serverProvider($which);

    expect($provider->isServerSide())->toBeTrue();
    expect($provider->name())->toBe($which);

    $provider->verifyIdToken('a.b.c', 'nonce');
})->with(['google', 'microsoft', 'facebook'])->throws(\LogicException::class);

// ── Fixtures ──────────────────────────────────────────────────────

/**
 * Run a provider's callback against a token it should be willing to read,
 * and answer the identity it made of it.
 *
 * @param array<string, mixed> $claims
 * @param list<string>         $remove
 */
function serverExchange(OAuthProvider $provider, array $claims, array $remove = [], ?string $verifier = null): ?VerifiedIdentity
{
    $key = Tokens::keyOrSkip();

    $claims = array_merge([
        'sub' => 'sub-1',
        'email' => 'member@example.org',
        'email_verified' => true,
        'nonce' => SERVER_NONCE,
        'iat' => time(),
        'exp' => time() + 600,
    ], $claims);

    foreach ($remove as $claim) {
        unset($claims[$claim]);
    }

    // The token exchange, then the JWKS the verifier fetches.
    FakeWpHttp::pushResponse(200, (string) json_encode(['id_token' => Tokens::sign($key, $claims, SERVER_KID)]));
    FakeWpHttp::pushResponse(200, Tokens::jwksBody(Tokens::jwk($key, SERVER_KID)));

    return $provider->handleCallback('a-code', SERVER_NONCE, SERVER_REDIRECT, $verifier);
}

/** @return array<string, mixed> */
function serverQuery(string $url): array
{
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    return $query;
}

function serverProvider(string $which): OAuthProvider
{
    return match ($which) {
        'google'    => serverGoogle(),
        'microsoft' => serverMicrosoft(),
        'facebook'  => serverFacebook(),
    };
}

function serverGoogle(): GoogleProvider
{
    return new GoogleProvider(test()->credentials, new JwtVerifier(SERVER_UA), SERVER_UA);
}

function serverMicrosoft(): MicrosoftProvider
{
    return new MicrosoftProvider(test()->credentials, new JwtVerifier(SERVER_UA), SERVER_UA);
}

function serverFacebook(): FacebookProvider
{
    return new FacebookProvider(test()->credentials, new JwtVerifier(SERVER_UA), SERVER_UA);
}
