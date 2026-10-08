<?php

declare(strict_types=1);

namespace Guardian\Tests\Unit;

use BleedingDeacons\WpMocks\WpState;
use Guardian\State\StateStore;

/**
 * The state that ties a provider's callback back to the request that began
 * it — single-use, carrying the nonce, the PKCE verifier, and whatever the
 * consumer needs afterwards.
 */

covers(StateStore::class);

beforeEach(function () {
    WpState::reset();
});

test('issue and consume round trip', function () {
    $store = new StateStore('consumer_oauth_state_');

    $issued = $store->issue('google', null, ['return_to' => 'https://example.org/after']);
    $consumed = $store->consume($issued['state']);

    expect($consumed)->toBe([
        'provider'      => 'google',
        'nonce'         => $issued['nonce'],
        'code_verifier' => null,
        'extra'         => ['return_to' => 'https://example.org/after'],
    ]);
});

test('the state is single use', function () {
    $store = new StateStore('consumer_oauth_state_');

    $issued = $store->issue('google');

    expect($store->consume($issued['state']))->not->toBeNull();
    expect($store->consume($issued['state']))->toBeNull('A replayed callback must find nothing.');
});

test('an unknown or empty state finds nothing', function () {
    $store = new StateStore('consumer_oauth_state_');

    expect($store->consume('never-issued'))->toBeNull();
    expect($store->consume(''))->toBeNull();
});

test('a verifier survives the round trip', function () {
    $store = new StateStore('consumer_oauth_state_');

    $issued = $store->issue('facebook', 'the-verifier');

    expect($issued['code_verifier'])->toBe('the-verifier');
    expect($store->consume($issued['state'])['code_verifier'] ?? null)->toBe('the-verifier');
});

test('no verifier comes back as null rather than empty', function () {
    // FacebookProvider treats '' as "no verifier" and refuses; a store that
    // turned null into '' would fail every exchange with no explanation.
    $store = new StateStore('consumer_oauth_state_');

    $consumed = $store->consume($store->issue('google', '')['state']);

    expect($consumed)->toHaveKey('code_verifier');
    expect($consumed['code_verifier'])->toBeNull();
});

test('state and nonce are unpredictable and distinct', function () {
    $store = new StateStore('consumer_oauth_state_');

    $a = $store->issue('google');
    $b = $store->issue('google');

    expect($a['state'])->toMatch('/^[0-9a-f]{32}$/');
    expect($a['nonce'])->toMatch('/^[0-9a-f]{32}$/');
    expect($a['state'])->not->toBe($b['state']);
    expect($a['state'])->not->toBe($a['nonce']);
});

test('the record is a transient under the consumer prefix', function () {
    $store = new StateStore('consumer_oauth_state_', 300);

    $issued = $store->issue('google');

    expect(WpState::$transients)->toHaveKey('consumer_oauth_state_' . $issued['state']);
});

test('one consumer cannot spend another consumer state', function () {
    $reach = new StateStore('reach_oauth_state_');
    $fellowship = new StateStore('fellowship_oauth_state_');

    $issued = $reach->issue('google');

    expect($fellowship->consume($issued['state']))->toBeNull();
    expect($reach->consume($issued['state']))->not->toBeNull();
});

test('extra fields cannot overwrite the fields Guardian owns', function () {
    $store = new StateStore('consumer_oauth_state_');

    $issued = $store->issue('google', null, ['provider' => 'apple', 'nonce' => 'forged', 'audience' => 'link']);
    $consumed = $store->consume($issued['state']);

    expect($consumed['provider'] ?? null)->toBe('google');
    expect($consumed['nonce'] ?? null)->toBe($issued['nonce']);
    expect($consumed['extra'] ?? null)->toBe(['audience' => 'link']);
});

test('a record written by the store this replaced still reads back', function () {
    // A sign-in in flight across the deploy: Fellowship's own store wrote
    // these keys flat, and the consumer's wrapper reads them from `extra`.
    WpState::$transients['fellowship_oauth_state_abc'] = [
        'provider'        => 'google',
        'nonce'           => 'n-1',
        'device_redirect' => 'link://auth',
        'code_verifier'   => null,
        'audience'        => 'freedom',
        'context'         => 'ctx',
    ];

    expect((new StateStore('fellowship_oauth_state_'))->consume('abc'))->toBe([
        'provider'      => 'google',
        'nonce'         => 'n-1',
        'code_verifier' => null,
        'extra'         => ['device_redirect' => 'link://auth', 'audience' => 'freedom', 'context' => 'ctx'],
    ]);
});

test('a fresh code verifier is within the RFC 7636 range', function () {
    $verifier = StateStore::newCodeVerifier();

    expect(strlen($verifier))->toBeGreaterThanOrEqual(43)->toBeLessThanOrEqual(128);
    expect($verifier)->toMatch('/^[0-9a-f]+$/');
    expect(StateStore::newCodeVerifier())->not->toBe($verifier);
});
