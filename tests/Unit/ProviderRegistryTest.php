<?php

declare(strict_types=1);

namespace Guardian\Tests\Unit;

use Guardian\Jwt\JwtVerifier;
use Guardian\ProviderRegistry;
use Guardian\Providers\AppleProvider;
use Guardian\Providers\GoogleProvider;
use Guardian\Tests\Support\InMemoryCredentialStore;

/**
 * Registration is the permission model: a provider not registered is
 * unreachable, whatever name a request asks for.
 */

covers(ProviderRegistry::class);

test('a registered provider is found by name in any case', function () {
    $registry = new ProviderRegistry();
    $google = new GoogleProvider(new InMemoryCredentialStore(), new JwtVerifier('UA'), 'UA');
    $registry->register($google);

    expect($registry->get('google'))->toBe($google);
    expect($registry->get('Google'))->toBe($google);
});

test('an unregistered provider is not found', function () {
    $registry = new ProviderRegistry();
    $registry->register(new GoogleProvider(new InMemoryCredentialStore(), new JwtVerifier('UA'), 'UA'));

    expect($registry->get('facebook'))->toBeNull();
    expect($registry->get(''))->toBeNull();
});

test('names lists what is registered in order', function () {
    $registry = new ProviderRegistry();
    $registry->register(new GoogleProvider(new InMemoryCredentialStore(), new JwtVerifier('UA'), 'UA'));
    $registry->register(new AppleProvider(new InMemoryCredentialStore(), new JwtVerifier('UA')));

    expect($registry->names())->toBe(['google', 'apple']);
});

test('registering a name twice replaces the first', function () {
    $registry = new ProviderRegistry();
    $first = new GoogleProvider(new InMemoryCredentialStore(), new JwtVerifier('UA'), 'UA');
    $second = new GoogleProvider(new InMemoryCredentialStore(), new JwtVerifier('UA'), 'UA');

    $registry->register($first);
    $registry->register($second);

    expect($registry->get('google'))->toBe($second);
    expect($registry->names())->toBe(['google']);
});
