<?php

declare(strict_types=1);

namespace Guardian\Tests\Unit;

use BleedingDeacons\WpMocks\WpState;
use Guardian\Admin\ProviderCredentialsSection;
use Guardian\Admin\ProviderField;
use Guardian\Tests\Support\InMemoryCredentialStore;

use function captureOutput;

/**
 * The provider rows a consumer embeds in its own settings page.
 *
 * The property that matters most is the one a screenshot would break: a
 * stored secret is never rendered back into the form, and submitting the
 * field empty never clears it.
 */

covers(ProviderCredentialsSection::class, ProviderField::class);

const SECTION_CALLBACK = 'https://aa-bristol.org/wp-json/consumer/v1/auth/callback';

beforeEach(function () {
    WpState::reset();

    $this->store = new InMemoryCredentialStore(
        ['google' => 'google-client-id', 'apple' => 'org.aa-bristol.link'],
        ['google' => 'a-stored-secret'],
    );
});

test('each provider gets its own block with its client id', function () {
    $html = captureOutput(fn () => sectionFor($this->store)->render());

    expect($html)->toContain('<h3>Google</h3>');
    expect($html)->toContain('<h3>Microsoft</h3>');
    expect($html)->toContain('<h3>Apple</h3>');
    expect($html)->toContain('name="c_client_id_google"');
    expect($html)->toContain('value="google-client-id"');
    expect($html)->toContain('value="org.aa-bristol.link"');
});

test('a stored secret is never rendered back', function () {
    $html = captureOutput(fn () => sectionFor($this->store)->render());

    expect($html)->not->toContain('a-stored-secret');
    expect($html)->toContain('A secret is stored.');
    expect($html)->toContain('name="c_clear_secret_google"');
});

test('a provider with no secret says sign in will not work', function () {
    $html = captureOutput(fn () => sectionFor($this->store)->render());

    expect($html)->toContain('No secret is stored — Microsoft sign-in will not work.');
    // Nothing to clear when nothing is stored.
    expect($html)->not->toContain('name="c_clear_secret_microsoft"');
});

test('Apple has no secret field at all', function () {
    $html = captureOutput(fn () => sectionFor($this->store)->render());

    expect($html)->not->toContain('c_client_secret_apple');
    expect($html)->toContain('Service ID (audience)');
});

test('the redirect URI is shown with a copy button', function () {
    $html = captureOutput(fn () => sectionFor($this->store)->render());

    expect($html)->toContain('id="c_redirect_google">' . SECTION_CALLBACK . '</code>');
    expect($html)->toContain('data-clipboard-target="c_redirect_google"');
    // Apple was given no redirect, so it shows none.
    expect($html)->not->toContain('c_redirect_apple');
});

test('saving writes client ids unslashed and trimmed of markup', function () {
    $store = new InMemoryCredentialStore();

    sectionFor($store)->save([
        'c_client_id_google'    => ' new-google-id ',
        'c_client_id_microsoft' => '<b>ms-id</b>',
        'c_client_id_apple'     => 'org.example\\\'s.app',
    ]);

    expect($store->ids)->toBe([
        'google'    => 'new-google-id',
        'microsoft' => 'ms-id',
        'apple'     => "org.example's.app",
    ]);
});

test('an empty secret field leaves the stored secret alone', function () {
    sectionFor($this->store)->save(['c_client_id_google' => 'google-client-id', 'c_client_secret_google' => '']);

    expect($this->store->getClientSecret('google'))->toBe('a-stored-secret');
});

test('a submitted secret replaces the stored one, unslashed but otherwise untouched', function () {
    sectionFor($this->store)->save(['c_client_secret_google' => '  s3cr\\"et<x>  ']);

    // Trimmed, unslashed — but not sanitised: a credential is not text.
    expect($this->store->getClientSecret('google'))->toBe('s3cr"et<x>');
});

test('ticking clear removes the secret even when a new one is typed', function () {
    sectionFor($this->store)->save([
        'c_clear_secret_google'  => '1',
        'c_client_secret_google' => 'typed-anyway',
    ]);

    expect($this->store->getClientSecret('google'))->toBe('');
});

test('a non string field is treated as empty', function () {
    sectionFor($this->store)->save([
        'c_client_id_google'     => ['an', 'array'],
        'c_client_secret_google' => ['nope'],
    ]);

    expect($this->store->getClientId('google'))->toBe('');
    expect($this->store->getClientSecret('google'))->toBe('a-stored-secret');
});

test('field names carry the prefix', function () {
    $section = new ProviderCredentialsSection($this->store, [ProviderField::google(SECTION_CALLBACK)], 'reach_');

    expect($section->fieldName('client_id', 'google'))->toBe('reach_client_id_google');
    expect($section->fieldName('clear_secret', 'google'))->toBe('reach_clear_secret_google');
});

test('the named fields carry the standard wording', function () {
    expect(ProviderField::facebook(SECTION_CALLBACK)->secretLabel)->toBe('App secret');
    expect(ProviderField::microsoft(SECTION_CALLBACK)->help)->toContain('Personal Microsoft accounts only');
    expect(ProviderField::apple()->hasSecret)->toBeFalse();
    expect(ProviderField::apple('', 'Custom help.')->help)->toBe('Custom help.');
});

function sectionFor(InMemoryCredentialStore $store): ProviderCredentialsSection
{
    return new ProviderCredentialsSection($store, [
        ProviderField::google(SECTION_CALLBACK),
        ProviderField::microsoft(SECTION_CALLBACK),
        ProviderField::apple(),
    ], 'c_');
}
