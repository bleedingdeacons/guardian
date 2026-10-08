# Guardian — OAuth Sign-in

[![CI](https://github.com/bleedingdeacons/guardian/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/bleedingdeacons/guardian/actions/workflows/ci.yml)
[![Semgrep](https://github.com/bleedingdeacons/guardian/actions/workflows/semgrep.yml/badge.svg?branch=main)](https://github.com/bleedingdeacons/guardian/actions/workflows/semgrep.yml)
[![Coverage Status](https://coveralls.io/repos/github/bleedingdeacons/guardian/badge.svg?branch=main)](https://coveralls.io/github/bleedingdeacons/guardian?branch=main)
![PHPStan](https://img.shields.io/badge/dynamic/yaml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbleedingdeacons%2Fguardian%2Fmain%2Fphpstan.neon.dist&query=%24.parameters.level&label=PHPStan&prefix=level%20&color=brightgreen)
![PHPCS](https://img.shields.io/badge/dynamic/xml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbleedingdeacons%2Fguardian%2Fmain%2F.phpcs.xml.dist&query=%2Fruleset%2Frule%5B1%5D%2F%40ref&label=PHPCS&color=brightgreen)
![Version](https://img.shields.io/github/v/tag/bleedingdeacons/guardian?label=version&color=blue)
![PHP](https://img.shields.io/badge/php-8.4%2B-777bb4)
![Licence](https://img.shields.io/badge/licence-MIT%20(Modified)-green)

OAuth sign-in for the Bleeding Deacons suite. **A Composer library, not a WordPress plugin** — it is never activated. Fellowship (the Link messaging server) and Reach (the 12th-step finder) each `require` it and load it through their own Composer autoloaders.

It exists because both plugins used to carry their own copy of this code, and the copies drifted. Reach's ID-token verifier gained a floor on cache-busting JWKS refetches; Fellowship's did not, and for months a token with a made-up key id could make Fellowship fetch a provider's keys on every request. The code that decides whether a stranger's claim about their own email address is true should exist once.

## What it ships

| Class | What it does |
|---|---|
| `Providers\GoogleProvider`, `MicrosoftProvider`, `FacebookProvider` | The server-side authorisation-code flow: build the authorization URL, exchange the callback's code, verify the ID token, answer a `VerifiedIdentity` or null. Facebook adds PKCE. Microsoft is pinned to the personal-accounts tenant. |
| `Providers\AppleProvider` | The client-side flow: verify an ID token the device or Apple's JS SDK obtained itself. |
| `Providers\OAuthProvider` | The contract all four satisfy. `isServerSide()` says which flow; `requiresPkce()` says whether to mint a verifier. |
| `Jwt\JwtVerifier` | RS256 only; `exp`, `iat`, issuer, audience and nonce all checked; key sets cached an hour, with at most one cache-busting refetch per key set per minute. |
| `State\StateStore` | Single-use state and nonce in a transient under the consumer's own prefix, carrying the PKCE verifier and whatever else the consumer needs back (`extra`). |
| `ProviderRegistry` | The providers a consumer accepts. Unregistered means unreachable. |
| `VerifiedIdentity` | An email address a provider proved the person controls — not yet an authorisation. |
| `Credentials\CredentialStore` | The interface a consumer's settings class implements so providers can read its client ids and secrets. |
| `Admin\ProviderCredentialsSection`, `ProviderField` | The client id and secret rows for a consumer's own settings page: `render()` inside its form, `save($_POST)` inside its handler. Secrets are write-only. |

What it deliberately does **not** ship: routes, controllers, sessions, device codes, member gates. Who may sign in, and what a successful sign-in turns into, is each consumer's business.

## Using it

```php
use Guardian\Jwt\JwtVerifier;
use Guardian\ProviderRegistry;
use Guardian\Providers\AppleProvider;
use Guardian\Providers\GoogleProvider;
use Guardian\State\StateStore;

$verifier  = new JwtVerifier(UserAgent::plugin(), 'myplugin');   // user-agent, log channel
$providers = new ProviderRegistry();
$providers->register(new GoogleProvider($settings, $verifier, UserAgent::plugin()));
$providers->register(new AppleProvider($settings, $verifier));

$states = new StateStore('myplugin_oauth_state_');

// Start
$provider = $providers->get('google');
$pkce     = $provider->requiresPkce() ? StateStore::newCodeVerifier() : null;
$issued   = $states->issue($provider->name(), $pkce, ['return_to' => $url]);
$redirect = $provider->getAuthorizationUrl($issued['state'], $issued['nonce'], $callbackUrl, $pkce);

// Callback
$stored   = $states->consume($_GET['state']);                    // null: expired or replayed
$identity = $providers->get($stored['provider'])
    ?->handleCallback($_GET['code'], $stored['nonce'], $callbackUrl, $stored['code_verifier']);
```

`$settings` is the consumer's own settings class, implementing `CredentialStore`. Credentials stay with each consumer: each registers its own redirect URI and may hold its own client, and one shared store would let one plugin's misconfiguration break another's sign-in.

## Two copies, one class

Fellowship and Reach each ship their own copy in `vendor/`, but PHP loads a class once per request: **whichever plugin's autoloader asks first supplies Guardian to both.** So the two must always be on compatible versions, and a new major means moving both together. The JWKS cache and the refetch floor are transients, shared by both consumers on a site.

`ProviderRegistry` is not `final` for one reason: Fellowship keeps a deprecated `Fellowship\Auth\ProviderRegistry` subclass while Freedom's test harness still builds one under that name. Nothing else should extend it.

## Installation

In the consuming plugin's `composer.json`:

```json
"repositories": [
    { "type": "vcs", "url": "https://github.com/bleedingdeacons/guardian" }
],
"require": {
    "bleedingdeacons/guardian": "^1.0"
}
```

Then load `vendor/autoload.php` from the plugin's main file, and have its build ship a `--no-dev` `vendor/`.

Releases are `vX.Y.Z` tags cut by hand on `main`. There is no zip and no GitHub Release asset.

## Requirements

- WordPress 6.1+
- PHP 8.4+, with `ext-openssl` and `ext-json`
- Sentinel optional: without `wp_log()`, the verifier's warnings go nowhere

## Testing

```bash
composer install
```

| Command | Description |
|---|---|
| `composer test` | Run the Pest suite |
| `composer test:coverage` | Generate an HTML coverage report |
| `composer phpstan` | Run PHPStan (level 8, no baseline) |
| `composer phpcs` | Check PSR-12 |
| `composer phpcs:fix` | Auto-fix PSR-12 violations |
| `composer check` | PHPCS + PHPStan + tests |

PHPStan scans `../sentinel/src`, so check Sentinel out alongside, as CI does.

**Set `OPENSSL_CONF` locally.** The provider and verifier tests mint real RSA keypairs, and on a PHP build without a usable `openssl.cnf` they skip rather than fail. A green run with skips has not tested the verifier; check the skip count is zero.

---

## License

MIT (Modified)
