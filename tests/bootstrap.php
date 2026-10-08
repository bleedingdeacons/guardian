<?php

declare(strict_types=1);

/**
 * Test bootstrap for Guardian, loaded by Pest through phpunit.xml.
 *
 * WordPress stand-ins come from bleedingdeacons/wp-mocks. Its bootstrap
 * loads Patchwork before anything patchable, so nothing defining WordPress
 * functions of its own may come before the Bootstrap::load() call.
 *
 * The WP HTTP API is stubbed by wp-mocks, backed by Doubles\FakeWpHttp: the
 * provider and verifier tests queue the token endpoint's and the JWKS
 * endpoint's answers on it, then assert on what was sent.
 *
 * Not loaded: the `sentinel` stub group. The logger is a no-op when wp_log()
 * is absent, and that is the branch these tests run.
 */

use BleedingDeacons\WpMocks\Bootstrap;
use BleedingDeacons\WpMocks\WpState;

require_once __DIR__ . '/../vendor/autoload.php';

Bootstrap::load(['wordpress']);

WpState::$pluginSlug = 'guardian';

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}
