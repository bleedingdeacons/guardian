<?php

declare(strict_types=1);

// Pest configuration.
//
// Every test here runs on wp-mocks' TestCase: the providers and the verifier
// reach the WP HTTP API and transients through the shared stubs, and the
// admin section echoes through the escaping functions. TestCase is what sets
// Brain Monkey up and tears it down around each test.

use BleedingDeacons\WpMocks\TestCase;

pest()->extend(TestCase::class)->in('Unit');

/**
 * Runs $render inside an output buffer and returns what it printed.
 *
 * The buffer is closed in a finally, so a render that throws cannot leave it
 * open and have PHPUnit flag the test as risky.
 */
function captureOutput(callable $render): string
{
    ob_start();

    try {
        $render();
    } finally {
        $html = (string) ob_get_clean();
    }

    return $html;
}
