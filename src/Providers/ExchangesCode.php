<?php

declare(strict_types=1);

namespace Guardian\Providers;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The token-endpoint POST every server-side provider makes.
 *
 * <b>POST, with the client secret in the body.</b> Facebook's endpoint also
 * accepts GET, but a secret in a request line lands in every proxy log,
 * access log and tracing span between here and the provider.
 *
 * Any transport failure, non-2xx answer or undecodable body is null: the
 * caller refuses the sign-in either way, and the distinction helps nobody but
 * whoever is probing.
 *
 * Expects the using class to hold the consumer's user-agent in
 * `$this->userAgent`.
 *
 * @internal
 */
trait ExchangesCode
{
    /**
     * @param array<string, string> $body
     * @param array<string, string> $headers
     * @return array<string, mixed>|null
     */
    private function postToTokenEndpoint(string $url, array $body, array $headers = []): ?array
    {
        $response = wp_remote_post($url, [
            'timeout' => 10,
            'user-agent' => $this->userAgent,
            'headers' => ['Accept' => 'application/json'] + $headers,
            'body' => $body,
        ]);

        if (is_wp_error($response)) {
            return null;
        }

        $httpCode = (int) wp_remote_retrieve_response_code($response);
        if ($httpCode < 200 || $httpCode >= 300) {
            return null;
        }

        $decoded = json_decode((string) wp_remote_retrieve_body($response), true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * The ID token out of a token-endpoint answer, or null.
     *
     * @param array<string, mixed>|null $tokens
     */
    private function idTokenFrom(?array $tokens): ?string
    {
        $idToken = $tokens['id_token'] ?? null;

        return is_string($idToken) && $idToken !== '' ? $idToken : null;
    }
}
