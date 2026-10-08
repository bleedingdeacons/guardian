<?php

declare(strict_types=1);

namespace Guardian\State;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The short-lived state that ties an OAuth redirect back to the request that
 * started it.
 *
 * `state` defeats CSRF on the callback; `nonce` binds the returned ID token to
 * this particular sign-in, so a token captured elsewhere cannot be replayed
 * here. Both are single-use: {@see consume()} deletes the record before
 * returning it, so a replayed callback finds nothing.
 *
 * <b>A PKCE `code_verifier` rides along for providers that require one.</b>
 * It never leaves this server: only its SHA-256 challenge goes out on the
 * authorise leg, which is the whole point of the mechanism. Providers without
 * PKCE leave it null, and null comes back as null, never '' — Facebook treats
 * an empty verifier as none and refuses.
 *
 * <b>Whatever else the consumer needs comes back in `extra`</b>: where to
 * send the browser afterwards, which audience the sign-in is for, and so on.
 * It is stored flat beside the three fields Guardian owns, which is what lets
 * a record written by the per-plugin stores this replaced still be read: a
 * sign-in in flight across the deploy completes. Guardian's own fields win a
 * clash.
 *
 * Each consumer passes its own key prefix, so one plugin's state can never be
 * spent at another's callback. Transients rather than a table: ten minutes is
 * plenty to bounce through a provider, and WordPress already sweeps them.
 */
final class StateStore
{
    public const DEFAULT_TTL_SECONDS = 600;

    private const OWN_FIELDS = ['provider', 'nonce', 'code_verifier'];

    public function __construct(
        private readonly string $prefix,
        private readonly int $ttlSeconds = self::DEFAULT_TTL_SECONDS,
    ) {
    }

    /**
     * @param array<string, mixed> $extra
     * @return array{state: string, nonce: string, code_verifier: string|null}
     */
    public function issue(string $provider, ?string $codeVerifier = null, array $extra = []): array
    {
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));

        set_transient(
            $this->prefix . $state,
            [
                'provider'      => $provider,
                'nonce'         => $nonce,
                'code_verifier' => $codeVerifier,
            ] + $extra,
            $this->ttlSeconds,
        );

        return ['state' => $state, 'nonce' => $nonce, 'code_verifier' => $codeVerifier];
    }

    /**
     * @return array{provider: string, nonce: string, code_verifier: string|null, extra: array<string, mixed>}|null
     */
    public function consume(string $state): ?array
    {
        if ($state === '') {
            return null;
        }

        $key = $this->prefix . $state;
        $stored = get_transient($key);
        if (!is_array($stored)) {
            return null;
        }

        delete_transient($key);

        $verifier = $stored['code_verifier'] ?? null;

        $extra = [];
        foreach ($stored as $field => $value) {
            if (is_string($field) && !in_array($field, self::OWN_FIELDS, true)) {
                $extra[$field] = $value;
            }
        }

        return [
            'provider'      => (string) ($stored['provider'] ?? ''),
            'nonce'         => (string) ($stored['nonce'] ?? ''),
            'code_verifier' => is_string($verifier) && $verifier !== '' ? $verifier : null,
            'extra'         => $extra,
        ];
    }

    /**
     * A fresh PKCE verifier: 32 random bytes, hex-encoded to 64 characters.
     * Inside RFC 7636's 43–128 range and made only of unreserved characters,
     * so it needs no escaping anywhere it travels.
     */
    public static function newCodeVerifier(): string
    {
        return bin2hex(random_bytes(32));
    }
}
