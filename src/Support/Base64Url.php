<?php

declare(strict_types=1);

namespace Guardian\Support;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * RFC 4648 §5 base64url, as JWTs, JWKs and PKCE challenges use it: '+' and
 * '/' swapped for '-' and '_', and the '=' padding dropped.
 *
 * Internal to Guardian. Fellowship and Reach each keep their own copy for the
 * session cookies, attempt tokens and FCM assertions that have nothing to do
 * with OAuth; a consumer reaching for this one would tie those to Guardian's
 * major version for no gain.
 *
 * @internal
 */
trait Base64Url
{
    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Null on a string that does not decode, so "did this decode" can be told
     * apart from "it decoded to nothing".
     */
    protected function base64UrlDecodeOrNull(string $data): ?string
    {
        $pad = strlen($data) % 4;
        if ($pad > 0) {
            $data .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        return $decoded === false ? null : $decoded;
    }

    /**
     * The empty string on failure, for JWT segments, where downstream parsing
     * fails either way.
     */
    protected function base64UrlDecode(string $data): string
    {
        return $this->base64UrlDecodeOrNull($data) ?? '';
    }
}
