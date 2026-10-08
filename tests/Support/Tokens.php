<?php

declare(strict_types=1);

namespace Guardian\Tests\Support;

use OpenSSLAsymmetricKey;

/**
 * Real RS256 tokens and the JWKS that verifies them.
 *
 * Keypairs are generated per test rather than committed — a fixture here
 * would mean a private key in a public repository.
 *
 * <b>The OPENSSL_CONF trap.</b> openssl_pkey_new() needs a usable openssl.cnf,
 * which some Windows PHP builds lack. {@see keyOrSkip()} skips the test and
 * says why, rather than reporting a green suite that tested the environment.
 */
final class Tokens
{
    public static function keyOrSkip(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            test()->markTestSkipped('OpenSSL could not generate a keypair. Set OPENSSL_CONF.');
        }

        return $key;
    }

    /**
     * @param array<string, mixed> $claims
     */
    public static function sign(OpenSSLAsymmetricKey $key, array $claims, string $kid): string
    {
        $head = self::encode(['alg' => 'RS256', 'kid' => $kid, 'typ' => 'JWT']);
        $payload = self::encode($claims);

        $signature = '';
        openssl_sign($head . '.' . $payload, $signature, $key, OPENSSL_ALGO_SHA256);

        return $head . '.' . $payload . '.' . self::base64Url($signature);
    }

    /** @return array<string, string> */
    public static function jwk(OpenSSLAsymmetricKey $key, string $kid): array
    {
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new \RuntimeException('Could not read the test key.');
        }

        return [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n'   => self::base64Url($details['rsa']['n']),
            'e'   => self::base64Url($details['rsa']['e']),
        ];
    }

    public static function publicPem(OpenSSLAsymmetricKey $key): string
    {
        $details = openssl_pkey_get_details($key);

        return $details === false ? '' : (string) $details['key'];
    }

    /** @param array<string, string> ...$jwks */
    public static function jwksBody(array ...$jwks): string
    {
        return (string) json_encode(['keys' => array_values($jwks)]);
    }

    /** @param array<string, mixed> $data */
    public static function encode(array $data): string
    {
        return self::base64Url((string) json_encode($data));
    }

    public static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
