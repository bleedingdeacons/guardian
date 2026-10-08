<?php

declare(strict_types=1);

namespace Guardian;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * An email address a provider has told us, with a verified signature, that
 * this person controls.
 *
 * It is not yet an authorisation. Whether the address belongs to somebody
 * allowed in — a Unity member, a responder — is the consumer's decision; this
 * only says the person at the other end is who the address says.
 *
 * `sub` is the provider's stable user id, kept so a future change in how an
 * address is spelt can still be joined back to the same person.
 *
 * `providerEmail` is the address as the provider actually delivered it, and
 * differs from `email` only when the provider anonymised it (a Facebook relay
 * address, possibly Apple's private relay). Null in the common case.
 */
final class VerifiedIdentity
{
    public function __construct(
        public readonly string $email,
        public readonly string $provider,
        public readonly string $sub,
        public readonly ?string $providerEmail = null,
    ) {
    }
}
