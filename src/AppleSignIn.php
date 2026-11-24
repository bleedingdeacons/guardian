<?php

declare(strict_types=1);

namespace Guardian;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * A Sign in with Apple token whose signature checked out, with or without an
 * email address.
 *
 * <b>Apple sends the email reliably only on the first authorisation.</b> A
 * returning user's token may carry no `email` claim at all, so the address
 * cannot be the key a consumer finds them by. `sub` is: Apple's stable user id
 * for this person and this app, present on every token. A consumer links it to
 * its own record the first time (when the email is there to match on) and
 * finds the record by `sub` from then on.
 *
 * Like {@see VerifiedIdentity}, this is not yet an authorisation. Who may sign
 * in is the consumer's decision.
 *
 * `email` is set only when the token carried one and Apple marked it
 * verified, and is lower-cased. `isPrivateRelay` says the address (if any) is
 * an `@privaterelay.appleid.com` forwarding address, which matches nobody a
 * consumer already knows.
 */
final readonly class AppleSignIn
{
    public function __construct(
        public string $sub,
        public ?string $email,
        public bool $isPrivateRelay,
    ) {
        if ($sub === '') {
            throw new \InvalidArgumentException('An Apple sign-in needs a non-empty sub.');
        }
    }
}
