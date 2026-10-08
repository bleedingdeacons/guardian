<?php

declare(strict_types=1);

namespace Guardian\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use Guardian\Credentials\CredentialStore;

/**
 * The client id and secret fields for each provider a consumer offers, for
 * embedding in that consumer's own settings page.
 *
 * <b>A section, not a page.</b> Each plugin's settings screen carries far
 * more than OAuth — push credentials, retention, out-of-hours windows — and a
 * library has no menu of its own to hang a page on. So the page keeps its
 * form, its nonce, its capability check and its redirect, calls
 * {@see render()} inside the form and {@see save()} inside its handler, and
 * this owns only the provider rows.
 *
 * <b>Secrets are write-only from here.</b> A stored secret is never rendered
 * back into the form: a screen that redisplays a credential puts it in every
 * screenshot, screen-share and browser form cache. Submitting the field empty
 * leaves what is stored alone — the normal case for anyone editing something
 * else on the page — and clearing one is an explicit tick.
 *
 * Field names carry the consumer's prefix, so the section cannot collide with
 * the page's own fields.
 */
final class ProviderCredentialsSection
{
    /**
     * @param list<ProviderField> $fields
     */
    public function __construct(
        private readonly CredentialStore $credentials,
        private readonly array $fields,
        private readonly string $fieldPrefix = '',
    ) {
    }

    public function render(): void
    {
        $this->printAssets();

        foreach ($this->fields as $field) {
            $this->renderProvider($field);
        }
    }

    /**
     * Write a submitted form into the credential store.
     *
     * Takes the raw request array — `$_POST` as WordPress delivers it, slashed
     * by wp_magic_quotes() — so the page cannot forget to unslash. A client id
     * is plain text; a secret is only trimmed, because sanitising a credential
     * can change it.
     *
     * @param array<array-key, mixed> $post
     */
    public function save(array $post): void
    {
        foreach ($this->fields as $field) {
            $provider = $field->provider;

            $this->credentials->setClientId(
                $provider,
                sanitize_text_field($this->posted($post, $this->fieldName('client_id', $provider))),
            );

            if (!$field->hasSecret) {
                continue;
            }

            if (!empty($post[$this->fieldName('clear_secret', $provider)])) {
                $this->credentials->setClientSecret($provider, '');
                continue;
            }

            $secret = trim($this->posted($post, $this->fieldName('client_secret', $provider)));
            if ($secret !== '') {
                $this->credentials->setClientSecret($provider, $secret);
            }
        }
    }

    /**
     * The form field name for one of a provider's inputs.
     *
     * @param 'client_id'|'client_secret'|'clear_secret' $kind
     */
    public function fieldName(string $kind, string $provider): string
    {
        return $this->fieldPrefix . $kind . '_' . $provider;
    }

    private function renderProvider(ProviderField $field): void
    {
        $provider = $field->provider;
        $idName = $this->fieldName('client_id', $provider);

        echo '<h3>' . esc_html($field->label) . '</h3>';
        echo '<table class="form-table" role="presentation"><tbody>';

        if ($field->redirectUri !== '') {
            $redirectId = $this->fieldPrefix . 'redirect_' . $provider;
            echo '<tr><th scope="row">' . esc_html__('Redirect URI', 'guardian') . '</th><td>';
            echo '<code class="guardian-copyable" id="' . esc_attr($redirectId) . '">' . esc_html($field->redirectUri) . '</code>';
            echo '<button type="button" class="button button-secondary guardian-copy-btn" data-clipboard-target="'
                . esc_attr($redirectId) . '">' . esc_html__('Copy', 'guardian') . '</button>';
            echo '</td></tr>';
        }

        echo '<tr><th scope="row"><label for="' . esc_attr($idName) . '">'
            . esc_html($field->idLabel !== '' ? $field->idLabel : __('Client ID', 'guardian')) . '</label></th><td>';
        echo '<input type="text" name="' . esc_attr($idName) . '" id="' . esc_attr($idName)
            . '" class="regular-text" autocomplete="off" value="'
            . esc_attr($this->credentials->getClientId($provider)) . '">';
        echo '</td></tr>';

        if ($field->hasSecret) {
            $this->renderSecret($field);
        }

        if ($field->help !== '') {
            echo '<tr><td colspan="2"><p class="description">' . esc_html($field->help) . '</p></td></tr>';
        }

        echo '</tbody></table>';
    }

    private function renderSecret(ProviderField $field): void
    {
        $provider = $field->provider;
        $secretName = $this->fieldName('client_secret', $provider);
        $stored = $this->credentials->getClientSecret($provider) !== '';

        echo '<tr><th scope="row"><label for="' . esc_attr($secretName) . '">'
            . esc_html($field->secretLabel !== '' ? $field->secretLabel : __('Client secret', 'guardian')) . '</label></th><td>';
        echo '<input type="password" name="' . esc_attr($secretName) . '" id="' . esc_attr($secretName)
            . '" class="regular-text" autocomplete="new-password" value="" placeholder="'
            . esc_attr($stored ? __('Saved — leave blank to keep', 'guardian') : '') . '">';
        echo '<p class="description">' . esc_html(
            $stored
                ? __('A secret is stored.', 'guardian')
                : sprintf(
                    /* translators: %s: provider name, e.g. Google */
                    __('No secret is stored — %s sign-in will not work.', 'guardian'),
                    $field->label,
                )
        ) . '</p>';

        if ($stored) {
            echo '<label><input type="checkbox" name="' . esc_attr($this->fieldName('clear_secret', $provider))
                . '" value="1"> ' . esc_html__('Clear the stored secret', 'guardian') . '</label>';
        }

        echo '</td></tr>';
    }

    /**
     * @param array<array-key, mixed> $post
     */
    private function posted(array $post, string $name): string
    {
        $value = $post[$name] ?? '';

        return is_string($value) ? (string) wp_unslash($value) : '';
    }

    /**
     * The copy buttons' style and script. Printed with every section, and the
     * script binds once per page however many sections render: a second
     * listener would capture "Copied" as the label to restore.
     */
    private function printAssets(): void
    {
        ?>
        <style>
            .guardian-copyable {
                display: inline-block;
                padding: 4px 8px;
                background: #f0f0f1;
                border: 1px solid #c3c4c7;
                border-radius: 3px;
                margin-right: 6px;
                user-select: all;
            }
            .guardian-copy-btn[data-copied="1"] {
                color: #00713c;
                border-color: #00713c;
            }
        </style>
        <script>
            (function () {
                if (window.guardianCopyBound) {
                    return;
                }
                window.guardianCopyBound = true;

                function fallbackCopy(text, done) {
                    var ta = document.createElement('textarea');
                    ta.value = text;
                    ta.setAttribute('readonly', '');
                    ta.style.position = 'absolute';
                    ta.style.left = '-9999px';
                    document.body.appendChild(ta);
                    ta.select();
                    try {
                        document.execCommand('copy');
                        done();
                    } catch (e) {
                        // Leave the value selected so it can be copied by hand.
                    }
                    document.body.removeChild(ta);
                }

                document.addEventListener('click', function (event) {
                    var btn = event.target instanceof Element ? event.target.closest('.guardian-copy-btn') : null;
                    if (!btn) {
                        return;
                    }
                    var target = document.getElementById(btn.getAttribute('data-clipboard-target'));
                    if (!target) {
                        return;
                    }
                    var text = target.textContent.trim();
                    var done = function () {
                        var original = btn.textContent;
                        btn.textContent = <?php echo wp_json_encode(__('Copied', 'guardian')); ?>;
                        btn.setAttribute('data-copied', '1');
                        setTimeout(function () {
                            btn.textContent = original;
                            btn.removeAttribute('data-copied');
                        }, 1500);
                    };
                    if (navigator.clipboard && window.isSecureContext) {
                        navigator.clipboard.writeText(text).then(done, function () {
                            fallbackCopy(text, done);
                        });
                    } else {
                        fallbackCopy(text, done);
                    }
                });
            })();
        </script>
        <?php
    }
}
