---
title: Troubleshooting
---

# Troubleshooting

## `View [security-advanced-auth::livewire.*] not found`

A 0.x bug — the 5 Livewire components didn't have shipped views. Fixed in v1.0. Update if you're on a pre-1.0 build.

## `Class 'OneLogin\Saml2\Auth' not found` / similar for OIDC / LDAP

The package ships interface-level for SSO. You need to install the underlying library (`onelogin/php-saml`, `web-token/jwt-framework`, `directorytree/ldaprecord-laravel`) and wire it into a custom SSO provider. See [Custom SSO providers](advanced/custom-sso-providers.md).

## WebAuthn registration silently fails

Three common causes:

1. **RP ID mismatch.** The Relying Party ID must match your app's domain (or a parent eTLD+1). If you registered against `example.com` and the user visits `app.example.com`, the credential's RP ID has to match. Verify via browser DevTools — the WebAuthn error usually includes the RP ID it tried.
2. **HTTPS required.** Browsers refuse WebAuthn over HTTP except for `localhost`. Make sure dev / staging / production all use HTTPS.
3. **No WebAuthn library wired.** The package ships interface-only — see [Wiring a WebAuthn library](advanced/webauthn-library.md).

## OAuth callback returns 419 (CSRF / expired)

The `state` parameter validation in `SocialAuthController::callback()` checks session state. If sessions are misconfigured (e.g. cross-domain cookies, missing `SESSION_DOMAIN`), the state lookup fails. Verify your session driver + cookie config across the redirect.

## SAML ACS returns 419

SAML POST-from-IdP is rejected by Laravel's CSRF middleware. Exempt the path:

```php
// app/Http/Middleware/VerifyCsrfToken.php
protected $except = [
    'auth/sso/*/callback',
];
```

## OIDC callback returns 500 on first login

Usually the first-time user creation fails because your User model has required fields that aren't supplied by the IdP. Options:

1. Add defaults to the User model's `$attributes` array
2. Override `SsoManager::findOrCreateUser()` (subclass + rebind) to supply the missing fields
3. Switch to a "link-only" flow — only allow SSO for users who already exist

## Tests fail with `no such table: users`

Same fix as security-auth:

```php
beforeEach( function (): void {
    if ( ! Schema::hasTable( 'users' ) ) {
        Schema::create( 'users', function ( Blueprint $table ): void {
            $table->id();
            $table->string( 'name' );
            $table->string( 'email' )->unique();
            $table->timestamp( 'email_verified_at' )->nullable();
            $table->string( 'password' );
            $table->rememberToken();
            $table->timestamps();
        } );
    }
    $this->artisan( 'migrate' );
} );
```

The package's `tests/Feature/Livewire/ComponentRenderTest.php` uses this pattern — copy from there.

## `Class [livewire] does not exist` in tests

The base test case loads `LivewireServiceProvider`. If you've subclassed `TestCase` and overridden `getPackageProviders()`, make sure you still include it.

## Suspicious-activity migration conflicts with security-analytics

Both packages ship a migration creating `suspicious_activities`. Workarounds:

- Install only one
- Or skip the duplicate by listing it in `--exclude` of the migration command
- Or guard the migration with `Schema::hasTable()` (long-term fix tracked as an issue)

## Routes don't show up

Check three things:

1. `'routes.enabled' => true` in config (default `true`)
2. `php artisan route:list --name=security-advanced-auth` shows the registered routes — if not, the package's service provider isn't loading. Check `composer dump-autoload` and that `vendor/autoload.php` is fresh.
3. Conflict with another route at the same path — Laravel registers in order; if your app routes claimed `/auth/social/*` first, theirs win.

## Still stuck?

Open an issue at https://github.com/ArtisanPack-UI/security-advanced-auth/issues with:

- PHP and Laravel versions
- Which subsystem (WebAuthn, SSO, social, biometric, device, suspicious activity)
- Which library you've wired (if applicable) and its version
- The exact error + minimal reproduction
- Config with secrets redacted
