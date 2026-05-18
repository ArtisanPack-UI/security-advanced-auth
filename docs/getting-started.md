---
title: Getting Started
---

# Getting Started

Five minutes from install to a working social login + Livewire dashboard.

## 1. Install

```bash
composer require artisanpack-ui/security-advanced-auth
php artisan migrate
```

> The migrations create 7 tables tied to the `users` table. Run Laravel's default migrations first.

## 2. Register a social provider

In a service provider (e.g. `AppServiceProvider::boot()`):

```php
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialAuthManager;

app( SocialAuthManager::class )->registerProvider( 'google', [
    'client_id'     => env('GOOGLE_CLIENT_ID'),
    'client_secret' => env('GOOGLE_CLIENT_SECRET'),
    'redirect_uri'  => route('security-advanced-auth.social.callback', ['provider' => 'google']),
] );
```

## 3. Add the redirect button

```blade
<a href="{{ route('security-advanced-auth.social.redirect', ['provider' => 'google']) }}">
    Sign in with Google
</a>
```

The user clicks → Google auth screen → Google redirects back to the bundled callback → user is logged in.

## 4. Mount the Livewire components

```blade
<livewire:webauthn-credentials-manager />
<livewire:biometric-manager />
<livewire:device-manager />
<livewire:social-accounts-manager />
<livewire:suspicious-activity-list />
```

Drop these on your user's security settings page.

## 5. (Optional) Wire up SSO

```php
use ArtisanPackUI\SecurityAdvancedAuth\Models\SsoConfiguration;

SsoConfiguration::create([
    'slug'       => 'corp-okta',
    'name'       => 'Corporate Okta',
    'type'       => 'oidc',
    'config'     => [
        'discovery_url' => 'https://corp.okta.com/.well-known/openid-configuration',
        'client_id'     => env('OKTA_CLIENT_ID'),
        'client_secret' => env('OKTA_CLIENT_SECRET'),
    ],
    'is_enabled' => true,
]);
```

Login URL: `/auth/sso/corp-okta/login`.

## 6. (Optional) Add a WebAuthn passkey

The Livewire `WebAuthnCredentialsManager` handles the UI. The actual WebAuthn ceremony is browser JS — host app calls `navigator.credentials.create()` against the options endpoint at `POST /auth/webauthn/register/options`.

## Next steps

- [Usage](usage.md) — per-subsystem reference (WebAuthn, SSO, social, biometric, device, suspicious activity)
- [Advanced](advanced.md) — extending providers, custom flows
- [Installation](installation.md) — full config reference
