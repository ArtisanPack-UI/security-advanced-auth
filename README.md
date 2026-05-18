# ArtisanPack UI — Security Advanced Auth

Enterprise authentication for Laravel: WebAuthn / FIDO2 passwordless auth, SSO (SAML / OIDC / LDAP), social login across 8 providers, biometric authentication, device fingerprinting, and suspicious activity detection.

This package is part of the **ArtisanPack UI Security 2.0** split — the enterprise-auth features previously bundled inside `artisanpack-ui/security` (1.x) live here in 2.0+.

## Features

- **WebAuthn / FIDO2** (`WebAuthnManager`, 577 lines) — registration + authentication options, response verification, credential CRUD. Supports passkeys, security keys, and platform authenticators.
- **SSO** (`SsoManager`, 302 lines) — SAML 2.0, OIDC, LDAP. Configurable per-IdP via `SsoConfiguration` model. SP metadata endpoint, single sign-on + single logout.
- **Social authentication** (`SocialAuthManager`, 363 lines) — OAuth across 8 shipped providers (Apple, Facebook, GitHub, Google, LinkedIn, Microsoft, plus generic OIDC and OAuth2 abstract bases for custom providers).
- **Biometric authentication** (`BiometricManager`) — pluggable provider model, `WebAuthnBiometricProvider` ships as the default.
- **Device fingerprinting** (`DeviceFingerprintService`) — generates device fingerprints, tracks known / trusted devices, flags unknown devices.
- **Suspicious activity detection** (`SuspiciousActivityService`) — auth-flow patterns (impossible travel, proxy detection, Tor detection, datacenter IPs, multiple failures, device changes, session hijacking).
- **Livewire components** (5) — `WebAuthnCredentialsManager`, `BiometricManager`, `DeviceManager`, `SocialAccountsManager`, `SuspiciousActivityList` — all with shipped Blade views in plain HTML + Tailwind.
- **HTTP controllers + routes** — bundled controllers and routes file with callback endpoints for social OAuth, SSO (SAML / OIDC), and WebAuthn ceremonies. Configurable prefix + middleware.
- **Eloquent models** (7) — `DeviceFingerprint`, `SocialIdentity`, `SsoConfiguration`, `SsoIdentity`, `SuspiciousActivity`, `UserDevice`, `WebAuthnCredential`.
- **Migrations** (7) — full schema for the above.
- `SecurityAdvancedAuth` Facade and `security_advanced_auth()` helper.

## Installation

```bash
composer require artisanpack-ui/security-advanced-auth
php artisan migrate
```

> The migrations create tables tied to the `users` table. Run Laravel's default migrations first.

(Optional) Publish the config:

```bash
php artisan vendor:publish --tag=security-advanced-auth-config
```

(Optional) Publish the Livewire views for customization:

```bash
php artisan vendor:publish --tag=security-advanced-auth-views
```

## Quick start

### Mount the Livewire components

```blade
<livewire:webauthn-credentials-manager />
<livewire:biometric-manager />
<livewire:device-manager />
<livewire:social-accounts-manager />
<livewire:suspicious-activity-list />
```

### Wire up a social provider

```php
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialAuthManager;

app( SocialAuthManager::class )->registerProvider( 'google', [
    'client_id'     => env('GOOGLE_CLIENT_ID'),
    'client_secret' => env('GOOGLE_CLIENT_SECRET'),
    'redirect_uri'  => route('security-advanced-auth.social.callback', ['provider' => 'google']),
] );
```

With the default route prefix (`auth`), users can hit `/auth/social/google/redirect` to begin login. The callback at `/auth/social/google/callback` is wired automatically. The prefix is configurable via `artisanpack.security-advanced-auth.routes.prefix`; prefer the named routes (`security-advanced-auth.social.redirect`, `.callback`) when generating URLs.

### Wire up an SSO provider

```php
use ArtisanPackUI\SecurityAdvancedAuth\Models\SsoConfiguration;

SsoConfiguration::create([
    'slug'       => 'corp-saml',
    'name'       => 'Corporate SAML',
    'type'       => 'saml',
    'config'     => [/* IdP-specific config */],
    'is_enabled' => true,
]);
```

With the default route prefix (`auth`), the login URL is `/auth/sso/corp-saml/login` and SAML metadata is at `/auth/sso/corp-saml/metadata`. Prefer the named routes (`security-advanced-auth.sso.login`, `.metadata`) when generating URLs — the prefix is configurable via `artisanpack.security-advanced-auth.routes.prefix`.

### WebAuthn registration

The Livewire `WebAuthnCredentialsManager` component handles the UI side. The host app's JS performs the actual WebAuthn ceremony via `navigator.credentials.create()` against options served by `POST /auth/webauthn/register/options`.

## Documentation

- [Documentation home](docs/home.md)
- [Getting started](docs/getting-started.md)
- [Installation](docs/installation.md)
- [Usage](docs/usage.md)
- [Advanced](docs/advanced.md)
- [FAQ](docs/faq.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Changelog](CHANGELOG.md)

## Requirements

- PHP 8.2+
- Laravel 10 / 11 / 12
- `livewire/livewire: ^3.6 | ^4.0` (for the 5 Livewire components)
- A working `users` table (run Laravel's default migrations first)
- Per-provider deps (e.g. SAML toolkit if you use SAML SSO — leave to the consumer to install)

## Sibling packages

| Package | Scope |
|---|---|
| [`artisanpack-ui/security-full`](https://github.com/ArtisanPack-UI/security-full) | Meta-package — pulls in the full security suite (all six packages below) in a single require |
| [`artisanpack-ui/security`](https://github.com/ArtisanPack-UI/security) | Core: input sanitization, escaping, CSP, security headers |
| [`artisanpack-ui/security-auth`](https://github.com/ArtisanPack-UI/security-auth) | 2FA, password complexity, account lockout, sessions |
| [`artisanpack-ui/rbac`](https://github.com/ArtisanPack-UI/rbac) | Roles, permissions, Gate integration |
| [`artisanpack-ui/secure-uploads`](https://github.com/ArtisanPack-UI/secure-uploads) | File validation, malware scanning, signed-URL serving |
| [`artisanpack-ui/security-analytics`](https://github.com/ArtisanPack-UI/security-analytics) | Event logging, anomaly detection, SIEM, dashboards |
| [`artisanpack-ui/compliance`](https://github.com/ArtisanPack-UI/compliance) | GDPR / CCPA / LGPD compliance tools |

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Please read the [contributing guidelines](CONTRIBUTING.md) before opening an issue or PR.
