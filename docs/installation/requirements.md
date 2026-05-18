---
title: Requirements
---

# Requirements

## PHP

- PHP 8.2+

## Laravel

- Laravel 10 / 11 / 12

## Composer dependencies (pulled in automatically)

- `artisanpack-ui/core: ^1.0`

## Optional dependencies

- **`livewire/livewire: ^3.6 | ^4.0`** — only required for the 5 Livewire components. The manager classes (`WebAuthnManager`, `SsoManager`, `SocialAuthManager`, `BiometricManager`, `DeviceFingerprintService`, `SuspiciousActivityService`) work without Livewire.
- **`web-auth/webauthn-lib`** or similar — `WebAuthnManager` is provider-agnostic; bring whichever WebAuthn library fits your stack and wire it in.
- **SAML / OIDC toolkit per IdP** — `SsoManager` is configuration-driven; install the underlying SAML or OIDC library that matches your IdP.
- **`socialiteproviders/*` packages** — `SocialAuthManager`'s provider list can lean on Socialite providers for the OAuth dance.

The package is intentionally light on hard deps so consumers pick the underlying libraries that fit their environment.

## Database

Any Eloquent-supported driver. Migrations reference `users(id)` — the standard Laravel `users` table must exist.

## External services (per-provider)

| Subsystem | Service |
|---|---|
| Social OAuth | Provider credentials (client ID + secret) per registered provider |
| SAML SSO | IdP metadata or per-app federation config |
| OIDC SSO | IdP discovery URL + client credentials |
| LDAP SSO | LDAP server connection details |
| WebAuthn | None — runs against the host app's domain as the Relying Party |
| Biometric | Browser support (WebAuthn-backed by default) |
