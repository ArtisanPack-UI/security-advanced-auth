# ArtisanPack UI — Security Advanced Auth Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-06-14

### Added

- Laravel 13 support — widened `illuminate/support` constraint to `^10.0|^11.0|^12.0|^13.0` so the package installs cleanly on Laravel 13 (and unblocks Laravel 13 adoption for consumers pulling this in via `artisanpack-ui/security-full`). Closes [#15](https://github.com/ArtisanPack-UI/security-advanced-auth/issues/15).
- CI: new Laravel × Livewire × PHP test matrix covering Laravel 12 and 13 across PHP 8.2–8.4 and Livewire 3.6 / 4.0, with incompatible combinations excluded (L13 requires PHP 8.3+ and Livewire 4).
- CI: `release/**` branches now trigger the workflow on push and pull request, so release-branch PRs are covered.

### Changed

- Widened `orchestra/testbench` constraint to `^10.2|^11.0` so the dev test environment can resolve a Testbench compatible with Laravel 13.
- Widened Pest constraints (`pestphp/pest` to `^3.8|^4.0`, `pestphp/pest-plugin-laravel` to `^3.2|^4.0`) so the Laravel 13 install leg can resolve Pest 4 (pest-plugin-laravel v3 caps Laravel at `^12`).

### Fixed

- `SecurityAdvancedAuth::version()` now returns `1.0.1` instead of the stale placeholder `0.1.0`.

## [1.0.0] - 2026-05-18

### Added

- Initial release of the standalone Security Advanced Auth package, extracted from `artisanpack-ui/security` 1.x as part of the Security 2.0 package split.
- **WebAuthn / FIDO2** — `WebAuthnManager` (577 lines) with registration + authentication options generation, response verification, and credential CRUD. Supports passkeys, security keys, and platform authenticators via the `WebAuthnInterface` contract.
- **SSO** — `SsoManager` (302 lines) supporting SAML 2.0, OIDC, and LDAP. `SsoConfiguration` model for per-IdP definitions. SP metadata endpoint, SSO + SLO flows. `SsoUser` value object.
- **Social authentication** — `SocialAuthManager` (363 lines) with 8 shipped OAuth providers (`AppleProvider`, `FacebookProvider`, `GitHubProvider`, `GoogleProvider`, `LinkedInProvider`, `MicrosoftProvider`, `GenericOidcProvider`, plus `AbstractOAuth2Provider` and `AbstractOidcProvider` base classes for custom providers). `SocialUser` value object, `SocialIdentity` model for link storage, account-linking helpers.
- **Biometric authentication** — `BiometricManager` (196 lines) with the pluggable `BiometricProviderInterface`. `WebAuthnBiometricProvider` ships as the default implementation.
- **Device fingerprinting** — `DeviceFingerprintService` for fingerprint generation, `UserDevice` model for known-device tracking, `DeviceFingerprint` model for raw fingerprint storage.
- **Suspicious activity detection** — `SuspiciousActivityService` covering 11 auth-flow patterns (`brute_force`, `impossible_travel`, `anomalous_login`, `proxy_detected`, `tor_detected`, `datacenter_ip`, `multiple_failures`, `device_change`, `unusual_time`, `session_hijacking`, `credential_stuffing`).
- **Livewire components** (5): `WebAuthnCredentialsManager`, `BiometricManager`, `DeviceManager`, `SocialAccountsManager`, `SuspiciousActivityList`. All with shipped Blade views in plain HTML + Tailwind, plus view-render smoke tests.
- **HTTP controllers** (3): `SocialAuthController`, `SsoController`, `WebAuthnController`. Thin wrappers that delegate to the corresponding manager.
- **Routes** (`routes/auth.php`): 12 endpoints covering social OAuth (redirect / callback / unlink), SSO (login / callback / logout / logout-callback / metadata), and WebAuthn (registration options / verify, authentication options / verify). Configurable prefix + per-group middleware.
- **Eloquent models** (7): `DeviceFingerprint`, `SocialIdentity`, `SsoConfiguration`, `SsoIdentity`, `SuspiciousActivity`, `UserDevice`, `WebAuthnCredential`.
- **Migrations** (7): full schema for the models above.
- **Service contracts** (6): `BiometricProviderInterface`, `DeviceFingerprintInterface`, `SocialProviderInterface`, `SsoProviderInterface`, `SuspiciousActivityDetectorInterface`, `WebAuthnInterface`.
- `SecurityAdvancedAuth` Facade and `security_advanced_auth()` helper.

### Fixed

- Closes [#12](https://github.com/ArtisanPack-UI/security-advanced-auth/issues/12) — wrote the 5 missing Livewire Blade views; without them every Livewire render threw `View not found` in production.
- Closes [#13](https://github.com/ArtisanPack-UI/security-advanced-auth/issues/13) — shipped `routes/auth.php` with the 12 callback endpoints plus the 3 thin HTTP controllers. Without these, social OAuth / SSO / WebAuthn flows had no out-of-the-box wiring and consumers had to write controllers from scratch.
- `SuspiciousActivityList` referenced model constants that don't exist (`TYPE_UNUSUAL_LOCATION`, `TYPE_UNUSUAL_DEVICE`, etc.). Replaced with the actual constants the model defines.
- Service provider now publishes the views (tag: `security-advanced-auth-views`) so consumers can customize them.
- Added `LivewireServiceProvider` to the test base case so Livewire component tests can mount.
- Author email normalized to `support@artisanpackui.dev`.
- License switched from GPL-3.0-or-later to MIT to match the rest of the ecosystem.

### Removed

- This package contains the enterprise auth content previously bundled in `artisanpack-ui/security` 1.x. See the [`artisanpack-ui/security` UPGRADE guide](https://github.com/ArtisanPack-UI/security/blob/main/UPGRADE.md) for migration instructions from 1.x.
