---
title: Livewire Components
---

# Livewire Components

Five components ship with Blade views in plain HTML + Tailwind. Drop them on the user's security settings page or wherever makes sense for your UX.

## `<livewire:webauthn-credentials-manager />`

Lists registered passkeys / security keys. "Add passkey" button opens an enrollment modal; "Delete" with confirmation per credential.

Public state:
- `credentials` (array) — list of registered credentials
- `showRegisterModal` (bool)
- `newCredentialName` (string)
- `registrationOptions` (array | null) — options the host JS uses for `navigator.credentials.create()`

Browser-side JS responsibilities:
- Listen for `start-webauthn-registration`
- Call `navigator.credentials.create({publicKey: options})`
- Dispatch `completeRegistration` with the response

## `<livewire:biometric-manager />`

Same shape as the WebAuthn component but for biometric authenticators (Touch ID, Face ID, Windows Hello, Android fingerprint). The default `WebAuthnBiometricProvider` makes biometric registration work through WebAuthn under the hood.

Public state:
- `biometrics` (array)
- `showEnrollModal` (bool)
- `enrollmentOptions` (array | null)
- `platformSupported` (bool) — set to `false` to disable the "Add biometric" button on devices without biometric support

## `<livewire:device-manager />`

Lists known devices with trust / revoke controls. "Revoke all other devices" button.

Public state:
- `devices` (array) — `[{id, name, browser, os, ip_address, last_seen_at, trusted}, ...]`
- `currentDeviceId` (string | null) — highlights the current device
- `revokingDeviceId` (string | null) — staging state for confirmation

## `<livewire:social-accounts-manager />`

Lists linked OAuth providers + "available to link" buttons.

Public state:
- `linkedAccounts` (array) — `[{provider, provider_user_email, linked_at}, ...]`
- `availableProviders` (array of strings) — providers not yet linked
- `unlinkingProvider` (string | null) — staging state for confirmation

## `<livewire:suspicious-activity-list />`

Filterable list of suspicious activity for the user (or all users for admins with the appropriate permission).

Public state:
- `filterSeverity` (string)
- `filterType` (string)

## Customizing views

Publish:

```bash
php artisan vendor:publish --tag=security-advanced-auth-views
```

Publishes the views to `resources/views/vendor/security-advanced-auth/livewire/*.blade.php`. Laravel resolves overrides before the package defaults.

Common customizations:
- Wrap in your design-system components
- Swap modals for a richer modal library
- Add platform-specific icons (Apple, Google, etc. logos for the social manager)
- Customize copy / translations
