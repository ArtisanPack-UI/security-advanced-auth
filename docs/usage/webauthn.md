---
title: WebAuthn / FIDO2
---

# WebAuthn / FIDO2

`WebAuthnManager` (577 lines) handles registration + authentication ceremonies for passkeys, security keys, and platform authenticators. The package ships interface-level — the actual WebAuthn library is the consumer's choice. Wire a concrete implementation in your service provider.

## Endpoints

| Method | Path | Controller method |
|---|---|---|
| POST | `/auth/webauthn/register/options` | `WebAuthnController::registerOptions` |
| POST | `/auth/webauthn/register/verify` | `WebAuthnController::registerVerify` |
| POST | `/auth/webauthn/authenticate/options` | `WebAuthnController::authenticateOptions` |
| POST | `/auth/webauthn/authenticate/verify` | `WebAuthnController::authenticateVerify` |

Prefix and middleware configurable in `config('artisanpack.security-advanced-auth.routes.webauthn')`.

## Registration flow

1. User triggers "Add passkey" in the UI (`WebAuthnCredentialsManager` Livewire component).
2. Component dispatches `start-webauthn-registration`.
3. Host JS fetches options: `POST /auth/webauthn/register/options`.
4. Host JS calls `navigator.credentials.create({publicKey: options})`.
5. Browser shows the authenticator prompt; user authenticates.
6. Host JS POSTs the response to `/auth/webauthn/register/verify`.
7. Server stores the credential as a `WebAuthnCredential` row.

## Authentication flow

1. Login form presents "Sign in with passkey" alongside password.
2. Host JS fetches: `POST /auth/webauthn/authenticate/options`. Pass `user_id` or omit for discovery flows.
3. Host JS calls `navigator.credentials.get({publicKey: options})`.
4. Host JS POSTs the response to `/auth/webauthn/authenticate/verify`.
5. Server verifies, returns user info, logs the user in.

## Programmatic API

```php
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\WebAuthn\WebAuthnManager;

$manager = app( WebAuthnManager::class );

// Registration
$options = $manager->generateRegistrationOptions( $user, [/* options */] );
$result  = $manager->verifyRegistration( $user, $response, $challenge );

// Authentication
$options = $manager->generateAuthenticationOptions( $user );
$result  = $manager->verifyAuthentication( $response, $challenge );

// Credential management
$creds = $manager->getCredentials( $user );    // Collection<WebAuthnCredential>
$manager->deleteCredential( $user, $credentialId );
$manager->updateCredential( $user, $credentialId, ['name' => 'New name'] );
```

## Passwordless / discovery

`generateAuthenticationOptions(null)` produces options without a specific user — the browser surfaces all stored passkeys and the user picks. Useful for "sign in with passkey" buttons that don't ask for username first.

## Relying Party

The Relying Party ID is your app's domain (e.g. `app.example.com`). Configure in `config('artisanpack.security-advanced-auth.webauthn.relying_party')` — defaults derive from `APP_URL`.

The RP ID is locked at registration time. Changing it later invalidates all existing credentials. Be deliberate about this in production.

## Live tests / e2e

For server-side flow tests, mock the underlying WebAuthn library. For browser-driven tests, [virtual authenticators](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/) let Playwright / Cypress simulate the authenticator without needing physical hardware.
