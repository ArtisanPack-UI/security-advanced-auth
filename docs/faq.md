---
title: FAQ
---

# FAQ

## Does this package require `artisanpack-ui/security`?

No. Security Advanced Auth is standalone — it only pulls `artisanpack-ui/core` beyond standard Laravel.

## Does it actually do WebAuthn / SAML / OAuth, or is it just glue?

Both. The package defines the contracts, models, controllers, routes, and Livewire UI. The actual cryptographic / protocol heavy-lifting is delegated to whichever library the consumer wires in — this avoids forcing one heavy library on everyone. See [Wiring a WebAuthn library](advanced/webauthn-library.md) and [Custom SSO providers](advanced/custom-sso-providers.md) for the integration patterns.

For the social OAuth providers (8 shipped), the package handles the full flow internally — no external library needed for the common providers.

## Do I need both `security-auth` and `security-advanced-auth`?

They're complementary:

- `security-auth` covers everyday auth security — 2FA, password policy, lockout, sessions.
- `security-advanced-auth` covers enterprise / passwordless — WebAuthn, SSO, social login, biometric.

Most apps want both. The split exists so apps that only need one path don't get the dependencies of the other.

## Can I use just one social provider?

Yes. Register only the providers you actually use. The unregistered providers don't respond to the callback routes (they throw `RuntimeException`).

## Can I disable the bundled routes?

Yes — `'routes' => ['enabled' => false]` in config. Then wire your own controllers using the manager methods directly. Useful if you need bespoke URL structures or middleware combinations that don't fit the shipped routes.

## How does device fingerprinting handle GDPR?

The fingerprint hash + IP + UA are tied to the user via `UserDevice`. When the user is deleted, the rows go with them. The fingerprinting itself is for security purposes (account-takeover detection), which is generally permitted under GDPR's legitimate-interest basis. Document the practice in your privacy policy.

For users who object specifically to fingerprinting, allow opt-out:

```php
if ( $user->privacy_settings['device_fingerprint'] ?? true ) {
    $service->recordDevice( $user, $fingerprint, $request );
}
```

## Why is suspicious activity detection in this package AND in security-analytics?

Two different scopes:

- **This package's `SuspiciousActivityService`** is auth-flow specific — impossible travel during login, proxy detection at sign-in time, etc. Tightly coupled to the auth event stream.
- **`security-analytics`'s service** is a higher-level audit surface — any activity, not just auth. Includes a broader catalogue of patterns.

Both can coexist. The migration table-name conflict (both want `suspicious_activities`) is tracked as a separate issue — for now, install only one or skip the duplicate migration.

## What if a user loses their WebAuthn device?

The user needs an alternative recovery path — they can't authenticate with the lost device anymore. Common patterns:

- Have multiple credentials registered (security key + platform passkey)
- Pair with `security-auth`'s 2FA recovery codes
- Account recovery flow with identity verification

Don't make WebAuthn the only credential type. Recovery is a deliberate UX decision.

## Can I use this with Laravel Sanctum / Passport?

Yes. The package's flows are session-based (WebAuthn ceremonies, OAuth callbacks). Once the user is authenticated, your normal Sanctum / Passport token flow continues. For pure API auth without sessions, you'd need to wire WebAuthn challenges directly into your token-issuance endpoint.

## Why are the migrations risky to run alongside security-analytics?

Both packages ship a `create_suspicious_activities_table` migration that creates the same table. Run one of them or skip the duplicate. Long-term fix: both migrations get `Schema::hasTable()` guards.

## Where do I configure the WebAuthn Relying Party?

```php
'webauthn' => [
    'relying_party' => [
        'id'   => 'app.example.com',
        'name' => 'My App',
    ],
],
```

The RP ID is locked at credential registration time — changing it invalidates existing credentials. Pick deliberately; document the choice.
