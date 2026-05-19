---
title: Device Fingerprinting
---

# Device Fingerprinting

`DeviceFingerprintService` generates per-device fingerprints, tracks known / trusted devices, and flags unknown devices. Pair with the `DeviceManager` Livewire component for the UI.

## How fingerprinting works

The fingerprint is a stable hash over a combination of:

- User-Agent string
- Accept-Language header
- Screen resolution (when JS-provided)
- Color depth (when JS-provided)
- Timezone offset (when JS-provided)
- Canvas / WebGL fingerprint (when JS-provided)

The hash is stable within a browser but distinct across devices. Not unique enough to be reliably privacy-invasive (multiple users on the same browser hash identically), but unique enough to detect "user signed in from a never-before-seen device."

## API

```php
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Device\DeviceFingerprintService;

$service = app( DeviceFingerprintService::class );

// Generate from the current request
$fingerprint = $service->fingerprint( $request, $clientHints = [] );

// Look up
$device = $service->findUserDevice( $user, $fingerprint );  // ?UserDevice

// Record on successful login
$device = $service->recordDevice( $user, $fingerprint, $request );

// Trust / untrust
$service->trustDevice( $device );
$service->untrustDevice( $device );

// Revoke (deletes the row — user has to re-establish trust on next login)
$service->revokeDevice( $device );
```

## Trust period

New devices start untrusted. Use `DeviceManager` to let users mark a device as trusted from their security settings page. Or auto-trust after N successful logins from the same fingerprint:

```php
'device_fingerprint' => [
    'auto_trust_after_logins' => 3,
],
```

## Per-app integration

The service is data-only — it doesn't gate access. To gate access on device trust:

```php
$fingerprint = $service->fingerprint( $request, $clientHints );
$device = $service->findUserDevice( $user, $fingerprint );

if ( ! $device || ! $device->trusted ) {
    // Require step-up authentication, additional verification, or notify the user
}
```

Or wire a middleware that does this check on protected routes.

## Livewire UI

```blade
<livewire:device-manager />
```

Lists known devices with trust state, IP, last seen, OS / browser. Trust / revoke buttons per device, plus "revoke all other devices."

## Privacy considerations

Device fingerprints are a soft form of cross-session identifier. In jurisdictions with strict privacy laws (EU, California), document fingerprinting in your privacy policy and offer opt-out. Fingerprinting for security purposes (fraud / account takeover detection) is generally permissible — fingerprinting for marketing / tracking is not.

The `UserDevice` row stores: fingerprint hash, IP at registration, user agent, OS, browser, last-seen-at. No raw biometric data, no precise geolocation. Easy to comply with subject access / erasure requests — delete the user, the rows go with them.
