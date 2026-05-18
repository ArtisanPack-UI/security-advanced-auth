---
title: Biometric Authentication
---

# Biometric Authentication

`BiometricManager` is a thin orchestrator over pluggable `BiometricProviderInterface` implementations. The shipped `WebAuthnBiometricProvider` is the default — it uses WebAuthn under the hood, which is the standard browser-native biometric API.

## API

```php
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Biometric\BiometricManager;

$manager = app( BiometricManager::class );

// Discover what's available on the user's device
$available = $manager->isAvailable( $deviceInfo );  // bool
$providers = $manager->getAvailableProviders( $deviceInfo );

// Enrollment
$options = $manager->startEnrollment( $user, $deviceInfo, [/* options */] );
// (client runs the biometric prompt, returns response)
$result  = $manager->completeEnrollment( $user, 'webauthn', $response, $challenge );

// Authentication
$options = $manager->startAuthentication( $user, $deviceInfo );
// (client prompts user for biometric, returns response)
$result  = $manager->verifyAuthentication( 'webauthn', $response, $challenge );
```

## Using the Livewire component

```blade
<livewire:biometric-manager />
```

Shows registered biometrics, an "Add biometric" button, and delete controls. The host app's JS handles the actual biometric prompt — the component dispatches `start-biometric-enrollment` with the options payload, host JS calls `navigator.credentials.create()`, then dispatches `completeEnrollment` back.

## Provider model

The package ships `WebAuthnBiometricProvider`. Add platform-specific providers by implementing `BiometricProviderInterface`:

```php
namespace App\Auth\Biometric;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\BiometricProviderInterface;

class FaceIdProvider implements BiometricProviderInterface
{
    public function isAvailable( array $deviceInfo ): bool { /* ... */ }
    public function startEnrollment( $user, array $options ): array { /* ... */ }
    public function completeEnrollment( $user, array $response, string $challenge ): array { /* ... */ }
    public function startAuthentication( $user, array $options ): array { /* ... */ }
    public function verifyAuthentication( array $response, string $challenge ): array { /* ... */ }
    public function getName(): string { return 'face-id'; }
}
```

Register:

```php
$manager->extend( 'face-id', new FaceIdProvider() );
```

## Use cases

- **WebAuthn-backed biometric is the right default.** It uses the device's native biometric (Touch ID, Face ID, Windows Hello, Android fingerprint) without needing platform-specific code.
- **Custom biometric providers** make sense for native mobile apps wrapping your Laravel app — pair with platform-specific biometric SDKs (iOS LocalAuthentication, Android BiometricPrompt).
- Don't roll your own biometric crypto. Either use WebAuthn or use a vetted platform SDK; never invent.
