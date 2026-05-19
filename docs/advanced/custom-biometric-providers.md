---
title: Custom Biometric Providers
---

# Custom Biometric Providers

The shipped `WebAuthnBiometricProvider` covers browser-based biometric authentication via WebAuthn — which handles Touch ID, Face ID, Windows Hello, and Android fingerprint without any platform-specific code.

When you need a platform-specific provider (typically inside a native mobile app wrapping your Laravel app), implement `BiometricProviderInterface`.

## The contract

```php
namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts;

interface BiometricProviderInterface
{
    public function getName(): string;
    public function isAvailable( array $deviceInfo ): bool;
    public function startEnrollment( $user, array $options ): array;
    public function completeEnrollment( $user, array $response, string $challenge ): array;
    public function startAuthentication( $user, array $options ): array;
    public function verifyAuthentication( array $response, string $challenge ): array;
}
```

`isAvailable($deviceInfo)` lets the provider decide based on what the client reports (platform, OS version, available authenticators).

## Example: iOS LocalAuthentication wrapper

For a wrapper around iOS LocalAuthentication used by a native iOS app:

```php
namespace App\Auth\Biometric;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\BiometricProviderInterface;

class IosLocalAuthProvider implements BiometricProviderInterface
{
    public function getName(): string
    {
        return 'ios-local-auth';
    }

    public function isAvailable( array $deviceInfo ): bool
    {
        return ( $deviceInfo['platform'] ?? null ) === 'ios'
            && ( $deviceInfo['supports_biometric'] ?? false );
    }

    public function startEnrollment( $user, array $options ): array
    {
        // Server side: generate a challenge, store keyed by the user
        $challenge = bin2hex( random_bytes( 32 ) );

        cache()->put( "biometric_enroll:{$user->id}", $challenge, now()->addMinutes(5) );

        return [
            'challenge'     => $challenge,
            'user_id'       => (string) $user->id,
            'attestation'   => 'direct',
        ];
    }

    public function completeEnrollment( $user, array $response, string $challenge ): array
    {
        $expected = cache()->pull( "biometric_enroll:{$user->id}" );

        if ( ! hash_equals( $expected ?? '', $challenge ) ) {
            return ['success' => false, 'error' => 'Invalid challenge'];
        }

        // Verify the response signature, store the public key
        // (Implementation depends on what the iOS app sends back)
        $publicKey = $response['public_key'] ?? null;

        if ( ! $publicKey ) {
            return ['success' => false, 'error' => 'Missing public key'];
        }

        $user->biometric_public_key = $publicKey;
        $user->biometric_enrolled_at = now();
        $user->save();

        return ['success' => true];
    }

    // ... rest of the interface
}
```

## Registering

```php
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Biometric\BiometricManager;

$this->app->afterResolving( BiometricManager::class, function ( BiometricManager $manager ): void {
    $manager->extend( 'ios-local-auth', new IosLocalAuthProvider() );
} );
```

Now usable:

```php
$manager->provider('ios-local-auth')->startAuthentication( $user, $deviceInfo );
```

## Default provider

Set in config:

```php
'biometric' => ['default_provider' => 'webauthn'],   // or 'ios-local-auth' etc.
```

When the client doesn't specify a provider, `BiometricManager::startEnrollment()` uses the default.

## Conventions

- **Never trust client-asserted biometric state.** Even if a client claims biometric verification succeeded, your server must verify a cryptographic proof. Don't accept "I biometric-authed, trust me" — accept "here's a signed challenge response, verify the signature against the registered public key."
- **Single-use challenges.** `cache()->pull()` over `cache()->get()` to prevent replay.
- **Platform detection.** Use `isAvailable()` to opt out cleanly — better than failing mid-enrollment when the platform doesn't support what you registered.
