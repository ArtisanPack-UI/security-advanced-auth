---
title: Wiring a WebAuthn Library
---

# Wiring a WebAuthn Library

The package's `WebAuthnManager` is intentionally library-agnostic — it defines the contract and the HTTP surface but leaves the actual WebAuthn cryptographic operations to a library of the consumer's choice. This page covers wiring two common options.

## Why no built-in library?

WebAuthn implementations are heavy, version-sensitive, and benefit from consumer control over the underlying library. The choices that fit production at one company don't always fit another. Forcing one would bloat installs and tie the package's version cadence to a third-party library's release cycle.

## Option 1: `web-auth/webauthn-lib`

The most popular PHP WebAuthn library. Install:

```bash
composer require web-auth/webauthn-lib
```

Wire a custom `WebAuthnManager` that delegates to it:

```php
namespace App\Auth;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\WebAuthn\WebAuthnManager as BaseManager;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\Server;

class WebAuthnLibManager extends BaseManager
{
    protected Server $server;

    public function __construct(/* inject the library's Server + supporting services */)
    {
        // ... configure Server with RP, credential loader, validators
    }

    public function generateRegistrationOptions( $user, array $options = [] ): array
    {
        $publicKeyCredentialCreationOptions = $this->server->generatePublicKeyCredentialCreationOptions(
            $this->buildPublicKeyCredentialUserEntity( $user ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $this->buildExcludeCredentials( $user ),
        );

        return $this->serializeOptions( $publicKeyCredentialCreationOptions );
    }

    public function verifyRegistration( $user, array $response, string $challenge ): array
    {
        // ... call $this->server->loadAndCheckAttestationResponse(...)
    }

    // ... rest
}
```

Register your subclass:

```php
$this->app->singleton(
    \ArtisanPackUI\SecurityAdvancedAuth\Authentication\WebAuthn\WebAuthnManager::class,
    \App\Auth\WebAuthnLibManager::class,
);
```

## Option 2: `pragmarx/webauthn-laravel`

Higher-level Laravel-friendly wrapper. Install:

```bash
composer require pragmarx/webauthn-laravel
```

Wrap its Facade calls similarly — the same pattern: subclass `WebAuthnManager` and delegate.

## Cross-package coordination

The `BiometricManager`'s default `WebAuthnBiometricProvider` uses the same `WebAuthnManager` under the hood. Wire `WebAuthnManager` once; both surfaces benefit.

## What you keep from the package

Even when wiring your own WebAuthn library:

- The Eloquent models (`WebAuthnCredential`) — stable schema, no library coupling
- The shipped controllers and routes — they call `WebAuthnManager` interface methods, your override transparently replaces the implementation
- The `WebAuthnCredentialsManager` Livewire component + view
- The cross-package integration with `BiometricManager`

Your custom code is concentrated in the manager subclass.

## Reference Relying Party

```php
'webauthn' => [
    'relying_party' => [
        'id'   => env('WEBAUTHN_RP_ID'),
        'name' => env('WEBAUTHN_RP_NAME'),
    ],
],
```

The RP ID must match the eTLD+1 your app runs on. For `app.example.com`, use `example.com` (so subdomains share credentials) or `app.example.com` (locked to that subdomain). Document the choice in your security runbook — it's hard to change later.
