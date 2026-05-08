<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Biometric;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\BiometricProviderInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\WebAuthn\WebAuthnManager;
use Illuminate\Contracts\Auth\Authenticatable;
use InvalidArgumentException;
use RuntimeException;

class BiometricManager
{
    /**
     * The registered providers.
     *
     * @var array<string, BiometricProviderInterface>
     */
    protected array $providers = [];

    /**
     * Create a new biometric manager instance.
     */
    public function __construct(
        protected WebAuthnManager $webAuthnManager,
    ) {
        $this->registerDefaultProviders();
    }

    /**
     * Get a biometric provider.
     */
    public function provider( string $name = 'webauthn' ): BiometricProviderInterface
    {
        if ( ! isset( $this->providers[ $name ] ) ) {
            throw new InvalidArgumentException( "Biometric provider not found: {$name}" );
        }

        return $this->providers[ $name ];
    }

    /**
     * Register a custom provider.
     */
    public function extend( string $name, BiometricProviderInterface $provider ): void
    {
        $this->providers[ $name ] = $provider;
    }

    /**
     * Check if biometric authentication is available.
     *
     * @param  array<string, mixed>  $deviceInfo
     */
    public function isAvailable( array $deviceInfo ): bool
    {
        foreach ( $this->providers as $provider ) {
            if ( $provider->isAvailable( $deviceInfo ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get available providers for a device.
     *
     * @param  array<string, mixed>  $deviceInfo
     *
     * @return array<string>
     */
    public function getAvailableProviders( array $deviceInfo ): array
    {
        $available = [];

        foreach ( $this->providers as $name => $provider ) {
            if ( $provider->isAvailable( $deviceInfo ) ) {
                $available[] = $name;
            }
        }

        return $available;
    }

    /**
     * Start biometric enrollment with the best available provider.
     *
     * @param  array<string, mixed>  $deviceInfo
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>
     */
    public function startEnrollment( Authenticatable $user, array $deviceInfo, array $options = [] ): array
    {
        $providerName = $options['provider'] ?? $this->selectBestProvider( $deviceInfo );
        $provider     = $this->provider( $providerName );

        $result             = $provider->startEnrollment( $user, $options );
        $result['provider'] = $providerName;

        return $result;
    }

    /**
     * Complete biometric enrollment.
     *
     * @param  array<string, mixed>  $response
     *
     * @return array{success: bool, credential_id: ?string, error: ?string}
     */
    public function completeEnrollment( Authenticatable $user, string $providerName, array $response, string $challenge ): array
    {
        $provider = $this->provider( $providerName );

        return $provider->completeEnrollment( $user, $response, $challenge );
    }

    /**
     * Start biometric authentication.
     *
     * @param  array<string, mixed>  $deviceInfo
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>
     */
    public function startAuthentication( ?Authenticatable $user, array $deviceInfo, array $options = [] ): array
    {
        $providerName = $options['provider'] ?? $this->selectBestProvider( $deviceInfo );
        $provider     = $this->provider( $providerName );

        $result             = $provider->startAuthentication( $user, $options );
        $result['provider'] = $providerName;

        return $result;
    }

    /**
     * Verify biometric authentication.
     *
     * @param  array<string, mixed>  $response
     *
     * @return array{success: bool, user_id: ?int, error: ?string}
     */
    public function verifyAuthentication( string $providerName, array $response, string $challenge ): array
    {
        $provider = $this->provider( $providerName );

        return $provider->verifyAuthentication( $response, $challenge );
    }

    /**
     * Check if user has biometric credentials.
     */
    public function hasCredentials( Authenticatable $user ): bool
    {
        return method_exists( $user, 'hasWebAuthnCredentials' ) && $user->hasWebAuthnCredentials();
    }

    /**
     * Check if user has platform authenticator (built-in biometric).
     */
    public function hasPlatformAuthenticator( Authenticatable $user ): bool
    {
        return method_exists( $user, 'hasPlatformAuthenticators' ) && $user->hasPlatformAuthenticators();
    }

    /**
     * Register default providers.
     */
    protected function registerDefaultProviders(): void
    {
        $this->providers['webauthn'] = new WebAuthnBiometricProvider( $this->webAuthnManager );
    }

    /**
     * Select the best provider for a device.
     */
    protected function selectBestProvider( array $deviceInfo ): string
    {
        // WebAuthn is the primary and most secure option
        if ( isset( $this->providers['webauthn'] ) && $this->providers['webauthn']->isAvailable( $deviceInfo ) ) {
            return 'webauthn';
        }

        // Return first available provider
        foreach ( $this->providers as $name => $provider ) {
            if ( $provider->isAvailable( $deviceInfo)) {
                return $name;
            }
        }

        throw new RuntimeException( 'No biometric provider available for this device');
    }
}
