<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Biometric;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\BiometricProviderInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\WebAuthn\WebAuthnManager;
use Illuminate\Contracts\Auth\Authenticatable;

class WebAuthnBiometricProvider implements BiometricProviderInterface
{
    /**
     * Create a new provider instance.
     */
    public function __construct(
        protected WebAuthnManager $webAuthnManager,
    ) {
    }

    /**
     * Get the provider name.
     */
    public function getName(): string
    {
        return 'webauthn';
    }

    /**
     * Check if biometric authentication is available.
     */
    public function isAvailable( array $deviceInfo ): bool
    {
        // WebAuthn with platform authenticator is available on modern browsers/devices
        // Check for platform authenticator support hints
        $hasPlatformAuthenticator = $deviceInfo['has_platform_authenticator'] ?? false;

        // If we have explicit info, use it
        if ( isset( $deviceInfo['has_platform_authenticator'] ) ) {
            return $hasPlatformAuthenticator;
        }

        // Otherwise, assume modern devices support it
        $userAgent = $deviceInfo['user_agent'] ?? '';

        // Check for modern browsers that support WebAuthn platform authenticators
        $supportsWebAuthn = preg_match( '/Chrome\/[89]\d|Firefox\/[89]\d|Safari\/1[456]/i', $userAgent );

        // Check for devices likely to have biometric
        $hasBiometricHardware =
            preg_match( '/iPhone|iPad|Mac OS|Windows NT 10/i', $userAgent ) ||
            preg_match( '/Android.*Chrome/i', $userAgent );

        return $supportsWebAuthn && $hasBiometricHardware;
    }

    /**
     * Start biometric enrollment.
     */
    public function startEnrollment( Authenticatable $user, array $options = [] ): array
    {
        // Force platform authenticator for biometric
        $options['authenticator_attachment'] = 'platform';

        return $this->webAuthnManager->generateRegistrationOptions( $user, $options );
    }

    /**
     * Complete biometric enrollment.
     */
    public function completeEnrollment( Authenticatable $user, array $response, string $challenge ): array
    {
        return $this->webAuthnManager->verifyRegistration( $user, $response, $challenge );
    }

    /**
     * Start biometric authentication.
     */
    public function startAuthentication( ?Authenticatable $user = null, array $options = [] ): array
    {
        return $this->webAuthnManager->generateAuthenticationOptions( $user, $options );
    }

    /**
     * Verify biometric authentication.
     */
    public function verifyAuthentication( array $response, string $challenge ): array
    {
        return $this->webAuthnManager->verifyAuthentication( $response, $challenge );
    }

    /**
     * Get supported biometric types.
     */
    public function getSupportedTypes(): array
    {
        return [
            'fingerprint',
            'face',
            'iris',
        ];
    }

    /**
     * Check if liveness detection is supported.
     */
    public function supportsLivenessDetection(): bool
    {
        // WebAuthn doesn't guarantee liveness detection
        // It depends on the authenticator implementation
        return false;
    }

    /**
     * Get fallback authentication methods.
     */
    public function getFallbackMethods(): array
    {
        return [
            'password',
            'security_key',
            '2fa',
        ];
    }
}
