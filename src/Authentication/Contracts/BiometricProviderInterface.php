<?php

/**
 * BiometricProviderInterface contract.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface BiometricProviderInterface
{
    /**
     * Get the provider name (webauthn, native, etc.).
     */
    public function getName(): string;

    /**
     * Check if biometric authentication is available on this device/platform.
     *
     * @param  array<string, mixed>  $deviceInfo
     */
    public function isAvailable( array $deviceInfo ): bool;

    /**
     * Start the biometric enrollment process.
     *
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>
     */
    public function startEnrollment( Authenticatable $user, array $options = [] ): array;

    /**
     * Complete the biometric enrollment process.
     *
     * @param  array<string, mixed>  $response
     *
     * @return array{success: bool, credential_id: ?string, error: ?string}
     */
    public function completeEnrollment( Authenticatable $user, array $response, string $challenge ): array;

    /**
     * Start the biometric authentication process.
     *
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>
     */
    public function startAuthentication( ?Authenticatable $user = null, array $options = [] ): array;

    /**
     * Verify the biometric authentication response.
     *
     * @param  array<string, mixed>  $response
     *
     * @return array{success: bool, user_id: ?int, error: ?string}
     */
    public function verifyAuthentication( array $response, string $challenge ): array;

    /**
     * Get the supported biometric types for this provider.
     *
     * @return array<string>
     */
    public function getSupportedTypes(): array;

    /**
     * Check if liveness detection is supported.
     */
    public function supportsLivenessDetection(): bool;

    /**
     * Get fallback authentication methods.
     *
     * @return array<string>
     */
    public function getFallbackMethods(): array;
}
