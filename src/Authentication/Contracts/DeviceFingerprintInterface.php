<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts;

use ArtisanPackUI\SecurityAdvancedAuth\Models\UserDevice;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

interface DeviceFingerprintInterface
{
    /**
     * Generate a device fingerprint from the request.
     *
     * @return array{hash: string, components: array<string, mixed>}
     */
    public function generateFingerprint( Request $request ): array;

    /**
     * Find or create a device for the user based on fingerprint.
     */
    public function findOrCreateDevice( Authenticatable $user, string $fingerprintHash, array $components ): UserDevice;

    /**
     * Update device information on login.
     */
    public function recordDeviceLogin( UserDevice $device, Request $request ): void;

    /**
     * Calculate trust score for a device.
     *
     * @return float Score between 0.0 and 1.0
     */
    public function calculateTrustScore( UserDevice $device ): float;

    /**
     * Check if a device is recognized for a user.
     */
    public function isRecognizedDevice( Authenticatable $user, string $fingerprintHash ): bool;

    /**
     * Check if a device is trusted for a user.
     */
    public function isTrustedDevice( Authenticatable $user, string $fingerprintHash ): bool;

    /**
     * Mark a device as trusted.
     */
    public function trustDevice( UserDevice $device, ?int $expirationDays = null ): void;

    /**
     * Revoke trust from a device.
     */
    public function revokeDeviceTrust( UserDevice $device ): void;

    /**
     * Get all devices for a user.
     *
     * @return \Illuminate\Support\Collection<int, UserDevice>
     */
    public function getUserDevices( Authenticatable $user ): \Illuminate\Support\Collection;

    /**
     * Delete a device.
     */
    public function deleteDevice( UserDevice $device ): void;

    /**
     * Prune inactive devices.
     */
    public function pruneInactiveDevices( int $inactiveDays ): int;

    /**
     * Get the hash algorithm used for fingerprinting.
     */
    public function getHashAlgorithm(): string;
}
