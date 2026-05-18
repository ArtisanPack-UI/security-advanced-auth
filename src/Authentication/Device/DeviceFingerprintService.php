<?php

/**
 * DeviceFingerprintService device fingerprinting service.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Device;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\DeviceFingerprintInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Models\DeviceFingerprint;
use ArtisanPackUI\SecurityAdvancedAuth\Models\UserDevice;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;

class DeviceFingerprintService implements DeviceFingerprintInterface
{
    /**
     * Generate a device fingerprint from the request.
     */
    public function generateFingerprint( Request $request ): array
    {
        $config     = config( 'artisanpack.security-advanced-auth.device_fingerprinting.components', [] );
        $components = [];

        // User Agent
        if ( $config['user_agent'] ?? true ) {
            $components['user_agent'] = $request->userAgent();
        }

        // Accept-Language header
        if ( $config['accept_language'] ?? true ) {
            $components['accept_language'] = $request->header( 'Accept-Language' );
        }

        // Screen resolution (from header or session)
        if ( $config['screen_resolution'] ?? true ) {
            $components['screen_resolution'] = $request->header( 'X-Screen-Resolution' )
                ?? session( 'device_screen_resolution' );
        }

        // Timezone (from header or session)
        if ( $config['timezone'] ?? true ) {
            $components['timezone'] = $request->header( 'X-Timezone' )
                ?? session( 'device_timezone' );
        }

        // IP subnet (first 3 octets for IPv4)
        $ip = $request->ip();
        if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            $parts                   = explode( '.', $ip );
            $components['ip_subnet'] = implode( '.', array_slice( $parts, 0, 3 ) );
        }

        // Accept headers
        $components['accept_encoding'] = $request->header( 'Accept-Encoding' );
        $components['accept']          = $request->header( 'Accept' );

        // Generate hash
        $algorithm = config( 'artisanpack.security-advanced-auth.device_fingerprinting.hash_algorithm', 'sha256' );
        $hash      = hash( $algorithm, json_encode( $components ) );

        return [
            'hash'       => $hash,
            'components' => $components,
        ];
    }

    /**
     * Find or create a device for the user.
     */
    public function findOrCreateDevice( Authenticatable $user, string $fingerprintHash, array $components ): UserDevice
    {
        $device = UserDevice::where( 'user_id', $user->getAuthIdentifier() )
            ->where( 'fingerprint_hash', $fingerprintHash )
            ->first();

        if ( $device ) {
            return $device;
        }

        // Parse user agent for device info
        $userAgent  = $components['user_agent'] ?? '';
        $deviceInfo = $this->parseUserAgent( $userAgent );

        return UserDevice::create( [
            'user_id'          => $user->getAuthIdentifier(),
            'fingerprint_hash' => $fingerprintHash,
            'type'             => $deviceInfo['type'],
            'browser'          => $deviceInfo['browser'],
            'browser_version'  => $deviceInfo['browser_version'],
            'os'               => $deviceInfo['os'],
            'os_version'       => $deviceInfo['os_version'],
        ] );
    }

    /**
     * Record a device login.
     */
    public function recordDeviceLogin( UserDevice $device, Request $request ): void
    {
        $location = $this->getLocationFromRequest( $request );
        $device->recordLogin( $request->ip(), $location );

        // Store fingerprint snapshot
        $fingerprint = $this->generateFingerprint( $request );
        DeviceFingerprint::create( [
            'device_id'        => $device->id,
            'fingerprint_hash' => $fingerprint['hash'],
            'components'       => $fingerprint['components'],
            'confidence_score' => 1.0,
        ] );
    }

    /**
     * Calculate trust score for a device.
     */
    public function calculateTrustScore( UserDevice $device ): float
    {
        $score   = 0.0;
        $factors = 0;

        // Login count factor (max 0.3)
        $loginScore = min( 0.3, $device->login_count * 0.03 );
        $score += $loginScore;
        $factors++;

        // Age factor (max 0.3)
        $daysSinceCreation = $device->created_at->diffInDays( now() );
        $ageScore          = min( 0.3, $daysSinceCreation * 0.01 );
        $score += $ageScore;
        $factors++;

        // Trusted status factor (0.2)
        if ( $device->isTrusted() ) {
            $score += 0.2;
        }
        $factors++;

        // Recent activity factor (0.2)
        if ( $device->last_used_at && $device->last_used_at->isAfter( now()->subDays( 7 ) ) ) {
            $score += 0.2;
        }
        $factors++;

        return min( 1.0, $score );
    }

    /**
     * Check if a device is recognized.
     */
    public function isRecognizedDevice( Authenticatable $user, string $fingerprintHash ): bool
    {
        return UserDevice::where( 'user_id', $user->getAuthIdentifier() )
            ->where( 'fingerprint_hash', $fingerprintHash )
            ->exists();
    }

    /**
     * Check if a device is trusted.
     */
    public function isTrustedDevice( Authenticatable $user, string $fingerprintHash ): bool
    {
        $device = UserDevice::where( 'user_id', $user->getAuthIdentifier() )
            ->where( 'fingerprint_hash', $fingerprintHash )
            ->first();

        return $device?->isTrusted() ?? false;
    }

    /**
     * Mark a device as trusted.
     */
    public function trustDevice( UserDevice $device, ?int $expirationDays = null ): void
    {
        $expirationDays = $expirationDays
            ?? config( 'artisanpack.security-advanced-auth.device_fingerprinting.trust.trust_duration_days', 30 );

        $device->trust( $expirationDays );
    }

    /**
     * Revoke trust from a device.
     */
    public function revokeDeviceTrust( UserDevice $device ): void
    {
        $device->revokeTrust();
    }

    /**
     * Get all devices for a user.
     */
    public function getUserDevices( Authenticatable $user ): Collection
    {
        return UserDevice::where( 'user_id', $user->getAuthIdentifier() )
            ->orderByDesc( 'last_used_at' )
            ->get();
    }

    /**
     * Delete a device.
     */
    public function deleteDevice( UserDevice $device ): void
    {
        $device->delete();
    }

    /**
     * Prune inactive devices.
     */
    public function pruneInactiveDevices( int $inactiveDays ): int
    {
        return UserDevice::inactive( $inactiveDays )->delete();
    }

    /**
     * Get the hash algorithm.
     */
    public function getHashAlgorithm(): string
    {
        return config( 'artisanpack.security-advanced-auth.device_fingerprinting.hash_algorithm', 'sha256' );
    }

    /**
     * Check if user should auto-trust device based on login count.
     */
    public function shouldAutoTrust( UserDevice $device ): bool
    {
        $autoTrustAfter = config( 'artisanpack.security-advanced-auth.device_fingerprinting.trust.auto_trust_after_logins', 3 );

        return $device->login_count >= $autoTrustAfter && ! $device->isTrusted();
    }

    /**
     * Parse user agent to extract device info.
     *
     * @return array{type: string, browser: ?string, browser_version: ?string, os: ?string, os_version: ?string}
     */
    protected function parseUserAgent( string $userAgent ): array
    {
        $info = [
            'type'            => UserDevice::TYPE_UNKNOWN,
            'browser'         => null,
            'browser_version' => null,
            'os'              => null,
            'os_version'      => null,
        ];

        // Detect device type
        if ( preg_match( '/Mobile|Android.*Mobile|iPhone|iPod/i', $userAgent ) ) {
            $info['type'] = UserDevice::TYPE_MOBILE;
        } elseif ( preg_match( '/iPad|Android(?!.*Mobile)|Tablet/i', $userAgent ) ) {
            $info['type'] = UserDevice::TYPE_TABLET;
        } elseif ( preg_match( '/Windows|Macintosh|Linux/i', $userAgent ) ) {
            $info['type'] = UserDevice::TYPE_DESKTOP;
        }

        // Detect browser
        if ( preg_match( '/Chrome\/(\d+\.\d+)/i', $userAgent, $matches ) ) {
            $info['browser']         = 'Chrome';
            $info['browser_version'] = $matches[1];
        } elseif ( preg_match( '/Firefox\/(\d+\.\d+)/i', $userAgent, $matches ) ) {
            $info['browser']         = 'Firefox';
            $info['browser_version'] = $matches[1];
        } elseif ( preg_match( '/Safari\/(\d+\.\d+)/i', $userAgent, $matches ) && ! str_contains( $userAgent, 'Chrome' ) ) {
            $info['browser']         = 'Safari';
            $info['browser_version'] = $matches[1];
        } elseif ( preg_match( '/Edg\/(\d+\.\d+)/i', $userAgent, $matches ) ) {
            $info['browser']         = 'Edge';
            $info['browser_version'] = $matches[1];
        }

        // Detect OS
        if ( preg_match( '/Windows NT (\d+\.\d+)/i', $userAgent, $matches ) ) {
            $info['os']         = 'Windows';
            $info['os_version'] = $this->mapWindowsVersion( $matches[1] );
        } elseif ( preg_match( '/Mac OS X (\d+[._]\d+)/i', $userAgent, $matches ) ) {
            $info['os']         = 'macOS';
            $info['os_version'] = str_replace( '_', '.', $matches[1] );
        } elseif ( preg_match( '/Android (\d+\.\d+)/i', $userAgent, $matches ) ) {
            $info['os']         = 'Android';
            $info['os_version'] = $matches[1];
        } elseif ( preg_match( '/iPhone OS (\d+_\d+)/i', $userAgent, $matches ) ) {
            $info['os']         = 'iOS';
            $info['os_version'] = str_replace( '_', '.', $matches[1] );
        } elseif ( preg_match( '/Linux/i', $userAgent ) ) {
            $info['os'] = 'Linux';
        }

        return $info;
    }

    /**
     * Map Windows NT version to friendly name.
     */
    protected function mapWindowsVersion( string $ntVersion ): string
    {
        return match ( $ntVersion ) {
            '10.0'  => '10/11',
            '6.3'   => '8.1',
            '6.2'   => '8',
            '6.1'   => '7',
            '6.0'   => 'Vista',
            default => $ntVersion,
        };
    }

    /**
     * Get location from request (simplified).
     *
     * @return array<string, mixed>|null
     */
    protected function getLocationFromRequest( Request $request ): ?array
    {
        // In production, use a GeoIP service
        return [
            'ip'      => $request->ip(),
            'country' => null,
            'region'  => null,
            'city'    => null,
        ];
    }
}
