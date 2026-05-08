<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Livewire;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Device\DeviceFingerprintService;
use Exception;
use Illuminate\Support\Facades\Auth;
use Livewire\Component;

class DeviceManager extends Component
{
    public array $devices = [];

    public ?string $currentDeviceId = null;

    public ?string $revokingDeviceId = null;

    protected DeviceFingerprintService $deviceService;

    public function boot( DeviceFingerprintService $deviceService ): void
    {
        $this->deviceService = $deviceService;
    }

    public function mount(): void
    {
        $this->loadDevices();
    }

    public function loadDevices(): void
    {
        $user = Auth::user();

        if ( ! $user || ! method_exists( $user, 'devices' ) ) {
            return;
        }

        // Get current device fingerprint
        $currentFingerprint = session( 'device_fingerprint' );

        $this->devices = $user->devices()
            ->orderBy( 'last_active_at', 'desc' )
            ->get()
            ->map( function ( $device ) use ( $currentFingerprint ) {
                $isCurrent = $currentFingerprint && $device->fingerprint_hash === $currentFingerprint;

                if ( $isCurrent ) {
                    $this->currentDeviceId = $device->id;
                }

                return [
                    'id'          => $device->id,
                    'name'        => $device->device_name ?? 'Unknown Device',
                    'type'        => $device->device_type,
                    'type_icon'   => $this->getDeviceTypeIcon( $device->device_type ),
                    'browser'     => $device->browser ?? 'Unknown',
                    'platform'    => $device->platform ?? 'Unknown',
                    'ip_address'  => $device->ip_address,
                    'location'    => $this->formatLocation( $device ),
                    'is_trusted'  => $device->is_trusted,
                    'is_current'  => $isCurrent,
                    'last_active' => $device->last_active_at?->diffForHumans() ?? 'Unknown',
                    'first_seen'  => $device->created_at->format( 'M j, Y' ),
                    'trust_score' => $device->trust_score,
                ];
            } )
            ->toArray();
    }

    public function trustDevice( string $deviceId ): void
    {
        $user = Auth::user();

        if ( ! $user ) {
            return;
        }

        $device = $user->devices()->find( $deviceId );

        if ( ! $device ) {
            session()->flash( 'error', 'Device not found.' );

            return;
        }

        try {
            $this->deviceService->trustDevice( $user, $device->fingerprint_hash );
            session()->flash( 'success', 'Device has been trusted.' );
            $this->loadDevices();
        } catch ( Exception $e ) {
            session()->flash( 'error', 'Failed to trust device: ' . $e->getMessage() );
        }
    }

    public function confirmRevoke( string $deviceId ): void
    {
        $this->revokingDeviceId = $deviceId;
    }

    public function cancelRevoke(): void
    {
        $this->revokingDeviceId = null;
    }

    public function revokeDevice( string $deviceId ): void
    {
        $user = Auth::user();

        if ( ! $user ) {
            return;
        }

        // Prevent revoking current device
        if ( $deviceId === $this->currentDeviceId ) {
            session()->flash( 'error', 'You cannot revoke your current device.' );
            $this->revokingDeviceId = null;

            return;
        }

        $device = $user->devices()->find( $deviceId );

        if ( ! $device ) {
            session()->flash( 'error', 'Device not found.' );
            $this->revokingDeviceId = null;

            return;
        }

        try {
            $this->deviceService->revokeDevice( $user, $device->fingerprint_hash );
            session()->flash( 'success', 'Device access has been revoked.' );
            $this->loadDevices();
        } catch ( Exception $e ) {
            session()->flash( 'error', 'Failed to revoke device: ' . $e->getMessage() );
        }

        $this->revokingDeviceId = null;
    }

    public function revokeAllOtherDevices(): void
    {
        $user = Auth::user();

        if ( ! $user ) {
            return;
        }

        try {
            $count = 0;
            foreach ( $this->devices as $device ) {
                if ( $device['id'] !== $this->currentDeviceId ) {
                    $deviceModel = $user->devices()->find( $device['id'] );
                    if ( $deviceModel ) {
                        $this->deviceService->revokeDevice( $user, $deviceModel->fingerprint_hash );
                        $count++;
                    }
                }
            }

            session()->flash( 'success', "{$count} device(s) have been revoked." );
            $this->loadDevices();
        } catch ( Exception $e ) {
            session()->flash( 'error', 'Failed to revoke devices: ' . $e->getMessage() );
        }
    }

    public function render()
    {
        return view( 'security-advanced-auth::livewire.device-manager' );
    }

    protected function getDeviceTypeIcon( string $deviceType ): string
    {
        return match ( $deviceType ) {
            'desktop' => 'fas fa-desktop',
            'mobile'  => 'fas fa-mobile-alt',
            'tablet'  => 'fas fa-tablet-alt',
            default   => 'fas fa-question-circle',
        };
    }

    protected function formatLocation( $device ): string
    {
        $parts = array_filter( [
            $device->city,
            $device->region,
            $device->country,
        ]);

        return implode( ', ', $parts) ?: 'Unknown location';
    }
}
