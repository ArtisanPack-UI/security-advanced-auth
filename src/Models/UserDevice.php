<?php

/**
 * UserDevice Eloquent model.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class UserDevice extends Model
{
    /**
     * Device types.
     */
    public const TYPE_DESKTOP = 'desktop';

    public const TYPE_MOBILE = 'mobile';

    public const TYPE_TABLET = 'tablet';

    public const TYPE_UNKNOWN = 'unknown';

    /**
     * The table associated with the model.
     */
    protected $table = 'user_devices';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'fingerprint_hash',
        'name',
        'type',
        'device_type',
        'browser',
        'browser_version',
        'os',
        'os_version',
        'is_trusted',
        'trusted_at',
        'trust_expires_at',
        'last_ip_address',
        'ip_address',
        'last_location',
        'last_used_at',
        'last_active_at',
        'login_count',
    ];

    /**
     * Set device_type (alias for type).
     */
    public function setDeviceTypeAttribute( ?string $value ): void
    {
        $this->attributes['type'] = $value;
    }

    /**
     * Get device_type (alias for type).
     */
    public function getDeviceTypeAttribute(): ?string
    {
        return $this->type;
    }

    /**
     * Set ip_address (alias for last_ip_address).
     */
    public function setIpAddressAttribute( ?string $value ): void
    {
        $this->attributes['last_ip_address'] = $value;
    }

    /**
     * Get ip_address (alias for last_ip_address).
     */
    public function getIpAddressAttribute(): ?string
    {
        return $this->last_ip_address;
    }

    /**
     * Set last_active_at (alias for last_used_at).
     */
    public function setLastActiveAtAttribute( $value ): void
    {
        $this->attributes['last_used_at'] = $value;
    }

    /**
     * Get last_active_at (alias for last_used_at).
     */
    public function getLastActiveAtAttribute()
    {
        return $this->last_used_at;
    }

    /**
     * Get the user that owns this device.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, UserDevice>
     */
    public function user(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel );
    }

    /**
     * Get the fingerprints for this device.
     *
     * @return HasMany<DeviceFingerprint>
     */
    public function fingerprints(): HasMany
    {
        return $this->hasMany( DeviceFingerprint::class, 'device_id' );
    }

    /**
     * Get the sessions for this device.
     *
     * @return HasMany<UserSession>
     */
    public function sessions(): HasMany
    {
        return $this->hasMany( UserSession::class, 'device_id' );
    }

    /**
     * Check if the device is currently trusted.
     */
    public function isTrusted(): bool
    {
        if ( ! $this->is_trusted ) {
            return false;
        }

        if ( null !== $this->trust_expires_at && $this->trust_expires_at->isPast() ) {
            return false;
        }

        return true;
    }

    /**
     * Mark the device as trusted.
     */
    public function trust( ?int $expirationDays = null ): void
    {
        $this->is_trusted = true;
        $this->trusted_at = now();

        if ( null !== $expirationDays ) {
            $this->trust_expires_at = now()->addDays( $expirationDays );
        } else {
            $this->trust_expires_at = null;
        }

        $this->save();
    }

    /**
     * Revoke trust from the device.
     */
    public function revokeTrust(): void
    {
        $this->is_trusted       = false;
        $this->trusted_at       = null;
        $this->trust_expires_at = null;
        $this->save();
    }

    /**
     * Record a login on this device.
     */
    public function recordLogin( string $ipAddress, ?array $location = null ): void
    {
        $this->last_ip_address = $ipAddress;
        $this->last_location   = $location;
        $this->last_used_at    = now();
        $this->login_count++;
        $this->save();
    }

    /**
     * Get a display name for the device.
     */
    public function getDisplayName(): string
    {
        if ( $this->name ) {
            return $this->name;
        }

        $parts = [];

        if ( $this->browser ) {
            $parts[] = $this->browser;
        }

        if ( $this->os ) {
            $parts[] = 'on ' . $this->os;
        }

        return implode( ' ', $parts ) ?: 'Unknown device';
    }

    /**
     * Scope a query to only include trusted devices.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<UserDevice>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<UserDevice>
     */
    public function scopeTrusted( $query )
    {
        return $query->where( 'is_trusted', true )
            ->where( function ( $q ): void {
                $q->whereNull( 'trust_expires_at' )
                    ->orWhere( 'trust_expires_at', '>', now() );
            } );
    }

    /**
     * Scope a query to only include devices used recently.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<UserDevice>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<UserDevice>
     */
    public function scopeRecentlyUsed( $query, int $days = 30 )
    {
        return $query->where( 'last_used_at', '>=', now()->subDays( $days ) );
    }

    /**
     * Scope a query to only include inactive devices.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<UserDevice>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<UserDevice>
     */
    public function scopeInactive( $query, int $days = 90 )
    {
        return $query->where( function ( $q ) use ( $days ): void {
            $q->whereNull( 'last_used_at' )
                ->orWhere( 'last_used_at', '<', now()->subDays( $days ) );
        } );
    }

    /**
     * Scope a query to find by fingerprint hash.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<UserDevice>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<UserDevice>
     */
    public function scopeByFingerprint( $query, string $fingerprintHash )
    {
        return $query->where( 'fingerprint_hash', $fingerprintHash );
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'is_trusted'       => 'boolean',
            'trusted_at'       => 'datetime',
            'trust_expires_at' => 'datetime',
            'last_location'    => 'array',
            'last_used_at'     => 'datetime',
            'login_count'      => 'integer',
        ];
    }
}
