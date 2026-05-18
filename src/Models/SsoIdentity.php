<?php

/**
 * SsoIdentity Eloquent model.
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

class SsoIdentity extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'sso_identities';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'idp_id',
        'idp_user_id',
        'name_id',
        'attributes',
        'session_index',
        'last_authenticated_at',
    ];

    /**
     * Get the user that owns this SSO identity.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, SsoIdentity>
     */
    public function user(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel );
    }

    /**
     * Get the SSO configuration for this identity.
     *
     * @return BelongsTo<SsoConfiguration, SsoIdentity>
     */
    public function configuration(): BelongsTo
    {
        return $this->belongsTo( SsoConfiguration::class, 'idp_id', 'slug' );
    }

    /**
     * Get a value from the SSO provider's attributes JSON.
     *
     * This retrieves a specific key from the 'attributes' JSON column,
     * which stores provider-specific user data from the IdP.
     *
     * @param  string  $key  The key to retrieve from the attributes JSON
     * @param  mixed  $default  Default value if key not found
     */
    public function getSsoAttribute( string $key, mixed $default = null ): mixed
    {
        return data_get( $this->attributes ?? [], $key, $default );
    }

    /**
     * Check if the SSO attributes contain a specific key.
     */
    public function hasSsoAttribute( string $key ): bool
    {
        return null !== data_get( $this->attributes ?? [], $key );
    }

    /**
     * Update the last authenticated timestamp and session index.
     */
    public function recordAuthentication( ?string $sessionIndex = null ): void
    {
        $this->last_authenticated_at = now();

        if ( null !== $sessionIndex ) {
            $this->session_index = $sessionIndex;
        }

        $this->save();
    }

    /**
     * Update the attributes from provider.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function updateAttributes( array $attributes ): void
    {
        $this->setAttribute( 'attributes', $attributes );
        $this->save();
    }

    /**
     * Scope a query to only include identities for a specific IdP.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SsoIdentity>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SsoIdentity>
     */
    public function scopeForIdp( $query, string $idpId )
    {
        return $query->where( 'idp_id', $idpId );
    }

    /**
     * Scope a query to find by IdP user ID.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SsoIdentity>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SsoIdentity>
     */
    public function scopeByIdpUserId( $query, string $idpId, string $idpUserId )
    {
        return $query->where( 'idp_id', $idpId )
            ->where( 'idp_user_id', $idpUserId );
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'attributes'            => 'array',
            'last_authenticated_at' => 'datetime',
        ];
    }
}
