<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Models;

use Exception;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Crypt;

class SocialIdentity extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'social_identities';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'provider',
        'provider_user_id',
        'email',
        'name',
        'avatar',
        'access_token',
        'refresh_token',
        'token_expires_at',
        'scopes',
        'raw_data',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'access_token',
        'refresh_token',
        'raw_data',
    ];

    /**
     * Get the user that owns this social identity.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, SocialIdentity>
     */
    public function user(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel );
    }

    /**
     * Set the access token with encryption.
     */
    public function setAccessTokenAttribute( ?string $value ): void
    {
        $this->attributes['access_token'] = $value ? Crypt::encryptString( $value ) : null;
    }

    /**
     * Get the decrypted access token.
     */
    public function getAccessTokenAttribute( ?string $value ): ?string
    {
        if ( null === $value ) {
            return null;
        }

        try {
            return Crypt::decryptString( $value );
        } catch ( Exception ) {
            return null;
        }
    }

    /**
     * Set the refresh token with encryption.
     */
    public function setRefreshTokenAttribute( ?string $value ): void
    {
        $this->attributes['refresh_token'] = $value ? Crypt::encryptString( $value ) : null;
    }

    /**
     * Get the decrypted refresh token.
     */
    public function getRefreshTokenAttribute( ?string $value ): ?string
    {
        if ( null === $value ) {
            return null;
        }

        try {
            return Crypt::decryptString( $value );
        } catch ( Exception ) {
            return null;
        }
    }

    /**
     * Check if the access token is expired.
     */
    public function isTokenExpired(): bool
    {
        if ( null === $this->token_expires_at ) {
            return false;
        }

        return $this->token_expires_at->isPast();
    }

    /**
     * Check if the access token needs refresh.
     */
    public function needsTokenRefresh(): bool
    {
        if ( null === $this->token_expires_at ) {
            return false;
        }

        // Refresh if token expires within 5 minutes. copy() avoids
        // mutating the model's underlying Carbon instance.
        return $this->token_expires_at->copy()->subMinutes( 5 )->isPast();
    }

    /**
     * Update tokens from provider response.
     *
     * @param  array{access_token: string, refresh_token: ?string, expires_in: ?int}  $tokens
     */
    public function updateTokens( array $tokens ): void
    {
        $this->access_token = $tokens['access_token'];

        // array_key_exists() so an explicit null from the provider clears
        // the stored value instead of preserving stale credentials.
        if ( array_key_exists( 'refresh_token', $tokens ) ) {
            $this->refresh_token = $tokens['refresh_token'];
        }

        if ( array_key_exists( 'expires_in', $tokens ) ) {
            $this->token_expires_at = null === $tokens['expires_in']
                ? null
                : now()->addSeconds( (int) $tokens['expires_in'] );
        }

        $this->save();
    }

    /**
     * Scope a query to only include identities for a specific provider.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SocialIdentity>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SocialIdentity>
     */
    public function scopeForProvider( $query, string $provider )
    {
        return $query->where( 'provider', $provider );
    }

    /**
     * Scope a query to find by provider user ID.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SocialIdentity>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SocialIdentity>
     */
    public function scopeByProviderUserId( $query, string $provider, string $providerUserId )
    {
        return $query->where( 'provider', $provider )
            ->where( 'provider_user_id', $providerUserId );
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'token_expires_at' => 'datetime',
            'scopes'           => 'array',
            'raw_data'         => 'array',
        ];
    }
}
