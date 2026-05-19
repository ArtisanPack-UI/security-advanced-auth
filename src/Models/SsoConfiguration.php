<?php

/**
 * SsoConfiguration Eloquent model.
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

use Exception;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\Crypt;

class SsoConfiguration extends Model
{
    /**
     * SSO types.
     */
    public const TYPE_SAML = 'saml';

    public const TYPE_OIDC = 'oidc';

    public const TYPE_LDAP = 'ldap';

    /**
     * The table associated with the model.
     */
    protected $table = 'sso_configurations';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'slug',
        'type',
        'protocol',
        'is_enabled',
        'is_active',
        'is_default',
        'settings',
        'attribute_mapping',
        'certificate',
        'private_key',
        'metadata_url',
        'metadata_xml',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'private_key',
        'settings',
    ];

    /**
     * Keys within settings that contain sensitive data and should be encrypted.
     *
     * @var array<string>
     */
    protected array $sensitiveSettingsKeys = [
        'client_secret',
        'private_key',
        'password',
        'api_key',
        'secret',
    ];

    /**
     * Set the protocol (alias for type).
     */
    public function setProtocolAttribute( ?string $value ): void
    {
        $this->attributes['type'] = $value;
    }

    /**
     * Get the protocol (alias for type).
     */
    public function getProtocolAttribute(): ?string
    {
        return $this->type;
    }

    /**
     * Set is_active (alias for is_enabled).
     */
    public function setIsActiveAttribute( ?bool $value ): void
    {
        $this->attributes['is_enabled'] = $value;
    }

    /**
     * Get is_active (alias for is_enabled).
     */
    public function getIsActiveAttribute(): ?bool
    {
        return $this->is_enabled;
    }

    /**
     * Set the settings with encryption for sensitive keys.
     *
     * @param  array<string, mixed>|null  $value
     */
    public function setSettingsAttribute( ?array $value ): void
    {
        if ( null === $value ) {
            $this->attributes['settings'] = null;

            return;
        }

        // Encrypt sensitive values
        $encryptedSettings = $this->encryptSensitiveSettings( $value );

        $this->attributes['settings'] = json_encode( $encryptedSettings );
    }

    /**
     * Get the settings with decryption for sensitive keys.
     *
     * @return array<string, mixed>|null
     */
    public function getSettingsAttribute( ?string $value ): ?array
    {
        if ( null === $value ) {
            return null;
        }

        $settings = json_decode( $value, true );

        if ( ! is_array( $settings ) ) {
            return null;
        }

        // Decrypt sensitive values
        return $this->decryptSensitiveSettings( $settings );
    }

    /**
     * Get the SSO identities associated with this configuration.
     *
     * @return HasMany<SsoIdentity>
     */
    public function identities(): HasMany
    {
        return $this->hasMany( SsoIdentity::class, 'idp_id', 'slug' );
    }

    /**
     * Set the private key with encryption.
     */
    public function setPrivateKeyAttribute( ?string $value ): void
    {
        $this->attributes['private_key'] = $value ? Crypt::encryptString( $value ) : null;
    }

    /**
     * Get the decrypted private key.
     */
    public function getPrivateKeyAttribute( ?string $value ): ?string
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
     * Get a specific setting value.
     */
    public function getSetting( string $key, mixed $default = null ): mixed
    {
        return data_get( $this->settings, $key, $default );
    }

    /**
     * Set a specific setting value.
     */
    public function setSetting( string $key, mixed $value ): void
    {
        $settings = $this->settings ?? [];
        data_set( $settings, $key, $value );
        $this->settings = $settings;
    }

    /**
     * Get attribute mapping for a specific attribute.
     */
    public function getAttributeMapping( string $attribute ): ?string
    {
        return data_get( $this->attribute_mapping, $attribute );
    }

    /**
     * Check if this is a SAML configuration.
     */
    public function isSaml(): bool
    {
        return self::TYPE_SAML === $this->type;
    }

    /**
     * Check if this is an OIDC configuration.
     */
    public function isOidc(): bool
    {
        return self::TYPE_OIDC === $this->type;
    }

    /**
     * Check if this is an LDAP configuration.
     */
    public function isLdap(): bool
    {
        return self::TYPE_LDAP === $this->type;
    }

    /**
     * Scope a query to only include enabled configurations.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SsoConfiguration>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SsoConfiguration>
     */
    public function scopeEnabled( $query )
    {
        return $query->where( 'is_enabled', true );
    }

    /**
     * Scope a query to only include configurations of a specific type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SsoConfiguration>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SsoConfiguration>
     */
    public function scopeOfType( $query, string $type )
    {
        return $query->where( 'type', $type );
    }

    /**
     * Scope a query to find the default configuration.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<SsoConfiguration>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<SsoConfiguration>
     */
    public function scopeDefault( $query )
    {
        return $query->where( 'is_default', true );
    }

    /**
     * Find a configuration by slug.
     */
    public static function findBySlug( string $slug ): ?self
    {
        return static::where( 'slug', $slug )->first();
    }

    /**
     * Get the route key for the model.
     */
    public function getRouteKeyName(): string
    {
        return 'slug';
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'is_enabled'        => 'boolean',
            'is_default'        => 'boolean',
            'attribute_mapping' => 'array',
        ];
    }

    /**
     * Encrypt sensitive settings.
     *
     * @param  array<string, mixed>  $settings
     *
     * @return array<string, mixed>
     */
    protected function encryptSensitiveSettings( array $settings ): array
    {
        foreach ( $this->sensitiveSettingsKeys as $key ) {
            if ( isset( $settings[ $key ] ) && is_string( $settings[ $key ] ) && '' !== $settings[ $key ] ) {
                // Mark as encrypted and encrypt the value
                $settings[ $key ] = [
                    '__encrypted' => true,
                    'value'       => Crypt::encryptString( $settings[ $key ] ),
                ];
            }
        }

        return $settings;
    }

    /**
     * Decrypt sensitive settings.
     *
     * @param  array<string, mixed>  $settings
     *
     * @return array<string, mixed>
     */
    protected function decryptSensitiveSettings( array $settings ): array
    {
        foreach ( $this->sensitiveSettingsKeys as $key ) {
            if ( isset( $settings[ $key ] ) && is_array( $settings[ $key ] ) && ( $settings[ $key ]['__encrypted'] ?? false ) ) {
                try {
                    $settings[ $key ] = Crypt::decryptString( $settings[ $key ]['value'] );
                } catch ( Exception ) {
                    $settings[ $key ] = null;
                }
            }
        }

        return $settings;
    }
}
