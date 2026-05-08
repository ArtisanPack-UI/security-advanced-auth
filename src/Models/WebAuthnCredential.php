<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Models;

use Exception;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Crypt;
use InvalidArgumentException;

class WebAuthnCredential extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'webauthn_credentials';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'name',
        'credential_id',
        'credential_id_hash',
        'public_key',
        'attestation_type',
        'transports',
        'aaguid',
        'sign_count',
        'user_verified',
        'backup_eligible',
        'backup_state',
        'last_used_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'credential_id',
        'public_key',
        'aaguid',
    ];

    /**
     * Get the user that owns this credential.
     *
     * @return BelongsTo<\Illuminate\Foundation\Auth\User, WebAuthnCredential>
     */
    public function user(): BelongsTo
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        return $this->belongsTo( $userModel );
    }

    /**
     * Set the credential ID with encryption.
     * Also generates a hash for efficient database lookups.
     */
    public function setCredentialIdAttribute( string $value ): void
    {
        $this->attributes['credential_id']      = Crypt::encryptString( base64_encode( $value ) );
        $this->attributes['credential_id_hash'] = hash( 'sha256', $value );
    }

    /**
     * Generate a hash for a credential ID for lookup purposes.
     */
    public static function hashCredentialId( string $credentialId ): string
    {
        return hash( 'sha256', $credentialId );
    }

    /**
     * Get the decrypted credential ID.
     */
    public function getCredentialIdAttribute( ?string $value ): ?string
    {
        if ( null === $value ) {
            return null;
        }

        try {
            return base64_decode( Crypt::decryptString( $value ) );
        } catch ( Exception ) {
            return null;
        }
    }

    /**
     * Set the public key with encryption.
     */
    public function setPublicKeyAttribute( string $value ): void
    {
        $this->attributes['public_key'] = Crypt::encryptString( base64_encode( $value ) );
    }

    /**
     * Get the decrypted public key.
     */
    public function getPublicKeyAttribute( ?string $value ): ?string
    {
        if ( null === $value ) {
            return null;
        }

        try {
            return base64_decode( Crypt::decryptString( $value ) );
        } catch ( Exception ) {
            return null;
        }
    }

    /**
     * Get the credential ID as base64 for API responses.
     */
    public function getCredentialIdBase64(): string
    {
        return base64_encode( $this->credential_id );
    }

    /**
     * Increment the signature counter.
     */
    public function incrementSignCount( int $newCount ): void
    {
        $this->sign_count   = $newCount;
        $this->last_used_at = now();
        $this->save();
    }

    /**
     * Check if the sign count is valid (prevents replay attacks).
     */
    public function isSignCountValid( int $newCount ): bool
    {
        // Sign count must always increase
        return $newCount > $this->sign_count;
    }

    /**
     * Check if this is a passkey (discoverable credential).
     */
    public function isPasskey(): bool
    {
        // Passkeys typically have backup eligibility
        return $this->backup_eligible;
    }

    /**
     * Check if this is a platform authenticator (built-in biometric).
     */
    public function isPlatformAuthenticator(): bool
    {
        $transports = $this->transports ?? [];

        return in_array( 'internal', $transports );
    }

    /**
     * Check if this is a roaming authenticator (security key).
     */
    public function isRoamingAuthenticator(): bool
    {
        $transports = $this->transports ?? [];

        return in_array( 'usb', $transports )
            || in_array( 'nfc', $transports )
            || in_array( 'ble', $transports );
    }

    /**
     * Get a human-readable description of the authenticator type.
     */
    public function getAuthenticatorTypeDescription(): string
    {
        if ( $this->isPlatformAuthenticator() ) {
            return 'Built-in authenticator (Touch ID, Face ID, Windows Hello)';
        }

        if ( $this->isRoamingAuthenticator() ) {
            $transports = $this->transports ?? [];
            $types      = [];

            if ( in_array( 'usb', $transports ) ) {
                $types[] = 'USB';
            }
            if ( in_array( 'nfc', $transports ) ) {
                $types[] = 'NFC';
            }
            if ( in_array( 'ble', $transports ) ) {
                $types[] = 'Bluetooth';
            }

            return 'Security key (' . implode( ', ', $types ) . ')';
        }

        return 'Unknown authenticator type';
    }

    /**
     * Scope a query to find by credential ID using the hash for efficient lookup.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<WebAuthnCredential>  $query
     *
     * @return \Illuminate\Database\Eloquent\Builder<WebAuthnCredential>
     */
    public function scopeByCredentialId( $query, string $credentialId )
    {
        $hash = self::hashCredentialId( $credentialId );

        return $query->where( 'credential_id_hash', $hash );
    }

    /**
     * Find a credential by its ID for a specific user using the hash for efficient lookup.
     */
    public static function findByCredentialIdForUser( string $credentialId, int $userId ): ?self
    {
        $hash = self::hashCredentialId( $credentialId );

        return static::where( 'user_id', $userId )
            ->where( 'credential_id_hash', $hash )
            ->first();
    }

    /**
     * Find a credential by its ID across all users using the hash for efficient lookup.
     */
    public static function findByCredentialId( string $credentialId ): ?self
    {
        $hash = self::hashCredentialId( $credentialId );

        return static::where( 'credential_id_hash', $hash )->first();
    }

    /**
     * Boot the model.
     */
    protected static function boot(): void
    {
        parent::boot();

        static::creating( function ( WebAuthnCredential $credential ): void {
            // Credential ID must be provided by the authenticator
            if ( empty( $credential->credential_id ) ) {
                throw new InvalidArgumentException( 'Credential ID is required and must be provided by the authenticator' );
            }
        } );
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'transports'      => 'array',
            'sign_count'      => 'integer',
            'user_verified'   => 'boolean',
            'backup_eligible' => 'boolean',
            'backup_state'    => 'boolean',
            'last_used_at'    => 'datetime',
        ];
    }
}
