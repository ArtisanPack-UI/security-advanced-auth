<?php

/**
 * WebAuthnManager WebAuthn class.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\WebAuthn;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\WebAuthnInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Models\WebAuthnCredential;
use Exception;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * WebAuthn/FIDO2 authentication manager.
 *
 * IMPORTANT: CBOR and COSE Implementation Note
 *
 * This implementation includes simplified placeholder methods for CBOR decoding
 * and COSE signature verification (`decodeCbor()` and `verifySignature()`).
 * These placeholders allow the authentication flow to work but do NOT provide
 * full cryptographic verification.
 *
 * For production deployments:
 * 1. Install a proper CBOR library: `composer require spomky-labs/cbor-php`
 * 2. Install a proper WebAuthn library: `composer require web-auth/webauthn-lib`
 *    or use `web-auth/cose-lib` for COSE key handling
 * 3. The `decodeCbor()` method should properly parse CBOR-encoded attestation objects
 * 4. The `verifySignature()` method should decode COSE public keys and verify
 *    signatures using the appropriate algorithm (ES256, RS256, etc.)
 *
 * The web-auth/webauthn-lib package provides a complete, production-ready
 * implementation of the WebAuthn specification.
 */
class WebAuthnManager implements WebAuthnInterface
{
    /**
     * Generate credential creation options for registration.
     */
    public function generateRegistrationOptions( Authenticatable $user, array $options = [] ): array
    {
        $challenge = $this->generateChallenge();
        $this->storeChallenge( $challenge, 'registration' );

        $rp     = $this->getRelyingParty();
        $config = config( 'artisanpack.security-advanced-auth.webauthn', [] );

        // Get existing credentials to exclude
        $excludeCredentials = [];
        if ( method_exists( $user, 'getWebAuthnCredentialDescriptors' ) ) {
            $excludeCredentials = $user->getWebAuthnCredentialDescriptors();
        }

        $publicKeyOptions = [
            'challenge' => $this->base64UrlEncode( $challenge ),
            'rp'        => [
                'name' => $rp['name'],
                'id'   => $rp['id'],
            ],
            'user' => [
                'id'          => $this->base64UrlEncode( (string) $user->getAuthIdentifier() ),
                'name'        => $user->email ?? $user->name ?? 'user',
                'displayName' => $user->name ?? $user->email ?? 'User',
            ],
            'pubKeyCredParams'       => $this->getSupportedAlgorithms(),
            'timeout'                => $config['timeout'] ?? 60000,
            'attestation'            => $config['attestation_conveyance'] ?? 'none',
            'excludeCredentials'     => $excludeCredentials,
            'authenticatorSelection' => [
                'userVerification' => $config['user_verification'] ?? 'preferred',
                'residentKey'      => $config['resident_key'] ?? 'preferred',
            ],
        ];

        // Add authenticator attachment if configured
        $attachment = $config['authenticator_attachment'] ?? $options['authenticator_attachment'] ?? null;
        if ( $attachment ) {
            $publicKeyOptions['authenticatorSelection']['authenticatorAttachment'] = $attachment;
        }

        return $publicKeyOptions;
    }

    /**
     * Verify and store the registration response.
     */
    public function verifyRegistration( Authenticatable $user, array $response, string $challenge ): array
    {
        try {
            // Verify the challenge
            $storedChallenge = $this->getStoredChallenge( 'registration' );
            if ( ! $storedChallenge || ! hash_equals( $storedChallenge, base64_decode( $challenge ) ) ) {
                return ['success' => false, 'credential_id' => null, 'error' => 'Invalid or expired challenge'];
            }

            $this->invalidateChallenge( $storedChallenge );

            // Decode the attestation response
            $clientDataJson    = $this->base64UrlDecode( $response['response']['clientDataJSON'] );
            $attestationObject = $this->base64UrlDecode( $response['response']['attestationObject'] );

            // Parse client data
            $clientData = json_decode( $clientDataJson, true );
            if ( ! $clientData ) {
                return ['success' => false, 'credential_id' => null, 'error' => 'Invalid client data'];
            }

            // Verify type
            if ( ( $clientData['type'] ?? '' ) !== 'webauthn.create' ) {
                return ['success' => false, 'credential_id' => null, 'error' => 'Invalid client data type'];
            }

            // Verify origin
            $allowedOrigins = config( 'artisanpack.security-advanced-auth.webauthn.allowed_origins', [config( 'app.url' )] );
            if ( ! in_array( $clientData['origin'] ?? '', $allowedOrigins ) ) {
                return ['success' => false, 'credential_id' => null, 'error' => 'Invalid origin'];
            }

            // Parse attestation object (simplified CBOR parsing)
            $attestation = $this->parseAttestationObject( $attestationObject );
            if ( ! $attestation ) {
                return ['success' => false, 'credential_id' => null, 'error' => 'Invalid attestation object'];
            }

            // Extract credential ID and public key
            $credentialId = $response['rawId'] ?? $response['id'];
            $publicKey    = $attestation['publicKey'];

            // Check user verification if required
            $uvRequired = 'required' === config( 'artisanpack.security-advanced-auth.webauthn.user_verification' );
            if ( $uvRequired && ! ( $attestation['flags']['uv'] ?? false ) ) {
                return ['success' => false, 'credential_id' => null, 'error' => 'User verification required'];
            }

            // Check credential limit
            if ( method_exists( $user, 'canAddWebAuthnCredential' ) && ! $user->canAddWebAuthnCredential() ) {
                return ['success' => false, 'credential_id' => null, 'error' => 'Maximum credentials limit reached'];
            }

            // Store the credential
            $credential = WebAuthnCredential::create( [
                'user_id'          => $user->getAuthIdentifier(),
                'name'             => $response['name'] ?? 'Security Key ' . now()->format( 'M j, Y' ),
                'credential_id'    => $this->base64UrlDecode( $credentialId ),
                'public_key'       => $publicKey,
                'attestation_type' => $attestation['fmt'] ?? 'none',
                'transports'       => $response['response']['transports'] ?? [],
                'aaguid'           => $attestation['aaguid'] ?? null,
                'sign_count'       => $attestation['signCount'] ?? 0,
                'user_verified'    => $attestation['flags']['uv'] ?? false,
                'backup_eligible'  => $attestation['flags']['be'] ?? false,
                'backup_state'     => $attestation['flags']['bs'] ?? false,
            ] );

            return [
                'success'       => true,
                'credential_id' => $credential->id,
                'error'         => null,
            ];
        } catch ( Exception $e ) {
            // Log the actual error for debugging
            report( $e );
            
            return [
                'success'       => false,
                'credential_id' => null,
                'error'         => 'Registration failed',
            ];
        }
    }

    /**
     * Generate credential request options for authentication.
     */
    public function generateAuthenticationOptions( ?Authenticatable $user = null, array $options = [] ): array
    {
        $challenge = $this->generateChallenge();
        $this->storeChallenge( $challenge, 'authentication' );

        $rp     = $this->getRelyingParty();
        $config = config( 'artisanpack.security-advanced-auth.webauthn', [] );

        $publicKeyOptions = [
            'challenge'        => $this->base64UrlEncode( $challenge ),
            'rpId'             => $rp['id'],
            'timeout'          => $config['timeout'] ?? 60000,
            'userVerification' => $config['user_verification'] ?? 'preferred',
        ];

        // Add allowed credentials if user is known
        if ( $user && method_exists( $user, 'getWebAuthnCredentialDescriptors' ) ) {
            $publicKeyOptions['allowCredentials'] = $user->getWebAuthnCredentialDescriptors();
        }

        return $publicKeyOptions;
    }

    /**
     * Verify the authentication response.
     */
    public function verifyAuthentication( array $response, string $challenge ): array
    {
        try {
            // Verify the challenge
            $storedChallenge = $this->getStoredChallenge( 'authentication' );
            if ( ! $storedChallenge || ! hash_equals( $storedChallenge, base64_decode( $challenge ) ) ) {
                return ['success' => false, 'user_id' => null, 'error' => 'Invalid or expired challenge'];
            }

            $this->invalidateChallenge( $storedChallenge );

            // Decode the assertion response
            $clientDataJson    = $this->base64UrlDecode( $response['response']['clientDataJSON'] );
            $authenticatorData = $this->base64UrlDecode( $response['response']['authenticatorData'] );
            $signature         = $this->base64UrlDecode( $response['response']['signature'] );
            $credentialId      = $this->base64UrlDecode( $response['rawId'] ?? $response['id'] );

            // Parse client data
            $clientData = json_decode( $clientDataJson, true );
            if ( ! $clientData ) {
                return ['success' => false, 'user_id' => null, 'error' => 'Invalid client data'];
            }

            // Verify type
            if ( ( $clientData['type'] ?? '' ) !== 'webauthn.get' ) {
                return ['success' => false, 'user_id' => null, 'error' => 'Invalid client data type'];
            }

            // Verify origin
            $allowedOrigins = config( 'artisanpack.security-advanced-auth.webauthn.allowed_origins', [config( 'app.url' )] );
            if ( ! in_array( $clientData['origin'] ?? '', $allowedOrigins ) ) {
                return ['success' => false, 'user_id' => null, 'error' => 'Invalid origin'];
            }

            // Find the credential
            $credential = $this->findCredentialById( $credentialId );
            if ( ! $credential ) {
                return ['success' => false, 'user_id' => null, 'error' => 'Credential not found'];
            }

            // Verify signature
            $clientDataHash = hash( 'sha256', $clientDataJson, true );
            $signedData     = $authenticatorData . $clientDataHash;

            if ( ! $this->verifySignature( $signedData, $signature, $credential->public_key ) ) {
                return ['success' => false, 'user_id' => null, 'error' => 'Invalid signature'];
            }

            // Parse authenticator data
            $authData = $this->parseAuthenticatorData( $authenticatorData );

            // Verify sign count (replay attack prevention)
            if ( $authData['signCount'] > 0 ) {
                if ( ! $credential->isSignCountValid( $authData['signCount'] ) ) {
                    return ['success' => false, 'user_id' => null, 'error' => 'Invalid signature counter'];
                }
            }

            // Update credential
            $credential->incrementSignCount( $authData['signCount'] );

            return [
                'success' => true,
                'user_id' => $credential->user_id,
                'error'   => null,
            ];
        } catch ( Exception $e ) {
            return [
                'success' => false,
                'user_id' => null,
                'error'   => $e->getMessage(),
            ];
        }
    }

    /**
     * Get all credentials for a user.
     */
    public function getCredentials( Authenticatable $user ): array
    {
        return WebAuthnCredential::where( 'user_id', $user->getAuthIdentifier() )
            ->get()
            ->map( function ( $credential ) {
                return [
                    'id'           => $credential->id,
                    'name'         => $credential->name,
                    'type'         => $credential->getAuthenticatorTypeDescription(),
                    'is_passkey'   => $credential->isPasskey(),
                    'last_used_at' => $credential->last_used_at,
                    'created_at'   => $credential->created_at,
                ];
            } )
            ->toArray();
    }

    /**
     * Delete a credential.
     */
    public function deleteCredential( Authenticatable $user, int $credentialId ): bool
    {
        return (bool) WebAuthnCredential::where( 'user_id', $user->getAuthIdentifier() )
            ->where( 'id', $credentialId )
            ->delete();
    }

    /**
     * Update credential metadata.
     */
    public function updateCredential( Authenticatable $user, int $credentialId, array $data ): bool
    {
        $credential = WebAuthnCredential::where( 'user_id', $user->getAuthIdentifier() )
            ->where( 'id', $credentialId )
            ->first();

        if ( ! $credential ) {
            return false;
        }

        if ( isset( $data['name'] ) ) {
            $credential->name = $data['name'];
        }

        return $credential->save();
    }

    /**
     * Get the relying party configuration.
     */
    public function getRelyingParty(): array
    {
        $config = config( 'artisanpack.security-advanced-auth.webauthn.relying_party', [] );

        return [
            'id'   => $config['id'] ?? parse_url( config( 'app.url' ), PHP_URL_HOST ),
            'name' => $config['name'] ?? config( 'app.name' ),
            'icon' => $config['icon'] ?? null,
        ];
    }

    /**
     * Check if passwordless authentication is enabled.
     */
    public function isPasswordlessEnabled(): bool
    {
        return config( 'artisanpack.security-advanced-auth.webauthn.allow_passwordless', true );
    }

    /**
     * Get the maximum number of credentials per user.
     */
    public function getMaxCredentialsPerUser(): int
    {
        return config( 'artisanpack.security-advanced-auth.webauthn.max_credentials_per_user', 10 );
    }

    /**
     * Invalidate a challenge after use.
     */
    public function invalidateChallenge( string $challenge ): void
    {
        // Clear challenges from session for both types
        session()->forget( 'webauthn_registration_challenge' );
        session()->forget( 'webauthn_authentication_challenge' );
    }

    /**
     * Generate a cryptographic challenge.
     */
    protected function generateChallenge(): string
    {
        return random_bytes( 32 );
    }

    /**
     * Store a challenge in the session.
     *
     * Using session storage ensures the challenge is bound to the user's session
     * and is automatically cleaned up when the session expires.
     */
    protected function storeChallenge( string $challenge, string $type ): void
    {
        $key = "webauthn_{$type}_challenge";
        session()->put( $key, $challenge );

        // Set expiration timestamp
        session()->put( "{$key}_expires", now()->addMinutes( 5 )->timestamp );
    }

    /**
     * Get a stored challenge from the session.
     */
    protected function getStoredChallenge( string $type ): ?string
    {
        $key        = "webauthn_{$type}_challenge";
        $expiresKey = "{$key}_expires";

        $challenge = session( $key );
        $expiresAt = session( $expiresKey );

        // Check if challenge exists and hasn't expired
        if ( null === $challenge ) {
            return null;
        }

        if ( null !== $expiresAt && time() > $expiresAt ) {
            // Challenge has expired, clean up
            session()->forget( $key );
            session()->forget( $expiresKey );

            return null;
        }

        return $challenge;
    }

    /**
     * Get supported algorithms.
     *
     * @return array<array{alg: int, type: string}>
     */
    protected function getSupportedAlgorithms(): array
    {
        return [
            ['alg' => -7, 'type' => 'public-key'],   // ES256
            ['alg' => -257, 'type' => 'public-key'], // RS256
        ];
    }

    /**
     * Parse attestation object (simplified).
     *
     * @return array<string, mixed>|null
     */
    protected function parseAttestationObject( string $attestationObject ): ?array
    {
        // This is a simplified CBOR parser
        // In production, use a proper CBOR library
        try {
            // The attestation object is CBOR encoded
            // For a full implementation, use web-auth/webauthn-lib package
            $decoded = $this->decodeCbor( $attestationObject );

            if ( ! $decoded || ! isset( $decoded['authData'] ) ) {
                return null;
            }

            $authData = $this->parseAuthenticatorData( $decoded['authData'] );

            return [
                'fmt'       => $decoded['fmt'] ?? 'none',
                'publicKey' => $authData['publicKey'] ?? '',
                'aaguid'    => $authData['aaguid'] ?? null,
                'signCount' => $authData['signCount'] ?? 0,
                'flags'     => $authData['flags'] ?? [],
            ];
        } catch ( Exception ) {
            return null;
        }
    }

    /**
     * Parse authenticator data.
     *
     * @return array<string, mixed>
     */
    protected function parseAuthenticatorData( string $authData ): array
    {
        if ( strlen( $authData ) < 37 ) {
            return [];
        }

        $rpIdHash  = substr( $authData, 0, 32 );
        $flags     = ord( $authData[32] );
        $signCount = unpack( 'N', substr( $authData, 33, 4 ) )[1];

        return [
            'rpIdHash' => bin2hex( $rpIdHash ),
            'flags'    => [
                'up' => (bool) ( $flags & 0x01 ), // User Present
                'uv' => (bool) ( $flags & 0x04 ), // User Verified
                'be' => (bool) ( $flags & 0x08 ), // Backup Eligible
                'bs' => (bool) ( $flags & 0x10 ), // Backup State
                'at' => (bool) ( $flags & 0x40 ), // Attested credential data included
                'ed' => (bool) ( $flags & 0x80 ), // Extension data included
            ],
            'signCount' => $signCount,
            'publicKey' => strlen( $authData ) > 37 ? substr( $authData, 37 ) : '',
            'aaguid'    => strlen( $authData ) > 53 ? substr( $authData, 37, 16 ) : null,
        ];
    }

    /**
     * Decode CBOR (simplified placeholder).
     *
     * WARNING: This is a PLACEHOLDER implementation that does not actually decode CBOR.
     * It returns a minimal structure to allow the flow to work during development/testing.
     *
     * For production use, replace this with a proper CBOR decoder:
     *   composer require spomky-labs/cbor-php
     *   composer require web-auth/webauthn-lib
     *
     * @return array<string, mixed>|null
     */
    protected function decodeCbor( string $data ): ?array
    {
        // PLACEHOLDER: Returns a minimal structure for the attestation object
        // In production, properly decode the CBOR structure to extract:
        // - fmt: attestation format (none, packed, tpm, android-key, etc.)
        // - authData: authenticator data (rpIdHash, flags, signCount, credentialData)
        // - attStmt: attestation statement for signature verification

        return [
            'fmt'      => 'none',
            'authData' => $data,
            'attStmt'  => [],
        ];
    }

    /**
     * Verify a signature.
     *
     * WARNING: This is a PLACEHOLDER implementation that may not work correctly
     * with all WebAuthn credential types. The public key from WebAuthn is in COSE
     * format and requires proper COSE key parsing before OpenSSL verification.
     *
     * For production use, install web-auth/cose-lib to properly:
     * 1. Parse COSE-encoded public keys
     * 2. Extract the algorithm and key parameters
     * 3. Convert to a format suitable for OpenSSL verification
     */
    protected function verifySignature( string $data, string $signature, string $publicKey ): bool
    {
        try {
            // PLACEHOLDER: Attempts direct OpenSSL verification
            // This will only work if publicKey is already in PEM format
            // COSE keys need to be decoded first using web-auth/cose-lib
            $result = openssl_verify( $data, $signature, $publicKey, OPENSSL_ALGO_SHA256 );

            return 1 === $result;
        } catch ( Exception ) {
            return false;
        }
    }

    /**
     * Find a credential by its ID.
     */
    protected function findCredentialById( string $credentialId ): ?WebAuthnCredential
    {
        // If using Laravel's encrypted casting, consider storing a hash for lookup
        // For now, use chunking to avoid loading all into memory at once
        $found = null;
        WebAuthnCredential::chunk( 100, function ( $credentials ) use ( $credentialId, &$found ) {
            foreach ( $credentials as $credential ) {
                if ( $credential->credential_id === $credentialId ) {
                    $found = $credential;
                    return false; // Stop chunking
                }
            }
        } );
        return $found;
    }

    /**
     * Base64 URL encode.
     */
    protected function base64UrlEncode( string $data ): string
    {
        return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
    }

    /**
     * Base64 URL decode.
     */
    protected function base64UrlDecode( string $data ): string
    {
        return base64_decode( strtr( $data, '-_', '+/'));
    }
}
