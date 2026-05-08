<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

interface WebAuthnInterface
{
    /**
     * Generate credential creation options for registration.
     *
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>
     */
    public function generateRegistrationOptions( Authenticatable $user, array $options = [] ): array;

    /**
     * Verify and store the registration response.
     *
     * @param  array<string, mixed>  $response
     *
     * @return array{success: bool, credential_id: ?string, error: ?string}
     */
    public function verifyRegistration( Authenticatable $user, array $response, string $challenge ): array;

    /**
     * Generate credential request options for authentication.
     *
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>
     */
    public function generateAuthenticationOptions( ?Authenticatable $user = null, array $options = [] ): array;

    /**
     * Verify the authentication response.
     *
     * @param  array<string, mixed>  $response
     *
     * @return array{success: bool, user_id: ?int, error: ?string}
     */
    public function verifyAuthentication( array $response, string $challenge ): array;

    /**
     * Get all credentials for a user.
     *
     * @return array<array<string, mixed>>
     */
    public function getCredentials( Authenticatable $user ): array;

    /**
     * Delete a credential by ID.
     */
    public function deleteCredential( Authenticatable $user, int $credentialId ): bool;

    /**
     * Update credential metadata (name, etc.).
     *
     * @param  array<string, mixed>  $data
     */
    public function updateCredential( Authenticatable $user, int $credentialId, array $data ): bool;

    /**
     * Get the relying party configuration.
     *
     * @return array{id: string, name: string, icon: ?string}
     */
    public function getRelyingParty(): array;

    /**
     * Check if passwordless authentication is enabled.
     */
    public function isPasswordlessEnabled(): bool;

    /**
     * Get the maximum number of credentials per user.
     */
    public function getMaxCredentialsPerUser(): int;

    /**
     * Invalidate a challenge after use.
     */
    public function invalidateChallenge( string $challenge): void;
}
