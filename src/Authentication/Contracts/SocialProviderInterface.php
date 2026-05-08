<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialUser;

interface SocialProviderInterface
{
    /**
     * Get the provider name identifier.
     */
    public function getName(): string;

    /**
     * Get the authorization URL to redirect the user to.
     */
    public function getAuthorizationUrl( array $options = [] ): string;

    /**
     * Exchange the authorization code for access tokens.
     *
     * @return array{access_token: string, refresh_token: ?string, expires_in: ?int, token_type: string}
     */
    public function getAccessToken( string $code ): array;

    /**
     * Refresh an expired access token using the refresh token.
     *
     * @return array{access_token: string, refresh_token: ?string, expires_in: ?int, token_type: string}
     */
    public function refreshAccessToken( string $refreshToken ): array;

    /**
     * Get the user details from the provider.
     */
    public function getUser( string $accessToken ): SocialUser;

    /**
     * Get the default scopes for this provider.
     *
     * @return array<string>
     */
    public function getDefaultScopes(): array;

    /**
     * Check if the provider supports token refresh.
     */
    public function supportsRefresh(): bool;

    /**
     * Validate the state parameter to prevent CSRF attacks.
     */
    public function validateState( string $state, string $expectedState ): bool;

    /**
     * Generate a cryptographically secure state parameter.
     */
    public function generateState(): string;

    /**
     * Get additional configuration options for this provider.
     */
    public function getConfig(): array;
}
