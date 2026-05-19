<?php

/**
 * AbstractOAuth2Provider social OAuth provider.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\SocialProviderInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialUser;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use RuntimeException;

abstract class AbstractOAuth2Provider implements SocialProviderInterface
{
    /**
     * The provider configuration.
     *
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * The HTTP client options.
     *
     * @var array<string, mixed>
     */
    protected array $httpOptions = [];

    /**
     * Create a new provider instance.
     *
     * @param  array<string, mixed>  $config
     */
    public function __construct( array $config = [] )
    {
        $this->config = array_merge( $this->getDefaultConfig(), $config );
    }

    /**
     * Get the authorization URL.
     */
    public function getAuthorizationUrl( array $options = [] ): string
    {
        $state  = $options['state'] ?? $this->generateState();
        $scopes = $options['scopes'] ?? $this->config['scopes'] ?? $this->getDefaultScopes();

        $params = [
            'client_id'     => $this->config['client_id'],
            'redirect_uri'  => $this->config['redirect_uri'],
            'response_type' => 'code',
            'scope'         => implode( ' ', $scopes ),
            'state'         => $state,
        ];

        $params = array_merge( $params, $this->getAdditionalAuthorizationParams( $options ) );

        return $this->getAuthorizationEndpoint() . '?' . http_build_query( $params );
    }

    /**
     * Exchange the authorization code for access tokens.
     */
    public function getAccessToken( string $code ): array
    {
        $response = Http::asForm()
            ->withOptions( $this->httpOptions )
            ->post( $this->getTokenEndpoint(), [
                'grant_type'    => 'authorization_code',
                'client_id'     => $this->config['client_id'],
                'client_secret' => $this->config['client_secret'],
                'redirect_uri'  => $this->config['redirect_uri'],
                'code'          => $code,
            ] );

        if ( ! $response->successful() ) {
            throw new RuntimeException( 'Failed to exchange authorization code: HTTP ' . $response->status() );
        }

        $data = $response->json();

        // Validate response structure
        if ( ! is_array( $data ) ) {
            throw new RuntimeException( 'Invalid token response: expected JSON object, got ' . $response->body() );
        }

        if ( ! isset( $data['access_token'] ) || ! is_string( $data['access_token'] ) ) {
            throw new RuntimeException( 'Invalid token response: missing or invalid access_token. Response: ' . $response->body() );
        }

        return [
            'access_token'  => $data['access_token'],
            'refresh_token' => $data['refresh_token'] ?? null,
            'expires_in'    => isset( $data['expires_in'] ) && is_numeric( $data['expires_in'] ) ? (int) $data['expires_in'] : null,
            'token_type'    => $data['token_type'] ?? 'Bearer',
        ];
    }

    /**
     * Refresh an expired access token.
     */
    public function refreshAccessToken( string $refreshToken ): array
    {
        $response = Http::asForm()
            ->withOptions( $this->httpOptions )
            ->post( $this->getTokenEndpoint(), [
                'grant_type'    => 'refresh_token',
                'client_id'     => $this->config['client_id'],
                'client_secret' => $this->config['client_secret'],
                'refresh_token' => $refreshToken,
            ] );

        if ( ! $response->successful() ) {
            throw new RuntimeException( 'Failed to refresh access token: HTTP ' . $response->status() );
        }

        $data = $response->json();

        // Validate response structure
        if ( ! is_array( $data ) ) {
            throw new RuntimeException( 'Invalid refresh token response: expected JSON object, got ' . $response->body() );
        }

        if ( ! isset( $data['access_token'] ) || ! is_string( $data['access_token'] ) ) {
            throw new RuntimeException( 'Invalid refresh token response: missing or invalid access_token. Response: ' . $response->body() );
        }

        return [
            'access_token' => $data['access_token'],
            // Use provided refresh token as fallback if not returned (some providers don't return a new one)
            'refresh_token' => $data['refresh_token'] ?? $refreshToken,
            'expires_in'    => isset( $data['expires_in'] ) && is_numeric( $data['expires_in'] ) ? (int) $data['expires_in'] : null,
            'token_type'    => $data['token_type'] ?? 'Bearer',
        ];
    }

    /**
     * Get the user from the provider.
     */
    public function getUser( string $accessToken ): SocialUser
    {
        $response = Http::withToken( $accessToken )
            ->withOptions( $this->httpOptions )
            ->get( $this->getUserInfoEndpoint() );

        if ( ! $response->successful() ) {
            throw new RuntimeException( 'Failed to get user info: HTTP ' . $response->status() );
        }

        $data = $response->json();

        // Validate response structure before mapping
        if ( ! is_array( $data ) ) {
            throw new RuntimeException( 'Invalid user info response: expected JSON object, got ' . $response->body() );
        }

        if ( empty( $data ) ) {
            throw new RuntimeException( 'Invalid user info response: empty response body' );
        }

        return $this->mapUserData( $data );
    }

    /**
     * Check if the provider supports token refresh.
     */
    public function supportsRefresh(): bool
    {
        return true;
    }

    /**
     * Validate the state parameter.
     */
    public function validateState( string $state, string $expectedState ): bool
    {
        return hash_equals( $expectedState, $state );
    }

    /**
     * Generate a cryptographically secure state parameter.
     */
    public function generateState(): string
    {
        return Str::random( 40 );
    }

    /**
     * Get the configuration.
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Set HTTP client options.
     *
     * @param  array<string, mixed>  $options
     */
    public function setHttpOptions( array $options ): self
    {
        $this->httpOptions = $options;

        return $this;
    }

    /**
     * Get the default configuration.
     *
     * @return array<string, mixed>
     */
    protected function getDefaultConfig(): array
    {
        return [
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => '',
            'scopes'        => $this->getDefaultScopes(),
        ];
    }

    /**
     * Get additional authorization parameters.
     *
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>
     */
    protected function getAdditionalAuthorizationParams( array $options ): array
    {
        return [];
    }

    /**
     * Map the provider's user data to a SocialUser.
     *
     * @param  array<string, mixed>  $data
     */
    abstract protected function mapUserData( array $data ): SocialUser;

    /**
     * Get the authorization endpoint URL.
     */
    abstract protected function getAuthorizationEndpoint(): string;

    /**
     * Get the token endpoint URL.
     */
    abstract protected function getTokenEndpoint(): string;

    /**
     * Get the user info endpoint URL.
     */
    abstract protected function getUserInfoEndpoint(): string;

    /**
     * Get the default scopes for this provider.
     *
     * @return array<int, string>
     */
    abstract protected function getDefaultScopes(): array;
}
