<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use RuntimeException;

abstract class AbstractOidcProvider extends AbstractOAuth2Provider
{
    /**
     * The OIDC discovery document cache key prefix.
     */
    protected const DISCOVERY_CACHE_PREFIX = 'security_oidc_discovery_';

    /**
     * The discovery document cache duration in seconds.
     */
    protected int $discoveryCacheDuration = 3600;

    /**
     * Get the default scopes for OIDC.
     *
     * @return array<string>
     */
    public function getDefaultScopes(): array
    {
        return ['openid', 'profile', 'email'];
    }

    /**
     * Clear the discovery document cache.
     */
    public function clearDiscoveryCache(): void
    {
        Cache::forget( self::DISCOVERY_CACHE_PREFIX . $this->getName() );
    }

    /**
     * Check if ID token validation is supported.
     */
    public function supportsIdTokenValidation(): bool
    {
        return true;
    }

    /**
     * Validate an ID token (basic validation - consider using a JWT library for production).
     *
     * @param  array<string, mixed>  $claims
     */
    public function validateIdTokenClaims( array $claims ): bool
    {
        // Check issuer
        if ( ( $claims['iss'] ?? null ) !== $this->getIssuerUrl() ) {
            return false;
        }

        // Check audience
        if ( ( $claims['aud'] ?? null ) !== $this->config['client_id'] ) {
            return false;
        }

        // Check expiration
        if ( ( $claims['exp'] ?? 0 ) < time() ) {
            return false;
        }

        return true;
    }

    /**
     * Get the OIDC issuer URL.
     */
    abstract protected function getIssuerUrl(): string;

    /**
     * Get the discovery document URL.
     */
    protected function getDiscoveryUrl(): string
    {
        return rtrim( $this->getIssuerUrl(), '/' ) . '/.well-known/openid-configuration';
    }

    /**
     * Fetch and cache the discovery document.
     *
     * @return array<string, mixed>
     */
    protected function getDiscoveryDocument(): array
    {
        $cacheKey = self::DISCOVERY_CACHE_PREFIX . $this->getName();

        return Cache::remember( $cacheKey, $this->discoveryCacheDuration, function () {
            $response = Http::withOptions( $this->httpOptions )->get( $this->getDiscoveryUrl() );

            if ( ! $response->successful() ) {
                throw new RuntimeException(
                    'Failed to fetch OIDC discovery document. Status: ' . $response->status(),
                );
            }

            return $response->json();
        } );
    }

    /**
     * Get the authorization endpoint from discovery.
     */
    protected function getAuthorizationEndpoint(): string
    {
        return $this->getDiscoveryDocument()['authorization_endpoint']
            ?? throw new RuntimeException( 'Authorization endpoint not found in discovery document' );
    }

    /**
     * Get the token endpoint from discovery.
     */
    protected function getTokenEndpoint(): string
    {
        return $this->getDiscoveryDocument()['token_endpoint']
            ?? throw new RuntimeException( 'Token endpoint not found in discovery document' );
    }

    /**
     * Get the user info endpoint from discovery.
     */
    protected function getUserInfoEndpoint(): string
    {
        return $this->getDiscoveryDocument()['userinfo_endpoint']
            ?? throw new RuntimeException( 'UserInfo endpoint not found in discovery document' );
    }

    /**
     * Get the JWKS URI from discovery.
     */
    protected function getJwksUri(): string
    {
        return $this->getDiscoveryDocument()['jwks_uri']
            ?? throw new RuntimeException( 'JWKS URI not found in discovery document' );
    }

    /**
     * Get the end session endpoint from discovery.
     */
    protected function getEndSessionEndpoint(): ?string
    {
        return $this->getDiscoveryDocument()['end_session_endpoint'] ?? null;
    }

    /**
     * Get additional authorization parameters for OIDC.
     *
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>
     */
    protected function getAdditionalAuthorizationParams( array $options ): array
    {
        $params = parent::getAdditionalAuthorizationParams( $options );

        // Add nonce for OIDC
        if ( ! isset( $params['nonce'] ) ) {
            $params['nonce'] = $this->generateState();
        }

        return $params;
    }
}
