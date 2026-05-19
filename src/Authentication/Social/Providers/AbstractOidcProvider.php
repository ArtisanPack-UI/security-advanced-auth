<?php

/**
 * AbstractOidcProvider social OAuth provider.
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
     *
     * Returns false until full RFC-compliant verification (JWKS signature
     * check, nonce binding, array-aware aud, exp/iat/auth_time, replay
     * protection) is implemented. Callers must verify the ID token through
     * a dedicated JWT library before trusting any claims; the partial
     * helper below is intentionally not advertised as authoritative.
     */
    public function supportsIdTokenValidation(): bool
    {
        return false;
    }

    /**
     * Best-effort claim sanity-check.
     *
     * NOT a substitute for signature verification — this only short-circuits
     * obviously-mismatched issuer / audience / expiration claims. The
     * surrounding flow must verify the JWT signature against the provider's
     * JWKS before calling this. `aud` may be a string or an array per
     * RFC 7519 §4.1.3; both forms are accepted here.
     *
     * @param  array<string, mixed>  $claims
     */
    public function validateIdTokenClaims( array $claims ): bool
    {
        if ( ( $claims['iss'] ?? null ) !== $this->getIssuerUrl() ) {
            return false;
        }

        $clientId = $this->config['client_id'] ?? null;
        $aud      = $claims['aud'] ?? null;

        if ( is_array( $aud ) ) {
            if ( ! in_array( $clientId, $aud, true ) ) {
                return false;
            }
        } elseif ( $aud !== $clientId ) {
            return false;
        }

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
