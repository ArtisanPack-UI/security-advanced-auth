<?php

/**
 * OidcClient OIDC SSO class.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\Oidc;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\SsoProviderInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\SsoUser;
use ArtisanPackUI\SecurityAdvancedAuth\Models\SsoConfiguration;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;
use RuntimeException;

class OidcClient implements SsoProviderInterface
{
    /**
     * The SSO configuration.
     */
    protected ?SsoConfiguration $configuration = null;

    /**
     * The OIDC settings.
     *
     * @var array<string, mixed>
     */
    protected array $settings = [];

    /**
     * The discovery document cache duration in seconds.
     */
    protected int $discoveryCacheDuration = 3600;

    /**
     * Get the provider type.
     */
    public function getType(): string
    {
        return 'oidc';
    }

    /**
     * Configure the provider.
     */
    public function configure( SsoConfiguration $configuration ): self
    {
        $this->configuration = $configuration;
        $this->settings      = $configuration->settings ?? [];

        return $this;
    }

    /**
     * Get the login URL.
     */
    public function getLoginUrl( array $options = [] ): string
    {
        $discovery             = $this->getDiscoveryDocument();
        $authorizationEndpoint = $discovery['authorization_endpoint'];

        $state = Str::random( 40 );
        $nonce = Str::random( 40 );

        Session::put( "sso.oidc.{$this->configuration->slug}.state", $state );
        Session::put( "sso.oidc.{$this->configuration->slug}.nonce", $nonce );

        $scopes = $this->settings['scopes'] ?? ['openid', 'profile', 'email'];

        $params = [
            'client_id'     => $this->settings['client_id'],
            'redirect_uri'  => $this->buildCallbackUrl(),
            'response_type' => 'code',
            'scope'         => implode( ' ', $scopes ),
            'state'         => $state,
            'nonce'         => $nonce,
        ];

        // Add PKCE if enabled
        if ( $this->settings['use_pkce'] ?? false ) {
            $codeVerifier = Str::random( 128 );
            Session::put( "sso.oidc.{$this->configuration->slug}.code_verifier", $codeVerifier );

            $codeChallenge                   = rtrim( strtr( base64_encode( hash( 'sha256', $codeVerifier, true ) ), '+/', '-_' ), '=' );
            $params['code_challenge']        = $codeChallenge;
            $params['code_challenge_method'] = 'S256';
        }

        return $authorizationEndpoint . '?' . http_build_query( $params );
    }

    /**
     * Handle the OIDC callback.
     */
    public function handleCallback( Request $request ): SsoUser
    {
        $code  = $request->input( 'code' );
        $state = $request->input( 'state' );

        if ( empty( $code ) ) {
            $error            = $request->input( 'error' );
            $errorDescription = $request->input( 'error_description' );
            throw new RuntimeException( "OIDC error: {$error} - {$errorDescription}" );
        }

        // Validate state
        $expectedState = Session::pull( "sso.oidc.{$this->configuration->slug}.state" );
        if ( ! $expectedState || $state !== $expectedState ) {
            throw new RuntimeException( 'Invalid state parameter' );
        }

        // Exchange code for tokens
        $tokens = $this->exchangeCodeForTokens( $code );

        // Get user info
        return $this->getUserFromTokens( $tokens );
    }

    /**
     * Get the logout URL.
     */
    public function getLogoutUrl( array $options = [] ): ?string
    {
        $discovery          = $this->getDiscoveryDocument();
        $endSessionEndpoint = $discovery['end_session_endpoint'] ?? null;

        if ( ! $endSessionEndpoint ) {
            return null;
        }

        $params = [];

        if ( ! empty( $options['id_token'] ) ) {
            $params['id_token_hint'] = $options['id_token'];
        }

        if ( ! empty( $options['post_logout_redirect_uri'] ) ) {
            $params['post_logout_redirect_uri'] = $options['post_logout_redirect_uri'];
        }

        if ( empty( $params ) ) {
            return $endSessionEndpoint;
        }

        return $endSessionEndpoint . '?' . http_build_query( $params );
    }

    /**
     * Handle the logout response.
     */
    public function handleLogout( Request $request ): bool
    {
        // OIDC RP-initiated logout typically just returns
        return true;
    }

    /**
     * Get metadata (not applicable for OIDC client).
     */
    public function getMetadata(): ?string
    {
        return null;
    }

    /**
     * Validate the configuration.
     */
    public function validateConfiguration(): array
    {
        $errors = [];

        if ( empty( $this->settings['issuer_url'] ) ) {
            $errors['issuer_url'] = 'Issuer URL is required';
        }

        if ( empty( $this->settings['client_id'] ) ) {
            $errors['client_id'] = 'Client ID is required';
        }

        if ( empty( $this->settings['client_secret'] ) ) {
            $errors['client_secret'] = 'Client Secret is required';
        }

        // Try to fetch discovery document
        if ( empty( $errors ) ) {
            try {
                $this->getDiscoveryDocument();
            } catch ( Exception $e ) {
                $errors['discovery'] = 'Failed to fetch discovery document: ' . $e->getMessage();
            }
        }

        return $errors;
    }

    /**
     * Map provider attributes.
     */
    public function mapAttributes( array $providerAttributes ): array
    {
        $mapping = $this->configuration->attribute_mapping ?? [];
        $mapped  = [];

        foreach ( $mapping as $localKey => $providerKey ) {
            if ( isset( $providerAttributes[ $providerKey ] ) ) {
                $mapped[ $localKey ] = $providerAttributes[ $providerKey ];
            }
        }

        return $mapped;
    }

    /**
     * Check if single logout is supported.
     */
    public function supportsSingleLogout(): bool
    {
        $discovery = $this->getDiscoveryDocument();

        return isset( $discovery['end_session_endpoint'] );
    }

    /**
     * Check if JIT provisioning is supported.
     */
    public function supportsJitProvisioning(): bool
    {
        return config( 'artisanpack.security-advanced-auth.sso.jit_provisioning', true );
    }

    /**
     * Clear the discovery cache.
     */
    public function clearDiscoveryCache(): void
    {
        Cache::forget( 'security_sso_oidc_discovery_' . $this->configuration->slug );
    }

    /**
     * Get the discovery document URL.
     */
    protected function getDiscoveryUrl(): string
    {
        $issuer = $this->settings['issuer_url'] ?? '';

        return rtrim( $issuer, '/' ) . '/.well-known/openid-configuration';
    }

    /**
     * Fetch and cache the discovery document.
     *
     * @return array<string, mixed>
     */
    protected function getDiscoveryDocument(): array
    {
        $cacheKey = 'security_sso_oidc_discovery_' . $this->configuration->slug;

        return Cache::remember( $cacheKey, $this->discoveryCacheDuration, function () {
            $response = Http::get( $this->getDiscoveryUrl() );

            if ( ! $response->successful() ) {
                throw new RuntimeException( 'Failed to fetch OIDC discovery document: ' . $response->body() );
            }

            return $response->json();
        } );
    }

    /**
     * Build the callback URL.
     */
    protected function buildCallbackUrl(): string
    {
        $baseUrl = config( 'app.url' );
        $slug    = $this->configuration->slug;

        return "{$baseUrl}/auth/sso/{$slug}/callback";
    }

    /**
     * Exchange authorization code for tokens.
     *
     * @return array<string, mixed>
     */
    protected function exchangeCodeForTokens( string $code ): array
    {
        $discovery     = $this->getDiscoveryDocument();
        $tokenEndpoint = $discovery['token_endpoint'];

        $params = [
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->settings['client_id'],
            'client_secret' => $this->settings['client_secret'],
            'redirect_uri'  => $this->buildCallbackUrl(),
            'code'          => $code,
        ];

        // Add PKCE verifier if used
        $codeVerifier = Session::pull( "sso.oidc.{$this->configuration->slug}.code_verifier" );
        if ( $codeVerifier ) {
            $params['code_verifier'] = $codeVerifier;
        }

        $response = Http::asForm()->post( $tokenEndpoint, $params );

        if ( ! $response->successful() ) {
            throw new RuntimeException( 'Failed to exchange code for tokens: ' . $response->body() );
        }

        return $response->json();
    }

    /**
     * Get user from tokens.
     *
     * @param  array<string, mixed>  $tokens
     */
    protected function getUserFromTokens( array $tokens ): SsoUser
    {
        $discovery        = $this->getDiscoveryDocument();
        $userInfoEndpoint = $discovery['userinfo_endpoint'] ?? null;

        // Try to get user info from userinfo endpoint
        $userInfo = [];
        if ( $userInfoEndpoint ) {
            $response = Http::withToken( $tokens['access_token'] )->get( $userInfoEndpoint );
            if ( $response->successful() ) {
                $userInfo = $response->json();
            }
        }

        // Also parse ID token for claims
        if ( isset( $tokens['id_token'] ) ) {
            $idTokenClaims = $this->parseIdToken( $tokens['id_token'] );
            $userInfo      = array_merge( $idTokenClaims, $userInfo );
        }

        return $this->mapToSsoUser( $userInfo );
    }

    /**
     * Parse and validate ID token.
     *
     * Note: This implementation validates standard JWT claims but does not verify
     * the cryptographic signature. For production use with high-security requirements,
     * consider using a dedicated JWT library like firebase/php-jwt or lcobucci/jwt
     * to perform full signature verification against the IdP's JWKS.
     *
     *
     * @throws RuntimeException if token validation fails
     *
     * @return array<string, mixed>
     */
    protected function parseIdToken( string $idToken ): array
    {
        $parts = explode( '.', $idToken );
        if ( 3 !== count( $parts ) ) {
            throw new RuntimeException( 'Invalid ID token format' );
        }

        $payload = json_decode( base64_decode( strtr( $parts[1], '-_', '+/' ) ), true );

        if ( ! $payload ) {
            throw new RuntimeException( 'Failed to decode ID token payload' );
        }

        // Validate issuer
        $expectedIssuer = rtrim( $this->settings['issuer_url'] ?? '', '/' );
        $tokenIssuer    = rtrim( $payload['iss'] ?? '', '/' );
        if ( $tokenIssuer !== $expectedIssuer ) {
            throw new RuntimeException( 'ID token issuer mismatch' );
        }

        // Validate audience (client_id)
        $audience      = $payload['aud'] ?? null;
        $clientId      = $this->settings['client_id'] ?? null;
        $audienceValid = is_array( $audience )
            ? in_array( $clientId, $audience, true )
            : $audience === $clientId;

        if ( ! $audienceValid ) {
            throw new RuntimeException( 'ID token audience mismatch' );
        }

        // Validate expiration with 5 minute clock skew tolerance
        $exp = $payload['exp'] ?? 0;
        if ( $exp < ( time() - 300 ) ) {
            throw new RuntimeException( 'ID token has expired' );
        }

        // Validate not-before if present
        if ( isset( $payload['nbf'] ) && $payload['nbf'] > ( time() + 300 ) ) {
            throw new RuntimeException( 'ID token is not yet valid' );
        }

        // Validate issued-at is not in the future (with tolerance)
        if ( isset( $payload['iat'] ) && $payload['iat'] > ( time() + 300 ) ) {
            throw new RuntimeException( 'ID token issued in the future' );
        }

        // Validate nonce if we stored one
        $expectedNonce = Session::get( "sso.oidc.{$this->configuration->slug}.nonce" );
        if ( $expectedNonce && ( $payload['nonce'] ?? null ) !== $expectedNonce ) {
            throw new RuntimeException( 'ID token nonce mismatch' );
        }

        return $payload;
    }

    /**
     * Map user info to SsoUser.
     *
     * @param  array<string, mixed>  $userInfo
     */
    protected function mapToSsoUser( array $userInfo ): SsoUser
    {
        $mapping = $this->configuration->attribute_mapping ?? [];

        return new SsoUser(
            id: $userInfo[ $mapping['id'] ?? 'sub' ] ?? $userInfo['sub'] ?? '',
            idpId: $this->configuration->slug,
            nameId: $userInfo['sub'] ?? null,
            email: $userInfo[ $mapping['email'] ?? 'email' ] ?? null,
            name: $userInfo[ $mapping['name'] ?? 'name' ] ?? null,
            firstName: $userInfo[ $mapping['first_name'] ?? 'given_name' ] ?? null,
            lastName: $userInfo[ $mapping['last_name'] ?? 'family_name' ] ?? null,
            sessionIndex: null, // OIDC doesn't have session index like SAML
            attributes: $userInfo,
        );
    }
}
