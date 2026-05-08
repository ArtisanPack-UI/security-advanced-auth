<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialUser;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use UnexpectedValueException;

class AppleProvider extends AbstractOAuth2Provider
{
    /**
     * Apple's JWKS URL for ID token verification.
     */
    protected const JWKS_URL = 'https://appleid.apple.com/auth/keys';

    /**
     * Apple's issuer URL for token validation.
     */
    protected const ISSUER = 'https://appleid.apple.com';

    /**
     * JWKS cache duration in seconds.
     */
    protected const JWKS_CACHE_TTL = 3600;

    /**
     * Get the provider name.
     */
    public function getName(): string
    {
        return 'apple';
    }

    /**
     * Get the default scopes.
     *
     * @return array<string>
     */
    public function getDefaultScopes(): array
    {
        return ['name', 'email'];
    }

    /**
     * Exchange the authorization code for access tokens.
     */
    public function getAccessToken( string $code ): array
    {
        $clientSecret = $this->generateClientSecret();

        $response = Http::asForm()
            ->withOptions( $this->httpOptions )
            ->post( $this->getTokenEndpoint(), [
                'grant_type'    => 'authorization_code',
                'client_id'     => $this->config['client_id'],
                'client_secret' => $clientSecret,
                'redirect_uri'  => $this->config['redirect_uri'],
                'code'          => $code,
            ] );

        if ( ! $response->successful() ) {
            throw new RuntimeException( 'Failed to exchange authorization code: ' . $response->body() );
        }

        $data = $response->json();

        return [
            'access_token'  => $data['access_token'],
            'refresh_token' => $data['refresh_token'] ?? null,
            'expires_in'    => $data['expires_in'] ?? null,
            'token_type'    => $data['token_type'] ?? 'Bearer',
            'id_token'      => $data['id_token'] ?? null,
        ];
    }

    /**
     * Get the user from the ID token.
     */
    public function getUser( string $accessToken ): SocialUser
    {
        throw new RuntimeException( 'Use getUserFromIdToken() for Apple Sign In' );
    }

    /**
     * Get the user from the ID token and optional user data.
     *
     * Verifies the JWT signature against Apple's JWKS before extracting claims.
     *
     * @param  array<string, mixed>|null  $userData  User data from form post (only on first auth)
     *
     * @throws RuntimeException if token verification fails
     */
    public function getUserFromIdToken( string $idToken, ?array $userData = null ): SocialUser
    {
        // Verify and decode the ID token
        $payload = $this->verifyIdToken( $idToken );

        $email         = $payload->email ?? null;
        $emailVerified = $payload->email_verified ?? false;

        // Apple only sends user name on first authorization
        $firstName = null;
        $lastName  = null;
        $name      = null;

        if ( $userData && isset( $userData['name'] ) ) {
            $firstName = $userData['name']['firstName'] ?? null;
            $lastName  = $userData['name']['lastName'] ?? null;
            $name      = trim( ( $firstName ?? '' ) . ' ' . ( $lastName ?? '' ) ) ?: null;
        }

        return new SocialUser(
            id: (string) $payload->sub,
            provider: $this->getName(),
            email: $email,
            name: $name,
            firstName: $firstName,
            lastName: $lastName,
            avatar: null, // Apple doesn't provide avatar
            nickname: null,
            scopes: $this->config['scopes'] ?? $this->getDefaultScopes(),
            rawData: array_merge( (array) $payload, ['user' => $userData] ),
        );
    }

    /**
     * Apple supports token refresh.
     */
    public function supportsRefresh(): bool
    {
        return true;
    }

    /**
     * Refresh an expired access token.
     */
    public function refreshAccessToken( string $refreshToken ): array
    {
        $clientSecret = $this->generateClientSecret();

        $response = Http::asForm()
            ->withOptions( $this->httpOptions )
            ->post( $this->getTokenEndpoint(), [
                'grant_type'    => 'refresh_token',
                'client_id'     => $this->config['client_id'],
                'client_secret' => $clientSecret,
                'refresh_token' => $refreshToken,
            ] );

        if ( ! $response->successful() ) {
            throw new RuntimeException( 'Failed to refresh access token: ' . $response->body() );
        }

        $data = $response->json();

        return [
            'access_token'  => $data['access_token'],
            'refresh_token' => $data['refresh_token'] ?? $refreshToken,
            'expires_in'    => $data['expires_in'] ?? null,
            'token_type'    => $data['token_type'] ?? 'Bearer',
            'id_token'      => $data['id_token'] ?? null,
        ];
    }

    /**
     * Get the authorization endpoint.
     */
    protected function getAuthorizationEndpoint(): string
    {
        return 'https://appleid.apple.com/auth/authorize';
    }

    /**
     * Get the token endpoint.
     */
    protected function getTokenEndpoint(): string
    {
        return 'https://appleid.apple.com/auth/token';
    }

    /**
     * Get the user info endpoint (Apple doesn't have one).
     */
    protected function getUserInfoEndpoint(): string
    {
        throw new RuntimeException( 'Apple does not have a user info endpoint' );
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
        $params = parent::getAdditionalAuthorizationParams( $options );

        $params['response_mode'] = 'form_post';

        return $params;
    }

    /**
     * Generate the client secret (JWT) for Apple.
     */
    protected function generateClientSecret(): string
    {
        if ( ! class_exists( JWT::class ) ) {
            throw new RuntimeException( 'Firebase JWT library is required for Apple Sign In' );
        }

        $now    = time();
        $expiry = $now + 86400 * 180; // 180 days

        $payload = [
            'iss' => $this->config['team_id'],
            'iat' => $now,
            'exp' => $expiry,
            'aud' => 'https://appleid.apple.com',
            'sub' => $this->config['client_id'],
        ];

        $privateKey = $this->config['private_key'];

        return JWT::encode( $payload, $privateKey, 'ES256', $this->config['key_id'] );
    }

    /**
     * Verify the ID token signature and validate claims.
     *
     *
     * @throws RuntimeException if verification fails
     *
     * @return object The decoded JWT payload
     */
    protected function verifyIdToken( string $idToken ): object
    {
        if ( ! class_exists( JWT::class ) || ! class_exists( JWK::class ) ) {
            throw new RuntimeException( 'Firebase JWT library is required for Apple Sign In verification' );
        }

        try {
            // Fetch Apple's public keys (JWKS)
            $jwks = $this->getAppleJwks();

            // Parse the JWKS into usable keys
            $keys = JWK::parseKeySet( $jwks );

            // Decode and verify the token
            $payload = JWT::decode( $idToken, $keys );

            // Validate issuer
            if ( ( $payload->iss ?? '' ) !== self::ISSUER ) {
                throw new RuntimeException( 'Invalid token issuer' );
            }

            // Validate audience (client_id)
            $audience = $payload->aud ?? '';
            if ( $audience !== $this->config['client_id'] ) {
                throw new RuntimeException( 'Invalid token audience' );
            }

            // Validate expiration
            if ( ( $payload->exp ?? 0 ) < time() ) {
                throw new RuntimeException( 'Token has expired' );
            }

            return $payload;
        } catch ( \Firebase\JWT\ExpiredException $e ) {
            throw new RuntimeException( 'Token has expired: ' . $e->getMessage() );
        } catch ( \Firebase\JWT\SignatureInvalidException $e ) {
            throw new RuntimeException( 'Invalid token signature: ' . $e->getMessage() );
        } catch ( UnexpectedValueException $e ) {
            throw new RuntimeException( 'Token verification failed: ' . $e->getMessage() );
        }
    }

    /**
     * Fetch Apple's JWKS (JSON Web Key Set) with caching.
     *
     *
     * @throws RuntimeException if fetching fails
     *
     * @return array<string, mixed>
     */
    protected function getAppleJwks(): array
    {
        return Cache::remember( 'apple_jwks', self::JWKS_CACHE_TTL, function () {
            $response = Http::withOptions( $this->httpOptions )
                ->get( self::JWKS_URL );

            if ( ! $response->successful() ) {
                throw new RuntimeException( 'Failed to fetch Apple JWKS: HTTP ' . $response->status() );
            }

            return $response->json();
        });
    }

    /**
     * Map the provider's user data to a SocialUser (not used for Apple).
     *
     * @param  array<string, mixed>  $data
     */
    protected function mapUserData( array $data): SocialUser
    {
        throw new RuntimeException( 'Use getUserFromIdToken() for Apple Sign In');
    }
}
