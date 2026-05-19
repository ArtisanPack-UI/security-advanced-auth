<?php

/**
 * GitHubProvider social OAuth provider.
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

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialUser;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class GitHubProvider extends AbstractOAuth2Provider
{
    /**
     * Get the provider name.
     */
    public function getName(): string
    {
        return 'github';
    }

    /**
     * Get the default scopes.
     *
     * @return array<string>
     */
    public function getDefaultScopes(): array
    {
        return ['user:email', 'read:user'];
    }

    /**
     * Exchange the authorization code for access tokens.
     */
    public function getAccessToken( string $code ): array
    {
        $response = Http::asForm()
            ->acceptJson()
            ->withOptions( $this->httpOptions )
            ->post( $this->getTokenEndpoint(), [
                'client_id'     => $this->config['client_id'],
                'client_secret' => $this->config['client_secret'],
                'redirect_uri'  => $this->config['redirect_uri'],
                'code'          => $code,
            ] );

        if ( ! $response->successful() ) {
            throw new RuntimeException( 'Failed to exchange authorization code: ' . $response->body() );
        }

        $data = $response->json();

        if ( isset( $data['error'] ) ) {
            throw new RuntimeException( 'GitHub OAuth error: ' . ( $data['error_description'] ?? $data['error'] ) );
        }

        return [
            'access_token'  => $data['access_token'],
            'refresh_token' => $data['refresh_token'] ?? null,
            'expires_in'    => $data['expires_in'] ?? null,
            'token_type'    => $data['token_type'] ?? 'Bearer',
        ];
    }

    /**
     * Get the user from GitHub.
     */
    public function getUser( string $accessToken ): SocialUser
    {
        $response = Http::withToken( $accessToken )
            ->withOptions( $this->httpOptions )
            ->get( $this->getUserInfoEndpoint() );

        if ( ! $response->successful() ) {
            throw new RuntimeException( 'Failed to get user info: ' . $response->body() );
        }

        $userData = $response->json();

        // GitHub doesn't always return email in user endpoint, need to fetch emails separately
        if ( empty( $userData['email'] ) ) {
            $email = $this->getPrimaryEmail( $accessToken );
            if ( $email ) {
                $userData['email'] = $email;
            }
        }

        return $this->mapUserData( $userData );
    }

    /**
     * GitHub doesn't support refresh tokens in the standard OAuth2 way.
     */
    public function supportsRefresh(): bool
    {
        return false;
    }

    /**
     * Get the authorization endpoint.
     */
    protected function getAuthorizationEndpoint(): string
    {
        return 'https://github.com/login/oauth/authorize';
    }

    /**
     * Get the token endpoint.
     */
    protected function getTokenEndpoint(): string
    {
        return 'https://github.com/login/oauth/access_token';
    }

    /**
     * Get the user info endpoint.
     */
    protected function getUserInfoEndpoint(): string
    {
        return 'https://api.github.com/user';
    }

    /**
     * Get the user's primary email from GitHub.
     */
    protected function getPrimaryEmail( string $accessToken ): ?string
    {
        $response = Http::withToken( $accessToken )
            ->withOptions( $this->httpOptions )
            ->get( 'https://api.github.com/user/emails' );

        if ( ! $response->successful() ) {
            return null;
        }

        $emails = $response->json();

        foreach ( $emails as $email ) {
            if ( $email['primary'] && $email['verified'] ) {
                return $email['email'];
            }
        }

        // Fallback to first verified email
        foreach ( $emails as $email ) {
            if ( $email['verified'] ) {
                return $email['email'];
            }
        }

        return null;
    }

    /**
     * Map the provider's user data to a SocialUser.
     *
     * @param  array<string, mixed>  $data
     */
    protected function mapUserData( array $data ): SocialUser
    {
        // Parse name into first/last name
        $nameParts = explode( ' ', $data['name'] ?? '', 2 );
        $firstName = $nameParts[0] ?? null;
        $lastName  = $nameParts[1] ?? null;

        return new SocialUser(
            id: (string) $data['id'],
            provider: $this->getName(),
            email: $data['email'] ?? null,
            name: $data['name'] ?? null,
            firstName: $firstName,
            lastName: $lastName,
            avatar: $data['avatar_url'] ?? null,
            nickname: $data['login'] ?? null,
            scopes: $this->config['scopes'] ?? $this->getDefaultScopes(),
            rawData: $data,
        );
    }
}
