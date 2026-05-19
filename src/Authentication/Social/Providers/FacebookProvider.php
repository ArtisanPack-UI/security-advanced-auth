<?php

/**
 * FacebookProvider social OAuth provider.
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
use RuntimeException;

class FacebookProvider extends AbstractOAuth2Provider
{
    /**
     * The default Graph API version.
     */
    protected const DEFAULT_GRAPH_VERSION = 'v21.0';

    /**
     * Get the provider name.
     */
    public function getName(): string
    {
        return 'facebook';
    }

    /**
     * Get the default scopes.
     *
     * @return array<string>
     */
    public function getDefaultScopes(): array
    {
        return ['email', 'public_profile'];
    }

    /**
     * Get the user from Facebook.
     */
    public function getUser( string $accessToken ): SocialUser
    {
        $fields = 'id,name,first_name,last_name,email,picture.type(large)';

        $url = $this->getUserInfoEndpoint() . '?' . http_build_query( [
            'access_token' => $accessToken,
            'fields'       => $fields,
        ] );

        $response = \Illuminate\Support\Facades\Http::withOptions( $this->httpOptions )->get( $url );

        if ( ! $response->successful() ) {
            throw new RuntimeException( 'Failed to get user info from Facebook: HTTP ' . $response->status() );
        }

        return $this->mapUserData( $response->json() );
    }

    /**
     * Get the Graph API version from config or use default.
     */
    protected function getGraphVersion(): string
    {
        return $this->config['graph_version']
            ?? config( 'artisanpack.security-advanced-auth.social.providers.facebook.graph_version' )
            ?? env( 'FACEBOOK_GRAPH_VERSION' )
            ?? self::DEFAULT_GRAPH_VERSION;
    }

    /**
     * Get the authorization endpoint.
     */
    protected function getAuthorizationEndpoint(): string
    {
        return 'https://www.facebook.com/' . $this->getGraphVersion() . '/dialog/oauth';
    }

    /**
     * Get the token endpoint.
     */
    protected function getTokenEndpoint(): string
    {
        return 'https://graph.facebook.com/' . $this->getGraphVersion() . '/oauth/access_token';
    }

    /**
     * Get the user info endpoint.
     */
    protected function getUserInfoEndpoint(): string
    {
        return 'https://graph.facebook.com/' . $this->getGraphVersion() . '/me';
    }

    /**
     * Map the provider's user data to a SocialUser.
     *
     * @param  array<string, mixed>  $data
     */
    protected function mapUserData( array $data ): SocialUser
    {
        $avatar = null;
        if ( isset( $data['picture']['data']['url'] ) ) {
            $avatar = $data['picture']['data']['url'];
        }

        return new SocialUser(
            id: (string) $data['id'],
            provider: $this->getName(),
            email: $data['email'] ?? null,
            name: $data['name'] ?? null,
            firstName: $data['first_name'] ?? null,
            lastName: $data['last_name'] ?? null,
            avatar: $avatar,
            nickname: null,
            scopes: $this->config['scopes'] ?? $this->getDefaultScopes(),
            rawData: $data,
        );
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

        // Request re-authentication if needed
        if ( ! empty( $options['reauthenticate'] ) ) {
            $params['auth_type'] = 'reauthenticate';
        }

        return $params;
    }
}
