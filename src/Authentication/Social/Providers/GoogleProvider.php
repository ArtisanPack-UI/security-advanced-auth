<?php

/**
 * GoogleProvider social OAuth provider.
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

class GoogleProvider extends AbstractOidcProvider
{
    /**
     * Get the provider name.
     */
    public function getName(): string
    {
        return 'google';
    }

    /**
     * Get the default scopes.
     *
     * @return array<string>
     */
    public function getDefaultScopes(): array
    {
        return ['openid', 'profile', 'email'];
    }

    /**
     * Validate hosted domain restriction.
     */
    public function validateHostedDomain( SocialUser $user ): bool
    {
        if ( empty( $this->config['hosted_domain'] ) ) {
            return true;
        }

        $email = $user->getEmail();
        if ( null === $email ) {
            return false;
        }

        $atPos = strpos( $email, '@' );
        if ( false === $atPos ) {
            return false;
        }
        $domain = substr( $email, $atPos + 1 );

        return $domain === $this->config['hosted_domain'];
    }

    /**
     * Get the OIDC issuer URL.
     */
    protected function getIssuerUrl(): string
    {
        return 'https://accounts.google.com';
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

        // Add access_type for offline access (refresh tokens)
        $params['access_type'] = 'offline';

        // Force consent prompt to get refresh token
        $params['prompt'] = $options['prompt'] ?? 'consent';

        // Restrict to hosted domain if configured
        if ( ! empty( $this->config['hosted_domain'] ) ) {
            $params['hd'] = $this->config['hosted_domain'];
        }

        return $params;
    }

    /**
     * Map the provider's user data to a SocialUser.
     *
     * @param  array<string, mixed>  $data
     */
    protected function mapUserData( array $data ): SocialUser
    {
        return new SocialUser(
            id: (string) $data['sub'],
            provider: $this->getName(),
            email: $data['email'] ?? null,
            name: $data['name'] ?? null,
            firstName: $data['given_name'] ?? null,
            lastName: $data['family_name'] ?? null,
            avatar: $data['picture'] ?? null,
            nickname: null,
            scopes: $this->config['scopes'] ?? $this->getDefaultScopes(),
            rawData: $data,
        );
    }
}
