<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\SsoUser;
use ArtisanPackUI\SecurityAdvancedAuth\Models\SsoConfiguration;
use Illuminate\Http\Request;

interface SsoProviderInterface
{
    /**
     * Get the provider type (saml, oidc, ldap).
     */
    public function getType(): string;

    /**
     * Initialize the provider with configuration.
     */
    public function configure( SsoConfiguration $configuration ): self;

    /**
     * Get the login URL to redirect the user to.
     *
     * @param  array<string, mixed>  $options
     */
    public function getLoginUrl( array $options = [] ): string;

    /**
     * Process the authentication response/callback.
     */
    public function handleCallback( Request $request ): SsoUser;

    /**
     * Get the logout URL for single logout.
     *
     * @param  array<string, mixed>  $options
     */
    public function getLogoutUrl( array $options = [] ): ?string;

    /**
     * Process the logout response/callback.
     */
    public function handleLogout( Request $request ): bool;

    /**
     * Get the Service Provider metadata (for SAML).
     */
    public function getMetadata(): ?string;

    /**
     * Validate the configuration is complete and correct.
     *
     * @return array<string, string>
     */
    public function validateConfiguration(): array;

    /**
     * Map provider attributes to user attributes.
     *
     * @param  array<string, mixed>  $providerAttributes
     *
     * @return array<string, mixed>
     */
    public function mapAttributes( array $providerAttributes ): array;

    /**
     * Check if single logout is supported.
     */
    public function supportsSingleLogout(): bool;

    /**
     * Check if just-in-time provisioning is supported.
     */
    public function supportsJitProvisioning(): bool;
}
