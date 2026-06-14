<?php

/**
 * Main SecurityAdvancedAuth class.
 *
 * Resolved from the container as `security-advanced-auth` and via the
 * {@see security_advanced_auth()} helper.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth;

class SecurityAdvancedAuth
{
    public function version(): string
    {
        return '1.0.1';
    }
}
