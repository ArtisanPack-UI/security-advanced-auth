<?php

/**
 * SecurityAdvancedAuth helper functions.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @since      1.0.0
 */

use ArtisanPackUI\SecurityAdvancedAuth\SecurityAdvancedAuth;

if ( ! function_exists( 'security_advanced_auth' ) ) {
    /**
     * Get the SecurityAdvancedAuth instance.
     *
     * @since 1.0.0
     *
     * @return SecurityAdvancedAuth
     */
    function security_advanced_auth(): SecurityAdvancedAuth
    {
        return app( 'security-advanced-auth' );
    }
}
