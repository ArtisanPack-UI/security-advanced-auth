<?php

/**
 * SsoController controller.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Http\Controllers;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\SsoManager;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;

class SsoController
{
    public function __construct(
        protected SsoManager $manager,
    ) {
    }

    /**
     * Begin the SSO login flow — redirect to the IdP.
     */
    public function login( string $slug ): RedirectResponse
    {
        $url = $this->manager->login( $slug );

        return redirect()->away( $url );
    }

    /**
     * Handle the SSO callback from the IdP (SAML ACS, OIDC code response).
     */
    public function callback( string $slug, Request $request ): RedirectResponse
    {
        $ssoUser = $this->manager->callback( $slug, $request );
        $user    = $this->manager->findOrCreateUser( $ssoUser );

        if ( $user ) {
            Auth::login( $user );
        }

        $intended = config( 'artisanpack.security-advanced-auth.sso.redirect_after_login', '/' );

        return redirect()->intended( $intended );
    }

    /**
     * Begin SLO (Single Logout) — redirect to the IdP's logout endpoint.
     */
    public function logout( string $slug ): RedirectResponse
    {
        $url = $this->manager->logout( $slug );

        Auth::logout();

        if ( $url ) {
            return redirect()->away( $url );
        }

        return redirect( '/' );
    }

    /**
     * Handle the IdP's SLO callback.
     */
    public function logoutCallback( string $slug, Request $request ): RedirectResponse
    {
        $this->manager->handleLogout( $slug, $request );

        return redirect( '/' );
    }

    /**
     * SAML SP metadata endpoint — returns the metadata XML the IdP needs to
     * federate with this app.
     */
    public function metadata( string $slug ): Response
    {
        $xml = $this->manager->getMetadata( $slug );

        if ( ! $xml ) {
            abort( 404 );
        }

        return response( $xml, 200, ['Content-Type' => 'application/xml'] );
    }
}
