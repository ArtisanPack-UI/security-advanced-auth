<?php

/**
 * SocialAuthController controller.
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

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialAuthManager;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use RuntimeException;

class SocialAuthController
{
    public function __construct(
        protected SocialAuthManager $manager,
    ) {
    }

    /**
     * Redirect the user to the provider's authorization page.
     */
    public function redirect( string $provider ): RedirectResponse
    {
        $this->assertProviderRegistered( $provider );

        $url = $this->manager->redirect( $provider );

        return redirect()->away( $url );
    }

    /**
     * Handle the OAuth callback from the provider.
     */
    public function callback( string $provider, Request $request ): RedirectResponse
    {
        $this->assertProviderRegistered( $provider );

        $code  = (string) $request->query( 'code', '' );
        $state = (string) $request->query( 'state', '' );

        $result = $this->manager->callback( $provider, $code, $state );

        if ( ! empty( $result['user'] ) ) {
            Auth::login( $result['user'] );
        }

        $intended = config( 'artisanpack.security-advanced-auth.social.redirect_after_login', '/' );

        return redirect()->intended( $intended );
    }

    /**
     * Unlink a connected provider from the authenticated user.
     */
    public function unlink( string $provider ): RedirectResponse
    {
        $this->assertProviderRegistered( $provider );

        $user = Auth::user();

        if ( ! $user ) {
            abort( 401 );
        }

        $this->manager->unlinkIdentity( $user, $provider );

        return back()->with( 'status', "{$provider} disconnected." );
    }

    protected function assertProviderRegistered( string $provider ): void
    {
        if ( ! $this->manager->hasProvider( $provider ) ) {
            throw new RuntimeException( "Social provider not registered: {$provider}" );
        }
    }
}
