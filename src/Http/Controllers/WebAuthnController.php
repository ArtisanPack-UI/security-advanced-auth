<?php

/**
 * WebAuthnController controller.
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

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\WebAuthn\WebAuthnManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class WebAuthnController
{
    public function __construct(
        protected WebAuthnManager $manager,
    ) {
    }

    /**
     * Generate registration options. Host JS passes these to
     * navigator.credentials.create().
     */
    public function registerOptions( Request $request ): JsonResponse
    {
        $user = Auth::user();

        if ( ! $user ) {
            abort( 401 );
        }

        $options = $this->manager->generateRegistrationOptions(
            user: $user,
            options: $request->all(),
        );

        return response()->json( $options );
    }

    /**
     * Verify the response from navigator.credentials.create().
     */
    public function registerVerify( Request $request ): JsonResponse
    {
        $user = Auth::user();

        if ( ! $user ) {
            abort( 401 );
        }

        $validated = $request->validate( [
            'response'  => ['required', 'array'],
            'challenge' => ['required', 'string'],
        ] );

        $result = $this->manager->verifyRegistration(
            user: $user,
            response: $validated['response'],
            challenge: $validated['challenge'],
        );

        return response()->json( $result );
    }

    /**
     * Generate authentication options. Host JS passes these to
     * navigator.credentials.get().
     */
    public function authenticateOptions( Request $request ): JsonResponse
    {
        $user = Auth::user();   // null is OK — supports passkey discovery flows

        $options = $this->manager->generateAuthenticationOptions(
            user: $user,
            options: $request->all(),
        );

        return response()->json( $options );
    }

    /**
     * Verify the response from navigator.credentials.get().
     */
    public function authenticateVerify( Request $request ): JsonResponse
    {
        $validated = $request->validate( [
            'response'  => ['required', 'array'],
            'challenge' => ['required', 'string'],
        ] );

        $result = $this->manager->verifyAuthentication(
            response: $validated['response'],
            challenge: $validated['challenge'],
        );

        if ( ! empty( $result['user'] ) ) {
            Auth::login( $result['user'] );
            unset( $result['user'] );
        }

        return response()->json( $result );
    }
}
