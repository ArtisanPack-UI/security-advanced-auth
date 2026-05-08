<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Livewire;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialAuthManager;
use Exception;
use Illuminate\Support\Facades\Auth;
use Livewire\Component;

class SocialAccountsManager extends Component
{
    public array $linkedAccounts = [];

    public array $availableProviders = [];

    public ?string $unlinkingProvider = null;

    protected SocialAuthManager $socialAuthManager;

    public function boot( SocialAuthManager $socialAuthManager ): void
    {
        $this->socialAuthManager = $socialAuthManager;
    }

    public function mount(): void
    {
        $this->loadAccounts();
    }

    public function loadAccounts(): void
    {
        $user = Auth::user();

        if ( ! $user || ! method_exists( $user, 'socialIdentities' ) ) {
            return;
        }

        $this->linkedAccounts = $user->socialIdentities()
            ->get()
            ->map( fn ( $identity ) => [
                'id'            => $identity->id,
                'provider'      => $identity->provider,
                'provider_name' => ucfirst( $identity->provider ),
                'email'         => $identity->email,
                'name'          => $identity->name,
                'avatar'        => $identity->avatar,
                'linked_at'     => $identity->created_at->diffForHumans(),
                'last_used'     => $identity->last_used_at?->diffForHumans() ?? 'Never',
            ] )
            ->toArray();

        $linkedProviders = array_column( $this->linkedAccounts, 'provider' );
        $allProviders    = config( 'artisanpack.security-advanced-auth.social.providers', [] );

        $this->availableProviders = collect( $allProviders )
            ->filter( fn ( $config, $provider ) => ( $config['enabled'] ?? false ) && ! in_array( $provider, $linkedProviders ) )
            ->keys()
            ->map( fn ( $provider ) => [
                'key'  => $provider,
                'name' => ucfirst( $provider ),
                'icon' => $this->getProviderIcon( $provider ),
            ] )
            ->values()
            ->toArray();
    }

    public function link( string $provider ): void
    {
        // Redirect to OAuth flow
        $this->redirect( route( 'social.redirect', ['provider' => $provider, 'link' => true] ) );
    }

    public function confirmUnlink( string $provider ): void
    {
        $this->unlinkingProvider = $provider;
    }

    public function cancelUnlink(): void
    {
        $this->unlinkingProvider = null;
    }

    public function unlink( string $provider ): void
    {
        $user = Auth::user();

        if ( ! $user ) {
            return;
        }

        // Ensure user has another way to log in
        $hasPassword      = ! empty( $user->password );
        $otherSocialCount = $user->socialIdentities()->where( 'provider', '!=', $provider )->count();
        $hasWebAuthn      = method_exists( $user, 'webAuthnCredentials' ) && $user->webAuthnCredentials()->count() > 0;

        if ( ! $hasPassword && 0 === $otherSocialCount && ! $hasWebAuthn ) {
            session()->flash( 'error', 'You must have at least one way to sign in. Set a password before unlinking this account.' );
            $this->unlinkingProvider = null;

            return;
        }

        try {
            $this->socialAuthManager->unlinkIdentity( $user, $provider );
            session()->flash( 'success', ucfirst( $provider ) . ' account has been unlinked.' );
            $this->loadAccounts();
        } catch ( Exception $e ) {
            session()->flash( 'error', 'Failed to unlink account: ' . $e->getMessage() );
        }

        $this->unlinkingProvider = null;
    }

    public function render()
    {
        return view( 'security-advanced-auth::livewire.social-accounts-manager' );
    }

    protected function getProviderIcon( string $provider ): string
    {
        return match ( $provider ) {
            'google'    => 'fab fa-google',
            'microsoft' => 'fab fa-microsoft',
            'github'    => 'fab fa-github',
            'facebook'  => 'fab fa-facebook',
            'apple'     => 'fab fa-apple',
            'linkedin'  => 'fab fa-linkedin',
            default     => 'fas fa-link',
        };
    }
}
