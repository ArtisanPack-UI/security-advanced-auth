<?php

/**
 * WebAuthnCredentialsManager Livewire component.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Livewire;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\WebAuthn\WebAuthnManager;
use Exception;
use Illuminate\Support\Facades\Auth;
use Livewire\Attributes\On;
use Livewire\Component;

class WebAuthnCredentialsManager extends Component
{
    public array $credentials = [];

    public bool $showRegisterModal = false;

    public string $newCredentialName = '';

    public ?string $deletingCredentialId = null;

    public ?array $registrationOptions = null;

    protected WebAuthnManager $webAuthnManager;

    public function boot( WebAuthnManager $webAuthnManager ): void
    {
        $this->webAuthnManager = $webAuthnManager;
    }

    public function mount(): void
    {
        $this->loadCredentials();
    }

    public function loadCredentials(): void
    {
        $user = Auth::user();

        if ( ! $user || ! method_exists( $user, 'webAuthnCredentials' ) ) {
            return;
        }

        $this->credentials = $user->webAuthnCredentials()
            ->orderBy( 'created_at', 'desc' )
            ->get()
            ->map( fn ( $credential ) => [
                'id'         => $credential->id,
                'name'       => $credential->name,
                'type'       => $credential->is_platform_credential ? 'Biometric' : 'Security Key',
                'icon'       => $credential->is_platform_credential ? 'fas fa-fingerprint' : 'fas fa-key',
                'created_at' => $credential->created_at->format( 'M j, Y' ),
                'last_used'  => $credential->last_used_at?->diffForHumans() ?? 'Never used',
                'sign_count' => $credential->sign_count,
            ] )
            ->toArray();
    }

    public function openRegisterModal(): void
    {
        $this->newCredentialName   = '';
        $this->registrationOptions = null;
        $this->showRegisterModal   = true;
    }

    public function closeRegisterModal(): void
    {
        $this->showRegisterModal   = false;
        $this->newCredentialName   = '';
        $this->registrationOptions = null;
    }

    public function startRegistration(): void
    {
        $this->validate( [
            'newCredentialName' => 'required|string|min:1|max:255',
        ] );

        $user = Auth::user();

        if ( ! $user ) {
            return;
        }

        try {
            $options                   = $this->webAuthnManager->generateRegistrationOptions( $user, $this->newCredentialName );
            $this->registrationOptions = $options;
            $this->dispatch( 'webauthn-registration-start', options: $options );
        } catch ( Exception $e ) {
            session()->flash( 'error', 'Failed to start registration: ' . $e->getMessage() );
        }
    }

    #[On( 'webauthn-registration-complete' )]
    public function completeRegistration( array $response ): void
    {
        $user = Auth::user();

        if ( ! $user ) {
            return;
        }

        if ( ! $this->registrationOptions || ! isset( $this->registrationOptions['challenge'] ) ) {
            session()->flash( 'error', 'Registration session expired. Please try again.' );
            return;
        }

        try {
            $this->webAuthnManager->verifyRegistration(
                $user,
                $response,
                $this->registrationOptions['challenge'],
            );
            session()->flash( 'success', 'Security key registered successfully.' );
            $this->closeRegisterModal();
            $this->loadCredentials();
        } catch ( Exception $e ) {
            session()->flash( 'error', 'Registration failed: ' . $e->getMessage() );
        }
    }

    public function confirmDelete( string $credentialId ): void
    {
        $this->deletingCredentialId = $credentialId;
    }

    public function cancelDelete(): void
    {
        $this->deletingCredentialId = null;
    }

    public function deleteCredential( string $credentialId ): void
    {
        $user = Auth::user();

        if ( ! $user ) {
            return;
        }

        // Ensure user has another way to log in
        $credentialCount   = $user->webAuthnCredentials()->count();
        $hasPassword       = null !== $user->password;
        $hasSocialAccounts = method_exists( $user, 'socialIdentities' ) && $user->socialIdentities()->count() > 0;

        if ( 1 === $credentialCount && ! $hasPassword && ! $hasSocialAccounts ) {
            session()->flash( 'error', 'You must have at least one way to sign in. Set a password before removing this credential.' );
            $this->deletingCredentialId = null;

            return;
        }

        try {
            $this->webAuthnManager->deleteCredential( $user, $credentialId );
            session()->flash( 'success', 'Security key has been removed.' );
            $this->loadCredentials();
        } catch ( Exception $e ) {
            session()->flash( 'error', 'Failed to remove credential: ' . $e->getMessage() );
        }

        $this->deletingCredentialId = null;
    }

    public function render()
    {
        return view( 'security-advanced-auth::livewire.webauthn-credentials-manager' );
    }
}
