<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Livewire;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Biometric\BiometricManager as BiometricService;
use Exception;
use Illuminate\Support\Facades\Auth;
use Livewire\Attributes\On;
use Livewire\Component;

class BiometricManager extends Component
{
    public array $biometrics = [];

    public bool $showEnrollModal = false;

    public string $newBiometricName = '';

    public ?string $deletingBiometricId = null;

    public ?array $enrollmentOptions = null;

    public bool $platformSupported = true;

    protected BiometricService $biometricManager;

    public function boot( BiometricService $biometricManager ): void
    {
        $this->biometricManager = $biometricManager;
    }

    public function mount(): void
    {
        $this->loadBiometrics();
    }

    public function loadBiometrics(): void
    {
        $user = Auth::user();

        if ( ! $user || ! method_exists( $user, 'webAuthnCredentials' ) ) {
            return;
        }

        // Filter to only platform authenticators (biometric)
        $this->biometrics = $user->webAuthnCredentials()
            ->where( 'is_platform_credential', true )
            ->orderBy( 'created_at', 'desc' )
            ->get()
            ->map( fn ( $credential ) => [
                'id'         => $credential->id,
                'name'       => $credential->name,
                'created_at' => $credential->created_at->format( 'M j, Y' ),
                'last_used'  => $credential->last_used_at?->diffForHumans() ?? 'Never used',
                'sign_count' => $credential->sign_count,
            ] )
            ->toArray();
    }

    public function openEnrollModal(): void
    {
        $this->newBiometricName  = '';
        $this->enrollmentOptions = null;
        $this->showEnrollModal   = true;
    }

    public function closeEnrollModal(): void
    {
        $this->showEnrollModal   = false;
        $this->newBiometricName  = '';
        $this->enrollmentOptions = null;
    }

    public function startEnrollment(): void
    {
        $this->validate( [
            'newBiometricName' => 'required|string|min:1|max:255',
        ] );

        $user = Auth::user();

        if ( ! $user ) {
            return;
        }

        try {
            $options = $this->biometricManager->enroll( $user, 'webauthn', [
                'name' => $this->newBiometricName,
            ] );

            $this->enrollmentOptions = $options;
            $this->dispatch( 'biometric-enrollment-start', options: $options );
        } catch ( Exception $e ) {
            session()->flash( 'error', 'Failed to start enrollment: ' . $e->getMessage() );
        }
    }

    #[On( 'biometric-enrollment-complete' )]
    public function completeEnrollment( array $response ): void
    {
        $user = Auth::user();

        if ( ! $user ) {
            return;
        }

        try {
            $this->biometricManager->verify( $user, 'webauthn', [
                'type'     => 'registration',
                'response' => $response,
            ] );

            session()->flash( 'success', 'Biometric enrolled successfully.' );
            $this->closeEnrollModal();
            $this->loadBiometrics();
        } catch ( Exception $e ) {
            session()->flash( 'error', 'Enrollment failed: ' . $e->getMessage() );
        }
    }

    public function confirmDelete( string $biometricId ): void
    {
        $this->deletingBiometricId = $biometricId;
    }

    public function cancelDelete(): void
    {
        $this->deletingBiometricId = null;
    }

    public function deleteBiometric( string $biometricId ): void
    {
        $user = Auth::user();

        if ( ! $user ) {
            return;
        }

        // Ensure user has another way to log in
        $biometricCount    = $user->webAuthnCredentials()->where( 'is_platform_credential', true )->count();
        $hasSecurityKey    = $user->webAuthnCredentials()->where( 'is_platform_credential', false )->count() > 0;
        $hasPassword       = null !== $user->password;
        $hasSocialAccounts = method_exists( $user, 'socialIdentities' ) && $user->socialIdentities()->count() > 0;

        if ( 1 === $biometricCount && ! $hasSecurityKey && ! $hasPassword && ! $hasSocialAccounts ) {
            session()->flash( 'error', 'You must have at least one way to sign in.' );
            $this->deletingBiometricId = null;

            return;
        }

        try {
            $this->biometricManager->revoke( $user, 'webauthn', $biometricId );
            session()->flash( 'success', 'Biometric has been removed.' );
            $this->loadBiometrics();
        } catch ( Exception $e ) {
            session()->flash( 'error', 'Failed to remove biometric: ' . $e->getMessage() );
        }

        $this->deletingBiometricId = null;
    }

    public function render()
    {
        return view( 'security-advanced-auth::livewire.biometric-manager');
    }
}
