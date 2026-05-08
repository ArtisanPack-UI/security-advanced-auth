<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Livewire;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Biometric\BiometricManager as BiometricService;
use Exception;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
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
            $options = $this->biometricManager->startEnrollment( $user, [], [
                'name' => $this->newBiometricName,
            ] );

            $this->enrollmentOptions = $options;
            $this->dispatch( 'biometric-enrollment-start', options: $options );
        } catch ( Exception $e ) {
            report( $e );
            session()->flash( 'error', 'Failed to start enrollment. Please try again.' );
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
            // Challenge was issued during startEnrollment() and stashed on
            // the component; pass it back so the manager can validate the
            // attestation response that the browser just produced.
            $challenge = (string) ( $this->enrollmentOptions['challenge'] ?? '' );

            if ( '' === $challenge ) {
                session()->flash( 'error', 'Enrollment session expired. Please start again.' );

                return;
            }

            $this->biometricManager->completeEnrollment( $user, 'webauthn', $response, $challenge );

            session()->flash( 'success', 'Biometric enrolled successfully.' );
            $this->closeEnrollModal();
            $this->loadBiometrics();
        } catch ( Exception $e ) {
            report( $e );
            session()->flash( 'error', 'Enrollment failed. Please try again.' );
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

        // Mirror loadBiometrics()'s relation guard so a user model that
        // doesn't expose webAuthnCredentials() doesn't blow up here.
        if ( ! method_exists( $user, 'webAuthnCredentials' ) ) {
            session()->flash( 'error', 'Biometric credentials are not available for this account.' );
            $this->deletingBiometricId = null;

            return;
        }

        // Run the eligibility check + delete inside one transaction with
        // SELECT ... FOR UPDATE so two concurrent requests can't both pass
        // the "user has another sign-in method" check and remove the last
        // remaining factor between them. Scoped to the authenticated user
        // AND to is_platform_credential=true so a forged id can't reach a
        // roaming security key through the biometric-only UI flow.
        $hasSocialAccounts = method_exists( $user, 'socialIdentities' )
            && $user->socialIdentities()->count() > 0;
        $hasPassword       = filled( $user->password );

        try {
            $result = DB::transaction( function () use ( $user, $biometricId, $hasPassword, $hasSocialAccounts ) {
                $biometricCount = $user->webAuthnCredentials()
                    ->where( 'is_platform_credential', true )
                    ->lockForUpdate()
                    ->count();

                $hasSecurityKey = $user->webAuthnCredentials()
                    ->where( 'is_platform_credential', false )
                    ->lockForUpdate()
                    ->exists();

                if ( 1 === $biometricCount && ! $hasSecurityKey && ! $hasPassword && ! $hasSocialAccounts ) {
                    return 'last-factor';
                }

                $deleted = $user->webAuthnCredentials()
                    ->where( 'id', $biometricId )
                    ->where( 'is_platform_credential', true )
                    ->delete();

                return 0 === $deleted ? 'not-found' : 'deleted';
            } );

            if ( 'last-factor' === $result ) {
                session()->flash( 'error', 'You must have at least one way to sign in.' );
            } elseif ( 'not-found' === $result ) {
                session()->flash( 'error', 'Biometric not found.' );
            } else {
                session()->flash( 'success', 'Biometric has been removed.' );
            }

            $this->loadBiometrics();
        } catch ( Exception $e ) {
            report( $e );
            session()->flash( 'error', 'Failed to remove biometric. Please try again.' );
        }

        $this->deletingBiometricId = null;
    }

    public function render()
    {
        return view( 'security-advanced-auth::livewire.biometric-manager' );
    }
}
