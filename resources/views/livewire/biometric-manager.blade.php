{{--
    Biometric credentials manager.

    Plain HTML + Tailwind. The package doesn't depend on
    artisanpack-ui/livewire-ui-components. The actual biometric prompt
    is host-app JS — the host listens for the `start-biometric-enrollment`
    Livewire event, invokes WebAuthn / platform biometrics, and dispatches
    back to `completeEnrollment` with the response.
--}}
<div class="space-y-4">
    <div class="flex justify-between items-center">
        <h2 class="text-xl font-bold">{{ __( 'Biometric authentication' ) }}</h2>
        <button
            type="button"
            wire:click="openEnrollModal"
            @disabled(! $platformSupported)
            class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md disabled:bg-gray-400 disabled:cursor-not-allowed"
        >
            {{ __( 'Add biometric' ) }}
        </button>
    </div>

    @if ( ! $platformSupported )
        <div role="alert" class="bg-yellow-50 border-l-4 border-yellow-500 p-3 rounded text-sm">
            {{ __( 'Your device does not support biometric authentication.' ) }}
        </div>
    @endif

    @if ( empty( $biometrics ) )
        <p class="text-sm text-gray-500 py-4">{{ __( 'No biometric authenticators registered yet.' ) }}</p>
    @else
        <ul class="divide-y border rounded-lg">
            @foreach ( $biometrics as $biometric )
                @php $deleting = ( $biometric['id'] ?? null ) === $deletingBiometricId; @endphp
                <li wire:key="biometric-{{ $biometric['id'] }}" class="flex justify-between items-center px-4 py-3">
                    <div>
                        <p class="font-medium">{{ $biometric['name'] ?? __( 'Biometric' ) }}</p>
                        <p class="text-xs text-gray-500">
                            {{ __( 'Added' ) }}: {{ $biometric['created_at'] ?? __( 'Unknown' ) }}
                            @if ( isset( $biometric['last_used_at'] ) )
                                · {{ __( 'Last used' ) }}: {{ $biometric['last_used_at'] }}
                            @endif
                        </p>
                    </div>
                    <div>
                        @if ( $deleting )
                            <div class="flex gap-2">
                                <button type="button" wire:click="deleteBiometric('{{ $biometric['id'] }}')" class="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded font-medium">
                                    {{ __( 'Confirm delete' ) }}
                                </button>
                                <button type="button" wire:click="cancelDelete" class="text-xs px-3 py-1.5 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 rounded font-medium">
                                    {{ __( 'Cancel' ) }}
                                </button>
                            </div>
                        @else
                            <button type="button" wire:click="confirmDelete('{{ $biometric['id'] }}')" class="text-sm text-red-600 hover:text-red-800 font-medium">
                                {{ __( 'Delete' ) }}
                            </button>
                        @endif
                    </div>
                </li>
            @endforeach
        </ul>
    @endif

    {{-- Enrollment modal --}}
    @if ( $showEnrollModal )
        <div role="dialog" aria-modal="true" aria-labelledby="biometric-enroll-title" class="fixed inset-0 z-50 overflow-y-auto">
            <div class="fixed inset-0 bg-black bg-opacity-50" aria-hidden="true"></div>
            <div class="flex min-h-full items-center justify-center p-4">
                <div class="relative bg-white rounded-lg shadow-xl max-w-md w-full p-6">
                    <div class="flex justify-between items-start mb-4">
                        <h3 id="biometric-enroll-title" class="text-lg font-bold">{{ __( 'Add biometric authenticator' ) }}</h3>
                        <button type="button" wire:click="closeEnrollModal" class="text-gray-400 hover:text-gray-600" aria-label="{{ __( 'Close' ) }}">&times;</button>
                    </div>
                    <form wire:submit.prevent="startEnrollment">
                        <label for="biometric-name" class="block text-sm font-medium text-gray-700 mb-1">
                            {{ __( 'Name this authenticator' ) }}
                        </label>
                        <input id="biometric-name" type="text" wire:model="newBiometricName" placeholder="{{ __( 'e.g. MacBook Touch ID' ) }}" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm" autofocus />
                        <div class="mt-4 flex justify-end gap-2">
                            <button type="button" wire:click="closeEnrollModal" class="px-4 py-2 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 text-sm font-medium rounded-md">{{ __( 'Cancel' ) }}</button>
                            <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md">{{ __( 'Continue' ) }}</button>
                        </div>
                    </form>
                    @if ( $enrollmentOptions )
                        <p class="mt-4 text-xs text-gray-500">{{ __( 'Awaiting authenticator response…' ) }}</p>
                    @endif
                </div>
            </div>
        </div>
    @endif
</div>
