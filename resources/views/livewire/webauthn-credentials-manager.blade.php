{{--
    WebAuthn / passkey credentials manager.

    Plain HTML + Tailwind. Actual WebAuthn ceremony is browser JS — the
    host app listens for the `start-webauthn-registration` Livewire event,
    calls navigator.credentials.create(), and dispatches the response back
    to `completeRegistration`.
--}}
<div class="space-y-4">
    <div class="flex justify-between items-center">
        <h2 class="text-xl font-bold">{{ __( 'Passkeys & security keys' ) }}</h2>
        <button
            type="button"
            wire:click="openRegisterModal"
            class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md"
        >
            {{ __( 'Add passkey' ) }}
        </button>
    </div>

    @if ( empty( $credentials ) )
        <p class="text-sm text-gray-500 py-4">{{ __( 'No passkeys registered yet.' ) }}</p>
    @else
        <ul class="divide-y border rounded-lg">
            @foreach ( $credentials as $credential )
                @php $deleting = ( $credential['id'] ?? null ) === $deletingCredentialId; @endphp
                <li wire:key="webauthn-{{ $credential['id'] }}" class="flex justify-between items-center px-4 py-3">
                    <div>
                        <p class="font-medium">{{ $credential['name'] ?? __( 'Unnamed key' ) }}</p>
                        <p class="text-xs text-gray-500">
                            @if ( isset( $credential['transports'] ) )
                                {{ implode( ', ', $credential['transports'] ) }} ·
                            @endif
                            {{ __( 'Added' ) }}: {{ $credential['created_at'] ?? __( 'Unknown' ) }}
                            @if ( isset( $credential['last_used_at'] ) )
                                · {{ __( 'Last used' ) }}: {{ $credential['last_used_at'] }}
                            @endif
                        </p>
                    </div>
                    <div>
                        @if ( $deleting )
                            <div class="flex gap-2">
                                <button type="button" wire:click="deleteCredential('{{ $credential['id'] }}')" class="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded font-medium">{{ __( 'Confirm delete' ) }}</button>
                                <button type="button" wire:click="cancelDelete" class="text-xs px-3 py-1.5 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 rounded font-medium">{{ __( 'Cancel' ) }}</button>
                            </div>
                        @else
                            <button type="button" wire:click="confirmDelete('{{ $credential['id'] }}')" class="text-sm text-red-600 hover:text-red-800 font-medium">{{ __( 'Delete' ) }}</button>
                        @endif
                    </div>
                </li>
            @endforeach
        </ul>
    @endif

    {{-- Registration modal --}}
    @if ( $showRegisterModal )
        <div role="dialog" aria-modal="true" aria-labelledby="webauthn-register-title" class="fixed inset-0 z-50 overflow-y-auto">
            <div class="fixed inset-0 bg-black bg-opacity-50" aria-hidden="true"></div>
            <div class="flex min-h-full items-center justify-center p-4">
                <div class="relative bg-white rounded-lg shadow-xl max-w-md w-full p-6">
                    <div class="flex justify-between items-start mb-4">
                        <h3 id="webauthn-register-title" class="text-lg font-bold">{{ __( 'Add a passkey' ) }}</h3>
                        <button type="button" wire:click="closeRegisterModal" class="text-gray-400 hover:text-gray-600" aria-label="{{ __( 'Close' ) }}">&times;</button>
                    </div>
                    <form wire:submit.prevent="startRegistration">
                        <label for="webauthn-name" class="block text-sm font-medium text-gray-700 mb-1">
                            {{ __( 'Name this passkey' ) }}
                        </label>
                        <input id="webauthn-name" type="text" wire:model="newCredentialName" placeholder="{{ __( 'e.g. iPhone Face ID, YubiKey 5' ) }}" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm" autofocus />
                        <div class="mt-4 flex justify-end gap-2">
                            <button type="button" wire:click="closeRegisterModal" class="px-4 py-2 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 text-sm font-medium rounded-md">{{ __( 'Cancel' ) }}</button>
                            <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md">{{ __( 'Continue' ) }}</button>
                        </div>
                    </form>
                    @if ( $registrationOptions )
                        <p class="mt-4 text-xs text-gray-500">{{ __( 'Follow the prompts from your authenticator…' ) }}</p>
                    @endif
                </div>
            </div>
        </div>
    @endif
</div>
