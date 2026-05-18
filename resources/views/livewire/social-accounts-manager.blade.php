{{--
    Social accounts manager — list of linked OAuth providers and link/unlink controls.
    Plain HTML + Tailwind, no livewire-ui-components dependency.
--}}
<div class="space-y-4">
    <div>
        <h2 class="text-xl font-bold">{{ __( 'Connected accounts' ) }}</h2>
        <p class="text-sm text-gray-600 mt-1">{{ __( 'Link external providers so you can sign in with them.' ) }}</p>
    </div>

    @if ( empty( $linkedAccounts ) )
        <p class="text-sm text-gray-500 py-2">{{ __( 'No connected accounts yet.' ) }}</p>
    @else
        <ul class="divide-y border rounded-lg">
            @foreach ( $linkedAccounts as $account )
                @php $unlinking = ( $account['provider'] ?? null ) === $unlinkingProvider; @endphp
                <li wire:key="linked-{{ $account['provider'] }}" class="flex justify-between items-center px-4 py-3">
                    <div>
                        <p class="font-medium capitalize">{{ $account['provider'] ?? __( 'Unknown' ) }}</p>
                        <p class="text-xs text-gray-500">
                            @if ( isset( $account['provider_user_email'] ) )
                                {{ $account['provider_user_email'] }}
                            @elseif ( isset( $account['provider_user_id'] ) )
                                ID: {{ $account['provider_user_id'] }}
                            @endif
                            @if ( isset( $account['linked_at'] ) )
                                · {{ __( 'Linked' ) }}: {{ $account['linked_at'] }}
                            @endif
                        </p>
                    </div>
                    <div>
                        @if ( $unlinking )
                            <div class="flex gap-2">
                                <button type="button" wire:click="unlink({{ json_encode($account['provider']) }})" class="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded font-medium">{{ __( 'Confirm unlink' ) }}</button>
                                <button type="button" wire:click="cancelUnlink" class="text-xs px-3 py-1.5 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 rounded font-medium">{{ __( 'Cancel' ) }}</button>
                            </div>
                        @else
                            <button type="button" wire:click="confirmUnlink({{ json_encode($account['provider']) }})" class="text-sm text-red-600 hover:text-red-800 font-medium">{{ __( 'Unlink' ) }}</button>
                        @endif
                    </div>
                </li>
            @endforeach
        </ul>
    @endif

    {{-- Available providers to link --}}
    @if ( ! empty( $availableProviders ) )
        <div>
            <h3 class="text-base font-semibold mb-2">{{ __( 'Available providers' ) }}</h3>
            <div class="flex flex-wrap gap-2">
                @foreach ( $availableProviders as $provider )
                    <button
                        type="button"
                        wire:click="link({{ json_encode($provider) }})"
                        class="inline-flex items-center px-4 py-2 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 text-sm font-medium rounded-md capitalize"
                    >
                        {{ __( 'Link' ) }} {{ $provider }}
                    </button>
                @endforeach
            </div>
        </div>
    @endif
</div>
