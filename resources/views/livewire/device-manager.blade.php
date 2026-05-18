{{--
    Device manager — lists known devices and offers trust / revoke controls.
    Plain HTML + Tailwind, no livewire-ui-components dependency.
--}}
<div class="space-y-4">
    <div class="flex justify-between items-center">
        <h2 class="text-xl font-bold">{{ __( 'Trusted devices' ) }}</h2>
        @if ( count( $devices ) > 1 )
            <button
                type="button"
                wire:click="revokeAllOtherDevices"
                wire:confirm="{{ __( 'Revoke all other devices?' ) }}"
                class="text-sm text-red-600 hover:text-red-800 font-medium"
            >
                {{ __( 'Revoke all other devices' ) }}
            </button>
        @endif
    </div>

    @if ( empty( $devices ) )
        <p class="text-sm text-gray-500 py-4">{{ __( 'No known devices yet.' ) }}</p>
    @else
        <div class="space-y-2">
            @foreach ( $devices as $device )
                @php
                    $isCurrent = ( $device['id'] ?? null ) === $currentDeviceId;
                    $isRevoking = ( $device['id'] ?? null ) === $revokingDeviceId;
                @endphp
                <div wire:key="device-{{ $device['id'] }}" class="border rounded-lg p-4 {{ $isCurrent ? 'bg-blue-50 border-blue-200' : 'bg-white border-gray-200' }}">
                    <div class="flex items-start justify-between gap-4">
                        <div class="flex-1 space-y-1">
                            <div class="flex items-center gap-2">
                                <span class="font-medium">{{ $device['name'] ?? $device['device'] ?? __( 'Unknown device' ) }}</span>
                                @if ( $isCurrent )
                                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">{{ __( 'This device' ) }}</span>
                                @endif
                                @if ( $device['trusted'] ?? false )
                                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">{{ __( 'Trusted' ) }}</span>
                                @endif
                            </div>
                            <div class="text-sm text-gray-600 space-y-0.5">
                                @if ( isset( $device['browser'] ) )
                                    <div>{{ __( 'Browser' ) }}: {{ $device['browser'] }}</div>
                                @endif
                                @if ( isset( $device['os'] ) )
                                    <div>{{ __( 'OS' ) }}: {{ $device['os'] }}</div>
                                @endif
                                @if ( isset( $device['ip_address'] ) )
                                    <div>{{ __( 'IP' ) }}: <span class="font-mono">{{ $device['ip_address'] }}</span></div>
                                @endif
                                @if ( isset( $device['last_seen_at'] ) )
                                    <div>{{ __( 'Last seen' ) }}: {{ $device['last_seen_at'] }}</div>
                                @endif
                            </div>
                        </div>

                        <div class="flex flex-col gap-2 items-end">
                            @if ( ! ( $device['trusted'] ?? false ) )
                                <button type="button" wire:click="trustDevice({{ json_encode($device['id']) }})" class="text-sm text-blue-600 hover:text-blue-800 font-medium">
                                    {{ __( 'Trust this device' ) }}
                                </button>
                            @endif
                            @if ( ! $isCurrent )
                                @if ( $isRevoking )
                                    <div class="flex gap-2">
                                        <button type="button" wire:click="revokeDevice({{ json_encode($device['id']) }})" class="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded font-medium">{{ __( 'Confirm revoke' ) }}</button>
                                        <button type="button" wire:click="cancelRevoke" class="text-xs px-3 py-1.5 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 rounded font-medium">{{ __( 'Cancel' ) }}</button>
                                    </div>
                                @else
                                    <button type="button" wire:click="confirmRevoke({{ json_encode($device['id']) }})" class="text-sm text-red-600 hover:text-red-800 font-medium">{{ __( 'Revoke' ) }}</button>
                                @endif
                            @endif
                        </div>
                    </div>
                </div>
            @endforeach
        </div>
    @endif
</div>
