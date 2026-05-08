<?php

declare( strict_types=1 );

return [

    /*
    |--------------------------------------------------------------------------
    | Social authentication
    |--------------------------------------------------------------------------
    */

    'social' => [
        'allow_linking'  => true,
        'auto_register'  => true,
        'require_email'  => true,
        'default_role'   => null,
        'callbacks'      => [
            'base_url' => env( 'APP_URL' ),
            'path'     => 'auth/social/{provider}/callback',
        ],
        'providers'      => [
            // 'github' => [...]
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | SSO (SAML / OIDC / LDAP)
    |--------------------------------------------------------------------------
    */

    'sso' => [
        'jit_provisioning' => true,
        'update_on_login'  => true,
        'default_role'     => null,
        'saml'             => [],
        'ldap'             => [
            'hosts'    => [],
            'base_dn'  => null,
            'username' => null,
            'password' => null,
            'port'     => 389,
            'use_tls'  => true,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | WebAuthn / FIDO2
    |--------------------------------------------------------------------------
    */

    'webauthn' => [
        'rp_name'      => env( 'APP_NAME', 'Application' ),
        'rp_id'        => null,
        'timeout'      => 60000,
        'attestation'  => 'none',
        'user_verification' => 'preferred',
    ],

    /*
    |--------------------------------------------------------------------------
    | Device fingerprinting
    |--------------------------------------------------------------------------
    */

    'device_fingerprinting' => [
        'enabled'       => true,
        'hash_algorithm' => 'sha256',
        'components'    => [
            'user_agent'      => true,
            'accept_language' => true,
            'accept_encoding' => true,
        ],
        'trust' => [
            'auto_trust_after_logins' => 5,
            'trust_duration_days'     => 90,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Suspicious activity detection
    |--------------------------------------------------------------------------
    */

    'suspicious_activity' => [
        'detectors' => [
            'brute_force' => [
                'enabled'        => true,
                'threshold'      => 5,
                'window_minutes' => 15,
            ],
            'impossible_travel' => [
                'enabled'        => true,
                'max_speed_kmh'  => 1000,
            ],
            'proxy_detection' => [
                'enabled' => true,
            ],
            'anomalous_login' => [
                'enabled'    => true,
                'check_time' => true,
            ],
        ],
        'risk_scoring' => [
            'low'      => 25,
            'medium'   => 50,
            'high'     => 75,
            'critical' => 90,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Step-up authentication methods (browser-side)
    |--------------------------------------------------------------------------
    */

    'step_up' => [
        'methods' => [
            'webauthn' => [],
        ],
        'default' => 'webauthn',
    ],

];
