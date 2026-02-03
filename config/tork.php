<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Default Action
    |--------------------------------------------------------------------------
    |
    | The default action to take when PII is detected.
    | Options: 'redact', 'deny', 'allow'
    |
    */
    'defaultAction' => env('TORK_DEFAULT_ACTION', 'redact'),

    /*
    |--------------------------------------------------------------------------
    | Policy Version
    |--------------------------------------------------------------------------
    |
    | The version identifier for your governance policy.
    |
    */
    'policyVersion' => env('TORK_POLICY_VERSION', '1.0.0'),

    /*
    |--------------------------------------------------------------------------
    | Middleware Options
    |--------------------------------------------------------------------------
    |
    | Configuration for the Tork middleware.
    |
    */
    'middleware' => [
        'governInput' => true,
        'governOutput' => true,
        'governBody' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Patterns
    |--------------------------------------------------------------------------
    |
    | Add custom regex patterns for PII detection.
    | Format: 'PATTERN_NAME' => '/regex/'
    |
    */
    'customPatterns' => [
        // 'CUSTOM_ID' => '/\bCUST-\d{6}\b/',
    ],
];
