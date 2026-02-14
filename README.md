# Tork Governance PHP SDK

On-device AI governance for PHP applications. PII detection, redaction, and cryptographic compliance receipts.

## Installation

```bash
composer require tork/governance
```

## Quick Start

```php
<?php

use Tork\Governance\Core\Tork;

$tork = new Tork();

$result = $tork->govern("Contact john@example.com or call 555-123-4567");

echo $result->action;  // "redact"
echo $result->output;  // "Contact [EMAIL_REDACTED] or call [PHONE_REDACTED]"
```

## Regional PII Detection (v1.1)

Activate country-specific and industry-specific PII patterns:

```php
$tork = new Tork();

// UAE regional detection — Emirates ID, +971 phone, PO Box
$result = $tork->govern(
    "Emirates ID: 784-1234-1234567-1",
    region: ['ae']
);

// Multi-region + industry
$result = $tork->govern(
    "Aadhaar: 1234 5678 9012, ICD-10: J45.20",
    region: ['in'],
    industry: 'healthcare'
);

// Available regions: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR
// Available industries: healthcare, finance, legal
```

## Laravel Integration

The SDK auto-registers via Laravel's package discovery.

```php
// In routes/api.php
Route::middleware('tork')->group(function () {
    Route::post('/users', [UserController::class, 'store']);
});

// Publish config (optional)
php artisan vendor:publish --tag=tork-config
```

Access in controllers:
```php
$tork = $request->attributes->get('tork');
$receipts = $request->attributes->get('torkReceipts');
```

## Symfony Integration

### 1. Register the bundle
```php
// config/bundles.php
return [
    // ...
    Tork\Governance\Symfony\TorkBundle::class => ['all' => true],
];
```

### 2. Configure (optional)
```yaml
# config/packages/tork.yaml
tork:
    default_action: redact
    policy_version: '1.0.0'
    middleware:
        governInput: true
        governOutput: true
        governBody: true
```

### 3. Use in controllers
```php
class ApiController extends AbstractController
{
    public function index(Request $request): JsonResponse
    {
        $tork = $request->attributes->get('tork');
        $receipts = $request->attributes->get('torkReceipts');

        // Your logic here...
    }
}
```

## Documentation

Visit [tork.network](https://tork.network) for full documentation.
