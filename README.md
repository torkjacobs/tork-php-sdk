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

> **Known gap:** `$region` and `$industry` are accepted by `Tork::govern()` and stored on the returned `GovernanceResult`, but no regional or industry-specific pattern set is implemented yet in this PHP SDK — `govern()` still only runs the base pattern set below against the content regardless of which regions/industries are passed. The examples in this section describe the target behavior (matching the JS/Python SDKs), not current PHP behavior. Tracked as a P1 follow-up.

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

## Scanning tool results

A tool result returned by an MCP server — or any external system you do not control — is untrusted input that is about to be appended to a model's context. `Tork::scanToolResult()` scans it first, on-device, for PII and prompt injection:

```php
use Tork\Governance\Core\Tork;

$tork = new Tork();
$report = $tork->scanToolResult(
    [
        'toolName' => 'lookup_customer',
        'serverUri' => 'mcp://crm.internal/customers',
        'payload' => $toolResult,     // whatever the server returned (array/stdClass/scalar)
    ],
    ['blockOnInjection' => true]
);

if ($report->blocked) {
    logWarning($report->reason);    // do not append anything
} else {
    appendToContext($report->sanitized); // PII masked in place
}

$report->findings;
// [ToolResultFinding{kind: 'pii', type: 'email', count: 1, location: '$.content[0].text'},
//  ToolResultFinding{kind: 'injection', type: 'heuristic:instruction_override', count: 1, location: '$.content[0].text'}]
```

There is also a standalone `Tork\Governance\Core\ToolResultScan::scan($input, $options)` with the same input/options shape that returns a `ToolResultScanResult` (`sanitized`, `findings`, `blocked`, `reason`) and produces no receipt.

- **PII uses the same on-device detector (`Pii::detect()`) as `scanToolResult()` throughout this feature** — the Tier 1 basic vocabulary below, JS-identical type labels and redaction placeholders. Matches are masked in place; the payload structure is otherwise unchanged, and a clean payload comes back untouched. This SDK's `Tork::govern()` uses its own separate, smaller legacy pattern set (see [Supported PII Types](#supported-pii-types)) — the two are not yet unified; see the parity note at the end of this section.
- **Injection detection is heuristic.** A conservative pattern set (`tork-injection-heuristics-v1`) covering instruction-override phrases, role reassignment, and exfiltration URLs — ported line-for-line from the JS SDK's regex sources. Every injection finding is typed `heuristic:<name>` because that is exactly what it is: a regex match over untrusted text, with false positives and false negatives, not a verified determination. Without `blockOnInjection`, matches are reported and the result is still returned; with it, `sanitized` is `null` so no masked copy can be appended by accident.
- **Zero network calls.** The scan is pure and synchronous PHP — no curl handle, no stream-wrapper I/O, no socket is ever opened on this path.
- **Recorded on the receipt as counts only.** `$report->receipt->toolResultScan` carries `attested_by: 'client'`, `capture_mode: 'edge'`, the tool name and server URI, counts by kind and type, the blocked flag, and the SDK version — snake_case keys in alphabetical order, optional keys (`reason`, `server_uri`) omitted rather than nulled, byte-identical in shape to the JS and Python SDKs' `tool_result_scan` block. It never carries the payload, a matched value, or a location path.
- **The receipt's `action` follows a four-way mapping:** `blocked` → `deny`; injection findings present (checked first, even alongside PII) → `escalate`; PII findings only → `redact`; otherwise → `allow`.
- **PHP-specific traversal rule.** PHP's `array` type serves as both JSON array and JSON object, which JS/Python's list-vs-dict types don't need to resolve. The rule applied: an array is walked as a JSON array when `array_is_list()` is true (including an empty array `[]`, matching PHP's own `json_encode([])` default), and as a map/object otherwise; non-identifier map keys (e.g. numeric-string keys) get bracket notation in `location`, e.g. `$["5"]`. `stdClass` instances are always walked as objects. See `ToolResultScan`'s class docblock for the full rule and its cycle-guard/identity implications.

**This is a client-side, client-attested control.** The scan runs in your process, and the receipt says so: Tork did not execute it and cannot verify it ran at all. **Gateway-side enforcement, where a caller cannot skip the scan, is a separate and later control.** Do not read a `tool_result_scan` block as proof that every tool result reaching a model was scanned; read it as a record of the scans a caller chose to run and report.

**Parity tier:** this port implements **Tier 1** — the 10-type basic vocabulary (`ssn`, `credit_card`, `email`, `phone`, `address`, `ip_address`, `date_of_birth`, `passport`, `drivers_license`, `bank_account`) with JS-identical type labels and redaction placeholders. It does **not** implement the Python SDK's regional/industry tier (Emirates ID, Aadhaar, ICD-10, etc.) — see [Regional PII Detection (v1.1)](#regional-pii-detection-v11) below for the pre-existing, separate gap in that area.

## Documentation

Visit [tork.network](https://tork.network) for full documentation.
