<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * Tork Governance SDK for PHP.
 *
 * Provides PII detection, redaction, and compliance receipts
 * for AI applications.
 *
 * govern() and scanToolResult() both detect PII through the single Tier 1
 * table in Pii::PII_PATTERNS (see Pii.php) -- lowercase snake_case type
 * keys and JS-identical [XXX_REDACTED] labels throughout this SDK. Prior to
 * 1.0.0, govern() ran its own separate 5-pattern table with uppercase type
 * keys (SSN, EMAIL, PHONE, CREDIT_CARD, IP_ADDRESS); see CHANGELOG.md for
 * the full old-label/key -> new-label/key mapping.
 */
class Tork
{
    private array $config;

    /** @var array<string, string>|null */
    private ?array $customPatterns;

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'defaultAction' => 'redact',
            'policyVersion' => '1.0.0',
        ], $config);

        $this->customPatterns = $config['customPatterns'] ?? null;
    }

    /**
     * Govern content for PII and policy violations.
     *
     * @param string $content The content to govern
     * @param array|null $region Optional regional PII profiles (e.g. ['ae', 'in'])
     * @param string|null $industry Optional industry profile (e.g. 'healthcare', 'finance', 'legal')
     * @param array|null $sessionContext Optional agent/session context with keys:
     *   - agent_id (string|null): Identifier for the agent making the call
     *   - agent_role (string|null): Role of the agent ("planner", "worker", or "judge")
     *   - session_id (string|null): Groups all calls from the same agent session
     *   - session_turn (int|null): Position in the conversation (1, 2, 3...)
     */
    public function govern(
        string $content,
        ?array $region = null,
        ?string $industry = null,
        ?array $sessionContext = null
    ): GovernanceResult {
        $detection = Pii::detect($content, $this->customPatterns);
        $action = $detection['hasPII'] ? $this->config['defaultAction'] : 'allow';
        // Always redact output when PII is present — DENY and ESCALATE must not leak raw input.
        // Pii::detect()'s redactedText already has custom patterns applied too, so it is used
        // unconditionally rather than only when hasPII is true.
        $output = $detection['redactedText'];
        // Group already-sanitized match values ('[REDACTED]') by type — never expose raw
        // substrings or PII match values in the result.
        $sanitizedPii = [];
        foreach ($detection['matches'] as $match) {
            $sanitizedPii[$match['type']][] = $match['value'];
        }

        $receipt = new GovernanceReceipt(
            receiptId: $this->generateReceiptId(),
            timestamp: new \DateTimeImmutable(),
            action: $action,
            piiTypesDetected: $detection['types'],
            policyVersion: $this->config['policyVersion']
        );

        return new GovernanceResult(
            action: $action,
            output: $output,
            pii: $sanitizedPii,
            receipt: $receipt,
            region: $region,
            industry: $industry,
            sessionContext: $sessionContext
        );
    }

    /**
     * Scan a tool result for PII and prompt injection before it is appended
     * to model context, and record the scan on a GovernanceReceipt.
     *
     * @param array{toolName: string, serverUri?: ?string, payload: mixed} $input
     * @param array{blockOnInjection?: bool, customPatterns?: array<string,string>, maxDepth?: int} $options
     *
     * The receipt's `action` follows a four-way mapping:
     *   blocked            -> 'deny'
     *   injection findings -> 'escalate' (checked before pii, even if pii also present)
     *   pii findings only  -> 'redact'
     *   otherwise          -> 'allow'
     *
     * This SDK has no apiKey/attestation transport, so unlike the JS/Python
     * SDKs there is no `report` field to return -- everything here is
     * computed entirely on-device, synchronously, with zero network calls.
     */
    public function scanToolResult(array $input, array $options = []): ToolResultScanReport
    {
        $result = ToolResultScan::scan($input, $options);

        $injectionCount = ToolResultScan::scanInjectionCount($result->findings);
        $piiCount = ToolResultScan::scanPiiCount($result->findings);

        $action = match (true) {
            $result->blocked => 'deny',
            $injectionCount > 0 => 'escalate',
            $piiCount > 0 => 'redact',
            default => 'allow',
        };

        $block = ToolResultScan::buildReceiptBlock(
            $input['toolName'] ?? '',
            $input['serverUri'] ?? null,
            $result,
            Version::SDK_VERSION
        );

        $receipt = new GovernanceReceipt(
            receiptId: $this->generateReceiptId(),
            timestamp: new \DateTimeImmutable(),
            action: $action,
            piiTypesDetected: ToolResultScan::scanPiiTypes($result->findings),
            policyVersion: $this->config['policyVersion'],
            toolResultScan: $block
        );

        return new ToolResultScanReport(
            sanitized: $result->sanitized,
            findings: $result->findings,
            blocked: $result->blocked,
            reason: $result->reason,
            receipt: $receipt
        );
    }

    /**
     * Generate unique receipt ID.
     */
    private function generateReceiptId(): string
    {
        return 'tork_' . bin2hex(random_bytes(16));
    }
}
