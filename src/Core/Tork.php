<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * Tork Governance SDK for PHP.
 *
 * Provides PII detection, redaction, and compliance receipts
 * for AI applications.
 */
class Tork
{
    private array $config;
    private array $patterns;

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'defaultAction' => 'redact',
            'policyVersion' => '1.0.0',
        ], $config);

        $this->patterns = $this->getDefaultPatterns();

        if (isset($config['customPatterns'])) {
            $this->patterns = array_merge($this->patterns, $config['customPatterns']);
        }
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
        $piiDetected = $this->detectPII($content);
        $action = $this->determineAction($piiDetected);
        // Always redact output when PII is present — DENY and ESCALATE must not leak raw input.
        $output = !empty($piiDetected) ? $this->redact($content, $piiDetected) : $content;
        // Sanitize PII match values before storing — never expose raw substrings in the result.
        $sanitizedPii = array_map(
            static fn(array $matches) => array_fill(0, count($matches), '[REDACTED]'),
            $piiDetected
        );

        $receipt = new GovernanceReceipt(
            receiptId: $this->generateReceiptId(),
            timestamp: new \DateTimeImmutable(),
            action: $action,
            piiTypesDetected: array_keys($piiDetected),
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
     * Detect PII in content.
     */
    private function detectPII(string $content): array
    {
        $detected = [];

        foreach ($this->patterns as $type => $pattern) {
            if (preg_match_all($pattern, $content, $matches)) {
                $detected[$type] = $matches[0];
            }
        }

        return $detected;
    }

    /**
     * Determine action based on detected PII.
     */
    private function determineAction(array $piiDetected): string
    {
        if (empty($piiDetected)) {
            return 'allow';
        }

        return $this->config['defaultAction'];
    }

    /**
     * Redact PII from content.
     */
    private function redact(string $content, array $piiDetected): string
    {
        $redacted = $content;

        foreach ($piiDetected as $type => $matches) {
            foreach ($matches as $match) {
                $redacted = str_replace($match, "[{$type}_REDACTED]", $redacted);
            }
        }

        return $redacted;
    }

    /**
     * Generate unique receipt ID.
     */
    private function generateReceiptId(): string
    {
        return 'tork_' . bin2hex(random_bytes(16));
    }

    /**
     * Get default PII patterns.
     */
    private function getDefaultPatterns(): array
    {
        return [
            'SSN' => '/\b\d{3}-\d{2}-\d{4}\b/',
            'EMAIL' => '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/',
            'PHONE' => '/\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/',
            'CREDIT_CARD' => '/\b(?:\d{4}[-\s]?){3}\d{4}\b/',
            'IP_ADDRESS' => '/\b(?:\d{1,3}\.){3}\d{1,3}\b/',
        ];
    }
}
