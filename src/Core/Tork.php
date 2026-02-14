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
     */
    public function govern(string $content, ?array $region = null, ?string $industry = null): GovernanceResult
    {
        $piiDetected = $this->detectPII($content);
        $action = $this->determineAction($piiDetected);
        $output = $action === 'redact' ? $this->redact($content, $piiDetected) : $content;

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
            pii: $piiDetected,
            receipt: $receipt,
            region: $region,
            industry: $industry
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
