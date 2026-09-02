<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * Cryptographic receipt for governance evaluations.
 */
class GovernanceReceipt
{
    /**
     * @param array|null $toolResultScan The `tool_result_scan` block (see
     *   ToolResultScan::buildReceiptBlock()), present only on receipts
     *   produced by Tork::scanToolResult(). Null for govern() receipts.
     */
    public function __construct(
        public readonly string $receiptId,
        public readonly \DateTimeImmutable $timestamp,
        public readonly string $action,
        public readonly array $piiTypesDetected,
        public readonly string $policyVersion,
        public readonly ?array $toolResultScan = null
    ) {}

    public function toArray(): array
    {
        $result = [
            'receiptId' => $this->receiptId,
            'timestamp' => $this->timestamp->format('c'),
            'action' => $this->action,
            'piiTypesDetected' => $this->piiTypesDetected,
            'policyVersion' => $this->policyVersion,
        ];

        if ($this->toolResultScan !== null) {
            $result['tool_result_scan'] = $this->toolResultScan;
        }

        return $result;
    }
}
