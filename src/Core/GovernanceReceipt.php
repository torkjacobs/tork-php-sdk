<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * Cryptographic receipt for governance evaluations.
 */
class GovernanceReceipt
{
    public function __construct(
        public readonly string $receiptId,
        public readonly \DateTimeImmutable $timestamp,
        public readonly string $action,
        public readonly array $piiTypesDetected,
        public readonly string $policyVersion
    ) {}

    public function toArray(): array
    {
        return [
            'receiptId' => $this->receiptId,
            'timestamp' => $this->timestamp->format('c'),
            'action' => $this->action,
            'piiTypesDetected' => $this->piiTypesDetected,
            'policyVersion' => $this->policyVersion,
        ];
    }
}
