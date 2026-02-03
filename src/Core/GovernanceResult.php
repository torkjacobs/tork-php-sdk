<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * Result of a governance evaluation.
 */
class GovernanceResult
{
    public function __construct(
        public readonly string $action,
        public readonly string $output,
        public readonly array $pii,
        public readonly GovernanceReceipt $receipt
    ) {}

    public function toArray(): array
    {
        return [
            'action' => $this->action,
            'output' => $this->output,
            'pii' => $this->pii,
            'receipt' => $this->receipt->toArray(),
        ];
    }
}
