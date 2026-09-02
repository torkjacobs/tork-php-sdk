<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * Return value of Tork::scanToolResult(): a scan result linked to the
 * GovernanceReceipt it produced. Mirrors what Tork#scanToolResult returns in
 * the JS/Python SDKs, minus the network-attestation `report` field -- this
 * SDK has no apiKey/attestation transport, so there is nothing to report on;
 * every field here is computed entirely on-device.
 */
final class ToolResultScanReport
{
    /**
     * @param list<ToolResultFinding> $findings
     */
    public function __construct(
        public readonly mixed $sanitized,
        public readonly array $findings,
        public readonly bool $blocked,
        public readonly ?string $reason,
        public readonly GovernanceReceipt $receipt
    ) {}

    public function toArray(): array
    {
        return [
            'sanitized' => $this->sanitized,
            'findings' => array_map(static fn(ToolResultFinding $f) => $f->toArray(), $this->findings),
            'blocked' => $this->blocked,
            'reason' => $this->reason,
            'receipt' => $this->receipt->toArray(),
        ];
    }
}
