<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * Result of scanning one tool-result payload with ToolResultScan::scan().
 *
 * `sanitized` is the payload with PII masked in place, structurally
 * identical otherwise; sub-trees containing no PII keep their original
 * identity, so a clean payload comes back untouched. `sanitized` is `null`
 * when `blocked` is true -- there is deliberately no masked payload to
 * accidentally append to model context.
 *
 * @property list<ToolResultFinding> $findings
 */
final class ToolResultScanResult
{
    /**
     * @param list<ToolResultFinding> $findings
     */
    public function __construct(
        public readonly mixed $sanitized,
        public readonly array $findings,
        public readonly bool $blocked,
        public readonly ?string $reason = null
    ) {}
}
