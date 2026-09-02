<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * One (kind, type) match count at one location in a scanned tool-result
 * payload.
 *
 * For kind='pii', `type` is a Pii::PII_PATTERNS key ('ssn', 'email', ...).
 * For kind='injection', `type` is always `heuristic:<name>` -- the prefix is
 * part of the value, not decoration, so a downstream reader of a receipt
 * cannot mistake a pattern hit for a verified determination.
 */
final class ToolResultFinding
{
    public function __construct(
        public readonly string $kind,
        public readonly string $type,
        public readonly int $count,
        public readonly string $location
    ) {}

    public function toArray(): array
    {
        return [
            'kind' => $this->kind,
            'type' => $this->type,
            'count' => $this->count,
            'location' => $this->location,
        ];
    }
}
