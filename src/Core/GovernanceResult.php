<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * Result of a governance evaluation.
 */
class GovernanceResult
{
    /**
     * @param string $action
     * @param string $output
     * @param array $pii
     * @param GovernanceReceipt $receipt
     * @param array|null $region
     * @param string|null $industry
     * @param array|null $sessionContext Agent/session context with agent_id, agent_role, session_id, session_turn
     */
    public function __construct(
        public readonly string $action,
        public readonly string $output,
        public readonly array $pii,
        public readonly GovernanceReceipt $receipt,
        public readonly ?array $region = null,
        public readonly ?string $industry = null,
        public readonly ?array $sessionContext = null
    ) {}

    public function toArray(): array
    {
        $result = [
            'action' => $this->action,
            'output' => $this->output,
            'pii' => $this->pii,
            'receipt' => $this->receipt->toArray(),
            'region' => $this->region,
            'industry' => $this->industry,
        ];

        if ($this->sessionContext !== null) {
            $result['session_context'] = $this->sessionContext;
        }

        return $result;
    }
}
