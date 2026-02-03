<?php

declare(strict_types=1);

namespace Tork\Governance\Symfony;

use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Symfony bundle for Tork Governance.
 */
class TorkBundle extends Bundle
{
    public function getPath(): string
    {
        return \dirname(__DIR__, 2);
    }
}
