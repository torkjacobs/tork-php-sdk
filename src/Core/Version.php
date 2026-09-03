<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * SDK version, embedded in receipt blocks (tool_result_scan.sdk_version).
 * Kept in lockstep with composer.json's "version" field.
 */
final class Version
{
    public const SDK_VERSION = '1.0.0';
}
