<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Tork\Governance\Core\Pii;
use Tork\Governance\Core\Tork;

/**
 * SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS (P1).
 *
 * Every PII type an SDK declares must have a live, compiling pattern behind
 * it. This exact bug class -- a declared type with no matching pattern --
 * was found in every SDK checked before this one (JS, Python). This test
 * guards the Tier 1 basic vocabulary (the 10-type set ToolResultScan reuses
 * via Pii::detect(), ported byte-for-byte from tork-js-sdk's pii.ts) against
 * the same class of drift: it fails if a type is declared without a pattern,
 * a pattern is declared but does not compile, or the declared vocabulary
 * silently grows/shrinks/reorders relative to the JS source.
 *
 * SEPARATE, PRE-EXISTING GAP FOUND BUT NOT FIXED HERE (reported, not in this
 * test): Tork::govern() accepts $region and $industry parameters, and
 * README.md documents "Regional PII Detection (v1.1)" (Emirates ID, +971
 * phone, PO Box, Aadhaar, ICD-10, and 12 listed regions/3 industries) -- but
 * govern()'s detectPII() never reads $region/$industry at all; every
 * regional/industry pattern that surface promises is a declared-without-
 * pattern gap of exactly this class, at a much larger scope (a full
 * regional/industry detector matching the JS SDK's, not a handful of
 * types). Building that detector is a separate task from porting
 * scanToolResult and is out of scope here; it is called out in the final
 * report as a P1 finding for follow-up.
 */
final class PiiParityTest extends TestCase
{
    /**
     * The Tier 1 basic vocabulary, JS-identical, in pii.ts's declaration
     * order (which is also the order patterns apply during redaction).
     */
    private const DECLARED_TYPES = [
        'ssn',
        'credit_card',
        'email',
        'phone',
        'address',
        'ip_address',
        'date_of_birth',
        'passport',
        'drivers_license',
        'bank_account',
    ];

    /**
     * One realistic example per declared type, reused by
     * testEachPatternActuallyMatchesItsOwnExample() and by
     * testGovernDetectsEveryDeclaredTypeThroughThePublicApi() below --
     * the same fixtures prove both scanToolResult()'s and govern()'s
     * PII detection, since 1.0.0 both run through this one table.
     *
     * 'drivers_license' uses 10 digits (not 8) and 'bank_account' uses a
     * 12-digit value not starting with '1': both avoid overlapping an
     * EARLIER pattern in Pii::PII_PATTERNS's application order (passport's
     * \d{6,9} and phone's optional leading "1" prefix, respectively) that
     * would otherwise consume the match first and leave the wrong
     * redaction label in govern()'s output -- verified empirically, not
     * just by inspection, before landing this fixture set.
     */
    private const EXAMPLES = [
        'ssn' => '123-45-6789',
        'credit_card' => '4111-1111-1111-1111',
        'email' => 'jane.doe@example.com',
        'phone' => '555-123-4567',
        'address' => '123 Main Street',
        'ip_address' => '192.168.1.1',
        'date_of_birth' => '01/15/1990',
        'passport' => 'AB1234567',
        'drivers_license' => 'D1234567890',
        'bank_account' => '987654321098',
    ];

    public function testEveryDeclaredTypeHasALivePattern(): void
    {
        foreach (self::DECLARED_TYPES as $type) {
            $this->assertArrayHasKey(
                $type,
                Pii::PII_PATTERNS,
                "Declared PII type '{$type}' has no pattern registered in Pii::PII_PATTERNS."
            );

            $spec = Pii::PII_PATTERNS[$type];
            $this->assertArrayHasKey('pattern', $spec, "PII type '{$type}' is missing its 'pattern' key.");
            $this->assertArrayHasKey('redaction', $spec, "PII type '{$type}' is missing its 'redaction' key.");
            $this->assertNotSame('', $spec['pattern'], "PII type '{$type}' has an empty pattern.");
            $this->assertNotSame('', $spec['redaction'], "PII type '{$type}' has an empty redaction label.");

            // preg_match returns false (not a thrown error) for a pattern that
            // fails to compile -- assert it actually compiles and runs.
            $this->assertNotFalse(
                @preg_match($spec['pattern'], ''),
                "Declared PII type '{$type}' has a pattern that fails to compile: {$spec['pattern']}"
            );
        }
    }

    public function testNoUndeclaredOrReorderedTypesInThePatternTable(): void
    {
        $this->assertSame(
            self::DECLARED_TYPES,
            array_keys(Pii::PII_PATTERNS),
            'Pii::PII_PATTERNS must declare exactly the Tier 1 basic vocabulary, in JS-identical order '
            . '(insertion order determines redaction application order).'
        );
    }

    public function testEachPatternActuallyMatchesItsOwnExample(): void
    {
        // A pattern that compiles but never matches anything is just as
        // useless as a missing one -- prove each one fires on a realistic
        // example, not just that preg_match doesn't error.
        foreach (self::DECLARED_TYPES as $type) {
            $this->assertArrayHasKey($type, self::EXAMPLES, "No example configured to prove type '{$type}' has a live pattern.");
            $count = preg_match_all(Pii::PII_PATTERNS[$type]['pattern'], self::EXAMPLES[$type]);
            $this->assertNotFalse($count, "PII type '{$type}' pattern failed to run against its own example.");
            $this->assertGreaterThan(0, $count, "PII type '{$type}' pattern did not match its own example '" . self::EXAMPLES[$type] . "'.");
        }
    }

    /**
     * SDK-PHP-GOVERN-USES-FIVE-PATTERN-DETECTOR-BESIDE-TEN-PATTERN-SCAN (P1),
     * now fixed as of 1.0.0: Tork::govern() used to run its own separate
     * 5-pattern table (uppercase type keys, e.g. 'SSN') while
     * Tork::scanToolResult() ran the Tier 1 10-type table above -- the same
     * passport number was caught on the scan path and missed on govern().
     * Both public entry points now detect through Pii::PII_PATTERNS, so the
     * exact same fixtures that prove scanToolResult() catches all 10 types
     * (testEachPatternActuallyMatchesItsOwnExample() above) must prove
     * govern() catches them too, through the public API -- not by reaching
     * into Pii::detect() directly.
     */
    public function testGovernDetectsEveryDeclaredTypeThroughThePublicApi(): void
    {
        $tork = new Tork();

        foreach (self::DECLARED_TYPES as $type) {
            $example = self::EXAMPLES[$type];
            $result = $tork->govern("Example: {$example} end.");

            $this->assertSame(
                'redact',
                $result->action,
                "govern() did not redact for declared type '{$type}' (example '{$example}')."
            );
            $this->assertContains(
                $type,
                $result->receipt->piiTypesDetected,
                "govern()'s receipt did not report declared type '{$type}' for example '{$example}'."
            );

            $redaction = Pii::PII_PATTERNS[$type]['redaction'];
            $this->assertStringContainsString(
                $redaction,
                $result->output,
                "govern() output did not contain the expected redaction label '{$redaction}' for type '{$type}'."
            );
            $this->assertStringNotContainsString(
                $example,
                $result->output,
                "govern() output leaked the raw '{$type}' example '{$example}' instead of redacting it."
            );
        }
    }
}
