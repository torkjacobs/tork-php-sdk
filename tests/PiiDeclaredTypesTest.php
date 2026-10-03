<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Tork\Governance\Core\Pii;
use Tork\Governance\Pii\PiiCountry;
use Tork\Governance\Pii\PiiRegistry;

/**
 * SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS (P1), tower-auto S01.
 *
 * A declared PII type with no working pattern is a false claim. This test
 * covers BOTH declared vocabularies in this SDK:
 *   - Tier 1 (Pii::PII_PATTERNS, 10 types), and
 *   - the country layer (PiiRegistry::countries() declares each country's
 *     pattern names; PiiRegistry::patterns() holds the patterns).
 * It asserts the two agree in both directions, every pattern compiles, and
 * every declared type has one positive and one negative example.
 */
final class PiiDeclaredTypesTest extends TestCase
{
    /** Tier 1: a string that must NOT match its own type's pattern. */
    private const TIER1_NEGATIVES = [
        'ssn' => '123-456-789',
        'credit_card' => '4111-1111-1111',
        'email' => 'jane.doe at example dot com',
        'phone' => '555-1234',
        'address' => 'Main Street',
        'ip_address' => '999.999.999.999',
        'date_of_birth' => '13/45/1990',
        'passport' => 'AB123',
        'drivers_license' => 'D123',
        'bank_account' => '1234567',
    ];

    private const TIER1_POSITIVES = [
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

    /**
     * Country layer: hand-written negatives where the generic near-miss
     * (the positive sample with a letter at each end) would still satisfy
     * the pattern because the sample itself contains letters.
     */
    private const COUNTRY_NEGATIVE_OVERRIDES = [
        'uk_postcode' => 'postcode 12 6ZX on file.',
        'in_pan' => 'Reference ZYCI1777 on file.',
        'in_ifsc' => 'Reference ZYC0QH52 on file.',
        'gh_ghana_card' => 'ghana card DP-77631706-X on file.',
        'mx_rfc' => 'rfc ZYC417776 on file.',
        'au_phone_intl' => 'call +61 112 345 678 today.',
    ];

    /** Patterns the shared unit-case fixture has no positive case for. */
    private const COUNTRY_POSITIVE_OVERRIDES = [
        'au_phone_intl' => ['input' => 'call +61 412 345 678 today.', 'sample' => '+61 412 345 678'],
    ];

    /** @return array<string, array{input: string, sample: string}> */
    private static function countryPositives(): array
    {
        $cases = json_decode((string) file_get_contents(__DIR__ . '/fixtures/pii_unit_cases.json'), true);
        $pos = [];
        foreach ($cases as $c) {
            if ($c['expectDetected'] && !isset($pos[$c['pattern']])) {
                $pos[$c['pattern']] = ['input' => $c['input'], 'sample' => $c['sample']];
            }
        }
        return self::COUNTRY_POSITIVE_OVERRIDES + $pos;
    }

    private static function countryDetects(array $pattern, string $text): bool
    {
        foreach (PiiCountry::detect($text, [$pattern]) as $m) {
            if ($m['name'] === $pattern['name']) {
                return true;
            }
        }
        return false;
    }

    /** @return array<string, array> pattern name => pattern */
    private static function countryPatternsByName(): array
    {
        $by = [];
        foreach (PiiRegistry::patterns() as $p) {
            $by[$p['name']] = $p;
        }
        return $by;
    }

    // ── Tier 1 ──────────────────────────────────────────────────────────

    public function testEveryTier1TypeHasAPositiveAndANegativeExample(): void
    {
        $this->assertSame(array_keys(Pii::PII_PATTERNS), array_keys(self::TIER1_POSITIVES));
        $this->assertSame(array_keys(Pii::PII_PATTERNS), array_keys(self::TIER1_NEGATIVES));

        foreach (Pii::PII_PATTERNS as $type => $spec) {
            $this->assertSame(
                1,
                preg_match($spec['pattern'], self::TIER1_POSITIVES[$type]),
                "Tier 1 '{$type}' must match its positive example."
            );
            $this->assertSame(
                0,
                preg_match($spec['pattern'], self::TIER1_NEGATIVES[$type]),
                "Tier 1 '{$type}' must NOT match its negative example."
            );
        }
    }

    // ── Country layer ───────────────────────────────────────────────────

    public function testEveryDeclaredCountryTypeHasAPatternAndNoPatternIsUndeclared(): void
    {
        $declared = [];
        foreach (PiiRegistry::countries() as $country) {
            foreach ($country['patterns'] as $name) {
                $this->assertArrayNotHasKey($name, $declared, "'{$name}' is declared by two countries.");
                $declared[$name] = $country['code'];
            }
        }
        $by = self::countryPatternsByName();

        $this->assertSame([], array_values(array_diff(array_keys($declared), array_keys($by))), 'Declared country types with no pattern.');
        $this->assertSame([], array_values(array_diff(array_keys($by), array_keys($declared))), 'Patterns not declared by any country.');
        foreach ($by as $name => $p) {
            $this->assertSame($declared[$name], $p['country'], "'{$name}' is declared under a different country than its pattern.");
            $this->assertNotSame('', $p['regex'], "'{$name}' has an empty regex.");
            $this->assertNotSame('', $p['redaction'], "'{$name}' has an empty redaction label.");
        }
    }

    public function testEveryCountryPatternCompiles(): void
    {
        foreach (self::countryPatternsByName() as $name => $p) {
            $this->assertNotFalse(
                @preg_match('~' . str_replace('~', '\~', $p['regex']) . '~u', ''),
                "Country pattern '{$name}' fails to compile."
            );
        }
    }

    public function testEveryCountryTypeHasAPositiveAndANegativeExample(): void
    {
        $by = self::countryPatternsByName();
        $pos = self::countryPositives();

        foreach ($by as $name => $p) {
            $this->assertArrayHasKey($name, $pos, "No positive example for '{$name}'.");
            $this->assertTrue(
                self::countryDetects($p, $pos[$name]['input']),
                "'{$name}' must detect its positive example: {$pos[$name]['input']}"
            );

            $s = $pos[$name]['sample'];
            $neg = self::COUNTRY_NEGATIVE_OVERRIDES[$name]
                ?? str_replace($s, 'X' . substr($s, 1, -1) . 'X', $pos[$name]['input']);
            $this->assertNotSame($pos[$name]['input'], $neg, "Negative example for '{$name}' equals its positive.");
            $this->assertFalse(
                self::countryDetects($p, $neg),
                "'{$name}' must NOT detect its negative example: {$neg}"
            );
        }
    }
}
