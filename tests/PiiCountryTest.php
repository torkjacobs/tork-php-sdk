<?php

/**
 * Country-layer parity tests.
 *
 * The fixtures are generated from the cloud's own evidence, not written here:
 *
 *   pii_unit_cases.json  one valid sample per registry pattern, a
 *                        checksum-broken variant for each pattern whose
 *                        checksum is a gate, and the Indonesian boundary cases.
 *   pii_vectors.json     all 2,092 inputs of the cloud's golden snapshot: every
 *                        country-corpus sentence for all 249 ISO jurisdictions,
 *                        and the whole 1,523-line business false-positive corpus.
 *
 * expectedOutput is the COUNTRY LAYER alone. Where the cloud's own output
 * differs, the case carries cloudOutput and a divergence naming the cause.
 */

declare(strict_types=1);

namespace Tork\Governance\Tests;

use PHPUnit\Framework\TestCase;
use Tork\Governance\Pii\PiiChecksums;
use Tork\Governance\Pii\PiiCountry;
use Tork\Governance\Pii\PiiRegistry;

final class PiiCountryTest extends TestCase
{
    private const NIK = '3171010101900001';

    /** @var array<string,mixed> */
    private static array $vectors;
    /** @var list<array<string,mixed>> */
    private static array $units;

    public static function setUpBeforeClass(): void
    {
        self::$vectors = json_decode(file_get_contents(__DIR__ . '/fixtures/pii_vectors.json'), true);
        self::$units = json_decode(file_get_contents(__DIR__ . '/fixtures/pii_unit_cases.json'), true);
    }

    private function redact(string $s): string
    {
        return PiiCountry::applyRedactions($s, PiiCountry::detect($s));
    }

    // ── the bundle ──────────────────────────────────────────────────────────

    public function testIsTheVersionAndContentTheFixturesWereGeneratedFrom(): void
    {
        $this->assertSame(self::$vectors['bundleVersion'], PiiRegistry::VERSION);
        $this->assertSame(self::$vectors['contentHash'], PiiRegistry::CONTENT_HASH);
    }

    public function testCarries54PatternsAcross24ProfilesWith51Signals(): void
    {
        $this->assertCount(54, PiiRegistry::patterns());
        $this->assertCount(24, PiiRegistry::countries());
        $this->assertCount(51, PiiRegistry::signals());
    }

    public function testShipsExactlyThreeAlwaysOnPatternsAllAustralian(): void
    {
        $names = array_column(PiiCountry::alwaysOnPatterns(), 'name');
        $this->assertSame(['au_tfn', 'au_abn', 'au_medicare'], $names);
    }

    public function testCoversIndonesiaAddedIn110(): void
    {
        $id = null;
        foreach (PiiRegistry::countries() as $c) {
            if ($c['code'] === 'ID') {
                $id = $c;
            }
        }
        $this->assertNotNull($id, 'Indonesia is missing from the bundle');
        $this->assertContains('id_nik', $id['patterns']);
        $nik = null;
        foreach (PiiRegistry::patterns() as $p) {
            if ($p['name'] === 'id_nik') {
                $nik = $p;
            }
        }
        $this->assertSame('NIK', $nik['label']);
        $this->assertContains('nik', $nik['whole_word_keywords']);
    }

    public function testReadsItsWindowsFromTheBundleAndTheyAreNotAllTheSame(): void
    {
        $this->assertSame(60, PiiCountry::KEYWORD_WINDOW_BEFORE);
        $this->assertSame(40, PiiCountry::KEYWORD_WINDOW_AFTER);
        $this->assertSame(60, PiiCountry::CONTEXT_WINDOW);
        $this->assertNotSame(PiiCountry::KEYWORD_WINDOW_BEFORE, PiiCountry::KEYWORD_WINDOW_AFTER);
    }

    public function testNamesAChecksumFunctionForEveryPatternThatDeclaresOne(): void
    {
        $fns = PiiChecksums::functions();
        foreach (PiiRegistry::patterns() as $p) {
            if ($p['checksum'] !== null) {
                $this->assertArrayHasKey($p['checksum'], $fns, "{$p['name']} -> {$p['checksum']}");
            }
        }
    }

    public function testUsesOnlyThePortableRegexSubset(): void
    {
        $forbidden = ['(?=' => 'lookahead', '(?!' => 'negative lookahead', '(?<=' => 'lookbehind',
                      '(?<!' => 'negative lookbehind', '\\p{' => 'unicode property escape', '(?>' => 'atomic group'];
        $sources = array_merge(
            array_column(PiiRegistry::patterns(), 'regex'),
            array_column(PiiRegistry::signals(), 'regex')
        );
        foreach ($sources as $src) {
            foreach ($forbidden as $bad => $why) {
                $this->assertStringNotContainsString($bad, $src, "$src uses $why");
            }
        }
    }

    // ── per-pattern unit cases ──────────────────────────────────────────────

    public function testPerPatternUnitCases(): void
    {
        $byName = [];
        foreach (PiiRegistry::patterns() as $p) {
            $byName[$p['name']] = $p;
        }
        $this->assertNotEmpty(self::$units);
        foreach (self::$units as $c) {
            $this->assertArrayHasKey($c['pattern'], $byName, "{$c['pattern']} is not in the bundle");
            $found = PiiCountry::detect($c['input'], [$byName[$c['pattern']]]);
            $hit = null;
            foreach ($found as $m) {
                if ($m['name'] === $c['pattern']) {
                    $hit = $m;
                    break;
                }
            }
            if ($c['expectDetected']) {
                $this->assertNotNull($hit, "expected {$c['pattern']} to match {$c['input']}");
                $this->assertSame($c['sample'], substr($c['input'], $hit['startIndex'], $hit['endIndex'] - $hit['startIndex']));
                $this->assertSame($c['redaction'], $hit['redaction']);
            } else {
                $this->assertNull($hit, "expected {$c['pattern']} NOT to match {$c['input']}");
            }
        }
    }

    // ── golden-snapshot parity ──────────────────────────────────────────────

    public function testReproducesTheCloudOnEveryCorpusVector(): void
    {
        $checked = 0;
        foreach (self::$vectors['cases'] as $c) {
            if ($c['kind'] === 'business-fp') {
                continue;
            }
            $checked++;
            $this->assertSame($c['expectedRegions'], PiiCountry::inferRegions($c['input']), "activation: {$c['id']}");
            $matches = PiiCountry::detect($c['input']);
            $this->assertSame(
                $c['expectedOutput'],
                PiiCountry::applyRedactions($c['input'], $matches),
                "redaction: {$c['id']}"
            );
            $this->assertSame($c['expectedLabels'], array_values(array_unique(array_column($matches, 'label'))), "labels: {$c['id']}");
            $this->assertSame($c['expectedNames'], array_values(array_unique(array_column($matches, 'name'))), "names: {$c['id']}");
        }
        $this->assertGreaterThan(500, $checked);
    }

    public function testAddsNoFalsePositiveToTheBusinessCorpus(): void
    {
        $n = 0;
        foreach (self::$vectors['cases'] as $c) {
            if ($c['kind'] !== 'business-fp') {
                continue;
            }
            $n++;
            $this->assertSame($c['expectedRegions'], PiiCountry::inferRegions($c['input']), "activation: {$c['id']}");
            $m = PiiCountry::detect($c['input']);
            $this->assertSame([], $m, "{$c['id']}: false positive in {$c['input']}");
        }
        $this->assertGreaterThan(1500, $n);
    }

    /**
     * Since bundle 1.2.0 ships au_tfn/au_abn/au_medicare as alwaysOn and this
     * SDK runs them unconditionally (rule 1a), the "AU bundle gap" cause that
     * 1.1.0 left open is fully closed: zero cases still diverge for it. The
     * one remaining, explained cause is L0 -- the cloud's universal (L0)
     * layer this bundle deliberately excludes -- and nothing else.
     */
    public function testTheAuBundleGapIsClosedAndOnlyL0RemainsUnexplained(): void
    {
        $auGaps = 0;
        $l0 = 0;
        foreach (self::$vectors['cases'] as $c) {
            if (!isset($c['divergence'])) {
                continue;
            }
            $isL0 = str_starts_with($c['divergence'], 'L0:');
            $isBundleGap = str_starts_with($c['divergence'], 'BUNDLE GAP:');
            $this->assertTrue($isL0 || $isBundleGap, "{$c['id']}: unexplained divergence cause");
            if ($isBundleGap) {
                $auGaps++;
            }
            if ($isL0) {
                $l0++;
            }
        }
        $this->assertSame(0, $auGaps, 'the AU bundle gap cause must be fully closed');
        $this->assertGreaterThan(0, $l0, 'L0 should still be the one cloud-only cause left');
        $this->assertSame($l0, count(array_filter(self::$vectors['cases'], static fn($c) => isset($c['divergence']))));
    }

    public function testNothingIsEverPartiallyRedacted(): void
    {
        foreach (self::$vectors['cases'] as $c) {
            $matches = PiiCountry::detect($c['input']);
            $out = PiiCountry::applyRedactions($c['input'], $matches);
            $this->assertDoesNotMatchRegularExpression('#\d\[[A-Z_]+_REDACTED\]|\[[A-Z_]+_REDACTED\]\d#', $out, $c['id']);
            foreach ($matches as $m) {
                $raw = substr($c['input'], $m['startIndex'], $m['endIndex'] - $m['startIndex']);
                $this->assertStringNotContainsString($raw, $out, "{$c['id']}: $raw survived");
            }
        }
    }

    // ── Indonesia, the rule 1.1.0 added ─────────────────────────────────────

    public function testDetectsTheShortSpellingWhichIsAWholeWordKeywordOnly(): void
    {
        $s = 'NIK ' . self::NIK . ' untuk pendaftaran rekening di Jakarta, Indonesia.';
        $this->assertSame(['ID'], PiiCountry::inferRegions($s));
        $this->assertSame('NIK [NIK_REDACTED] untuk pendaftaran rekening di Jakarta, Indonesia.', $this->redact($s));
    }

    public function testDetectsTheLongSpellingWhichIsAnOrdinarySubstringKeyword(): void
    {
        $s = 'Nomor Induk Kependudukan ' . self::NIK . ' untuk pendaftaran.';
        $this->assertStringContainsString('[NIK_REDACTED]', $this->redact($s));
    }

    public function testNikInsideAnOrdinaryIndonesianWordDoesNotOpenTheGate(): void
    {
        foreach (['teknik', 'elektronik', 'klinik', 'pabrik', 'piknik'] as $word) {
            $this->assertSame([], PiiCountry::detect("Faktur $word " . self::NIK . ' untuk pelanggan.'), "$word opened the gate");
        }
    }

    public function testABareNikIsNotRedacted(): void
    {
        $this->assertSame([], PiiCountry::detect(self::NIK));
    }

    // ── the rules 1.1.0 added to the SDK half of the contract ───────────────

    public function testRule6ChecksumFailingIdentifierIsRedactedGenerically(): void
    {
        $out = $this->redact('South African ID number 8001015009088 for the FICA check.');
        $this->assertStringNotContainsString('8001015009088', $out);
        $this->assertStringContainsString('[NATIONAL_ID_REDACTED]', $out);
    }

    public function testRule7ColumnHeaderIsTheContextForABareValueCell(): void
    {
        $csv = "Name,CNIC,City\nAli,42201-1234567-1,Karachi\nSana,42201-7654321-2,Lahore\nOmar,42201-1111111-3,Multan";
        $this->assertNotEmpty(PiiCountry::tableScopes($csv));
        $this->assertStringNotContainsString('42201-1234567-1', $this->redact($csv));
    }

    public function testRule7GenericHeaderDoesNotActAsContext(): void
    {
        $csv = "Name,Order ID Number,City\nAli,42201-1234567-1,Karachi\nSana,42201-7654321-2,Lahore\nOmar,42201-1111111-3,Multan";
        $this->assertSame([], PiiCountry::detect($csv));
    }

    public function testRule7bCloserCommercialLabelClosesTheGate(): void
    {
        $s = 'Please do not send your CNIC. Use the job number 4220112345671.';
        $at = strpos($s, '4220112345671');
        $this->assertTrue(PiiCountry::labelledAsReference($s, $at, $at + 13, ['cnic']));
        $this->assertStringContainsString('4220112345671', $this->redact($s));
    }

    public function testRule7bCanOnlyCloseAGateNeverOpenOne(): void
    {
        $this->assertSame([], PiiCountry::detect('Order 12345678901234 with no identifier word anywhere.'));
    }

    public function testRule5CountryMatchSupersedesAWiderL0Range(): void
    {
        $s = 'CPF 529.982.247-25 para a nota fiscal no Brasil.';
        $at = strpos($s, '529.982.247-25');
        $res = PiiCountry::detectWithRanges($s, null, [[$at - 1, $at + 14]]);
        $this->assertContains('br_cpf', array_column($res['matches'], 'name'));
        $this->assertCount(1, $res['superseded']);
    }

    public function testWholeWordMatchingRespectsBoundaries(): void
    {
        $this->assertTrue(PiiCountry::hasWholeWordContextAround('nik 123', 4, 7, ['nik']));
        $this->assertFalse(PiiCountry::hasWholeWordContextAround('teknik 123', 7, 10, ['nik']));
    }

    // ── the AU alwaysOn patterns, bundle 1.2.0 ───────────────────────────────

    public function testDetectsAValidTfnWithNoRegionActivatedAtAll(): void
    {
        $s = 'Please provide your tax file number 123456782 for the payroll form.';
        $this->assertSame([], PiiCountry::inferRegions($s), 'nothing in this sentence activates AU');
        $this->assertStringContainsString('[TFN_REDACTED]', $this->redact($s));
        $this->assertStringNotContainsString('123456782', $this->redact($s));
    }

    public function testAChecksumFailingTfnIsANearMissNotAFalseNegative(): void
    {
        $s = 'Please provide your tax file number 123456781 for the payroll form.';
        $out = $this->redact($s);
        $this->assertStringNotContainsString('123456781', $out);
        $this->assertStringContainsString('[NATIONAL_ID_REDACTED]', $out, 'checksum-failing TFN must still be caught, generically');
    }

    public function testDetectsAValidAbnEvenThoughItsOwnCorpusSentenceActivatesNoRegion(): void
    {
        // README rule 1a's own example: an 11-digit ABN alone activates no AU signal.
        $s = 'Supplier ABN 51 824 753 556 appears on the Australian invoice.';
        $this->assertStringContainsString('[ABN_REDACTED]', $this->redact($s));
        $this->assertStringNotContainsString('51 824 753 556', $this->redact($s));
    }

    public function testAChecksumFailingAbnIsDroppedEntirelyLikeBrCnpj(): void
    {
        // au_abn is a required checksum with near_miss_fallback = false: unlike
        // au_tfn, a bad ABN checksum is not a near miss, it is no match at all.
        $s = 'Supplier ABN 51 824 753 557 appears on the Australian invoice.';
        $this->assertSame([], PiiCountry::detect($s));
        $this->assertSame($s, $this->redact($s));
    }

    public function testDetectsAValidMedicareNumberWithItsKeyword(): void
    {
        $s = 'Your Medicare number is 2123456701 for the claim.';
        $this->assertStringContainsString('[MEDICARE_REDACTED]', $this->redact($s));
        $this->assertStringNotContainsString('2123456701', $this->redact($s));
    }

    public function testAChecksumFailingMedicareNumberIsStillDetectedBecauseTheGateIsAdvisoryOnly(): void
    {
        // Services Australia publishes no check-digit algorithm; checksums.json
        // marks au_medicare advisoryFor, never requiredBy. A failing checksum
        // must never reject the match.
        $s = 'Your Medicare number is 2123456791 for the claim.';
        $this->assertStringContainsString('[MEDICARE_REDACTED]', $this->redact($s));
        $this->assertStringNotContainsString('2123456791', $this->redact($s));
    }

    public function testAlwaysOnPatternsSupersedeAWiderExistingL0RangeUnderRule5(): void
    {
        // Rule 1a: alwaysOn patterns run before country patterns, and rule 5
        // still applies to them -- a wider "existing" (L0) range that fully
        // contains the ABN is superseded, not left double-redacted.
        $s = 'ABN 51 824 753 556 for the invoice.';
        $at = strpos($s, '51 824 753 556');
        $res = PiiCountry::detectWithRanges($s, null, [[$at - 1, $at + strlen('51 824 753 556') + 1]]);
        $this->assertContains('au_abn', array_column($res['matches'], 'name'));
        $this->assertCount(1, $res['superseded']);
    }
}
