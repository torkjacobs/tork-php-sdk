<?php

/**
 * The country layer: 24 country profiles, 51 patterns, 20 check digits.
 *
 * This implements the seven rules that generated/sdk-registry/README.md marks
 * SDK, from the bundle alone. Bundle 1.1.0 carries the data all seven need --
 * the activation signals, the country map, the three windows, the whole-word
 * vocabulary, the near-miss policy, the table constants and the reference
 * labels -- so nothing here is hand-written registry data and no window is
 * hard-coded.
 *
 *   1. ACTIVATE   a country's patterns run only when one of its signals fires.
 *   2. MATCH      the regex, case-sensitively, globally.
 *   3. KEYWORD    whole-word (symmetric CONTEXT_WINDOW) or column verdict or
 *                 the ASYMMETRIC substring window (60 before, 40 after); then
 *                 7b may close the gate again.
 *   4. CHECKSUM   when required. Advisory checksums never reject.
 *   5. SUPERSEDE  a match containing every range it overlaps takes them.
 *   6. NEAR MISS  a checksum-failing identifier is redacted generically.
 *   7. COLUMN     in a delimited table a bare value cell is judged by its header.
 *   7b. NEAREST LABEL  a closer commercial label closes the gate.
 *
 * Still cloud-only, by design: the universal (L0) patterns, the slot, context,
 * gravity and name layers, industry profiles and org configuration.
 *
 * Offsets are BYTE offsets, matching preg_match_all with PREG_OFFSET_CAPTURE.
 */

declare(strict_types=1);

namespace Tork\Governance\Pii;

final class PiiCountry
{
    /** Characters before a match that count as nearby for the substring gate. */
    public const KEYWORD_WINDOW_BEFORE = PiiRegistry::KEYWORD_WINDOW_BEFORE;
    /** Characters after. Deliberately NOT the same number as BEFORE. */
    public const KEYWORD_WINDOW_AFTER = PiiRegistry::KEYWORD_WINDOW_AFTER;
    /** The symmetric window: whole-word keywords and the near-miss gate. */
    public const CONTEXT_WINDOW = PiiRegistry::CONTEXT_WINDOW;

    /** @var array<string,array<string,mixed>>|null */
    private static ?array $byName = null;
    /** @var array<string,list<string>>|null */
    private static ?array $countryPatterns = null;
    /** @var list<string>|null */
    private static ?array $signalOrder = null;
    /** @var array<string,bool>|null */
    private static ?array $genericSet = null;
    /** @var list<string>|null */
    private static ?array $nationalIdWords = null;
    /** @var list<array<string,mixed>>|null */
    private static ?array $alwaysOn = null;

    private static function boot(): void
    {
        if (self::$byName !== null) {
            return;
        }
        self::$byName = [];
        self::$alwaysOn = [];
        foreach (PiiRegistry::patterns() as $p) {
            self::$byName[$p['name']] = $p;
            if ($p['always_on']) {
                self::$alwaysOn[] = $p;
            }
        }
        self::$countryPatterns = [];
        foreach (PiiRegistry::countries() as $c) {
            self::$countryPatterns[$c['code']] = $c['patterns'];
        }
        self::$signalOrder = [];
        foreach (PiiRegistry::signals() as $s) {
            if (!in_array($s['country'], self::$signalOrder, true)) {
                self::$signalOrder[] = $s['country'];
            }
        }
        self::$genericSet = [];
        foreach (PiiRegistry::GENERIC_ID_KEYWORDS as $k) {
            self::$genericSet[$k] = true;
        }
        self::$nationalIdWords = array_merge(PiiRegistry::GENERIC_ID_KEYWORDS, PiiRegistry::LOCAL_ID_KEYWORDS);
    }

    /**
     * A delimiter the pattern does not contain. `#` first, as the bundle's
     * README suggests, then a fallback for the rare pattern containing one.
     */
    private static function compile(string $regex, bool $ignoreCase = false): string
    {
        foreach (['#', '~', '%', '!'] as $d) {
            if (!str_contains($regex, $d)) {
                return $d . $regex . $d . ($ignoreCase ? 'i' : '');
            }
        }
        return '#' . str_replace('#', '\\#', $regex) . '#' . ($ignoreCase ? 'i' : '');
    }

    private static function isAlnum(string $ch): bool
    {
        return $ch !== '' && (ctype_alnum($ch) && strlen($ch) === 1);
    }

    /** A pattern's whole vocabulary: the substring keywords and the whole-word ones. */
    private static function allKeywordsOf(array $p): array
    {
        return $p['whole_word_keywords'] === []
            ? $p['keywords']
            : array_merge($p['keywords'], $p['whole_word_keywords']);
    }

    /** The half of a vocabulary that names ONE country's identifier. */
    private static function specificKeywords(array $keywords): array
    {
        self::boot();
        return array_values(array_filter($keywords, static fn($k) => !isset(self::$genericSet[$k])));
    }

    /** Rule 3, substring half: ASYMMETRIC -- 60 before the match, 40 after it. */
    private static function hasNearbyContext(string $content, int $start, int $end, array $keywords): bool
    {
        $lo = max(0, $start - self::KEYWORD_WINDOW_BEFORE);
        $before = strtolower(substr($content, $lo, $start - $lo));
        $after = strtolower(substr($content, $end, self::KEYWORD_WINDOW_AFTER));
        foreach ($keywords as $kw) {
            if (str_contains($before, $kw) || str_contains($after, $kw)) {
                return true;
            }
        }
        return false;
    }

    /** Symmetric CONTEXT_WINDOW either side, substring. Used by rule 6. */
    private static function hasContextAround(string $content, int $start, int $end, array $keywords): bool
    {
        $w = strtolower(self::windowAround($content, $start, $end));
        foreach ($keywords as $kw) {
            if (str_contains($w, $kw)) {
                return true;
            }
        }
        return false;
    }

    private static function windowAround(string $content, int $start, int $end): string
    {
        $lo = max(0, $start - self::CONTEXT_WINDOW);
        $hi = min(strlen($content), $end + self::CONTEXT_WINDOW);
        return substr($content, $lo, $hi - $lo);
    }

    /**
     * Rule 3, whole-word half: symmetric CONTEXT_WINDOW, a boundary each side,
     * a boundary being "not a letter or digit".
     *
     * This is the gate Indonesia needs: `nik` sits inside teknik, elektronik,
     * klinik and pabrik, so a substring test would open the gate on a ledger.
     */
    public static function hasWholeWordContextAround(string $content, int $start, int $end, array $words): bool
    {
        if ($words === []) {
            return false;
        }
        $w = strtolower(self::windowAround($content, $start, $end));
        $n = strlen($w);
        foreach ($words as $word) {
            $from = 0;
            while (($i = strpos($w, $word, $from)) !== false) {
                $beforeOk = $i === 0 || !self::isAlnum($w[$i - 1]);
                $j = $i + strlen($word);
                $afterOk = $j >= $n || !self::isAlnum($w[$j]);
                if ($beforeOk && $afterOk) {
                    return true;
                }
                $from = $i + 1;
            }
        }
        return false;
    }

    private static function documentHasWholeWord(string $content, array $words): bool
    {
        return $words !== [] && self::hasWholeWordContextAround($content, 0, strlen($content), $words);
    }

    // ── rule 1: activation ──────────────────────────────────────────────────

    /** @return list<string> the countries this text activates, in signal order */
    public static function inferRegions(string $content): array
    {
        self::boot();
        $regions = [];
        $lower = strtolower($content);
        $signals = PiiRegistry::signals();
        foreach (self::$signalOrder as $code) {
            foreach ($signals as $s) {
                if ($s['country'] !== $code) {
                    continue;
                }
                if (!preg_match(self::compile($s['regex'], str_contains($s['flags'], 'i')), $content)) {
                    continue;
                }
                $bySubstring = false;
                foreach ($s['keywords'] as $k) {
                    if (str_contains($lower, $k)) {
                        $bySubstring = true;
                        break;
                    }
                }
                $byWholeWord = self::documentHasWholeWord($content, $s['whole_word_keywords']);
                // Both lists empty means the shape alone is distinctive enough.
                if (($s['keywords'] !== [] || $s['whole_word_keywords'] !== []) && !$bySubstring && !$byWholeWord) {
                    continue;
                }
                $target = $s['activates'] !== '' ? $s['activates'] : $code;
                if (!in_array($target, $regions, true)) {
                    $regions[] = $target;
                }
                break; // one signal per country is enough
            }
        }
        return $regions;
    }

    /** @return list<array<string,mixed>> */
    public static function patternsForRegions(array $regions): array
    {
        self::boot();
        $out = [];
        $seen = [];
        foreach ($regions as $code) {
            foreach (self::$countryPatterns[strtoupper($code)] ?? [] as $name) {
                if (isset($seen[$name]) || !isset(self::$byName[$name])) {
                    continue;
                }
                $seen[$name] = true;
                $out[] = self::$byName[$name];
            }
        }
        return $out;
    }

    /**
     * Rule 1a: patterns marked `always_on` run on every document, whatever
     * rule 1 (country activation) returned, and run before the activated
     * country patterns so an activated pattern can supersede one of them
     * under rule 5. Today that is exactly `au_tfn`, `au_abn`, `au_medicare`.
     *
     * @return list<array<string,mixed>>
     */
    public static function alwaysOnPatterns(): array
    {
        self::boot();
        return self::$alwaysOn;
    }

    // ── rule 7: the column is the context ───────────────────────────────────

    private static function looksLikeHeader(array $cells, string $delimiter): bool
    {
        $minimum = $delimiter === ',' ? PiiRegistry::TABLE_MIN_COMMA_COLUMNS : 2;
        if (count($cells) < $minimum) {
            return false;
        }
        foreach ($cells as $c) {
            $t = trim($c);
            if ($t === '' || strlen($t) > PiiRegistry::TABLE_MAX_HEADER_LENGTH) {
                return false;
            }
            if (!preg_match('#[A-Za-z\x{00C0}-\x{FFFF}]#u', $t)) {
                return false;
            }
            if (preg_match('#^\+?[\d\s.\-/]+$#', $t)) {
                return false;
            }
            if (preg_match('#[.?!]#', $t)) {
                return false;
            }
            if (count(preg_split('#\s+#', $t)) > PiiRegistry::TABLE_MAX_HEADER_WORDS) {
                return false;
            }
        }
        return true;
    }

    /** @return list<array{start:int,end:int,header:string,rowStart:int,rowEnd:int}> */
    public static function tableScopes(string $content): array
    {
        $lines = explode("\n", $content);
        if (count($lines) < PiiRegistry::TABLE_MIN_ROWS) {
            return [];
        }
        $offsets = [];
        $at = 0;
        foreach ($lines as $line) {
            $offsets[] = $at;
            $at += strlen($line) + 1;
        }
        foreach (PiiRegistry::TABLE_DELIMITERS as $delimiter) {
            $headerCells = explode($delimiter, $lines[0]);
            if (!self::looksLikeHeader($headerCells, $delimiter)) {
                continue;
            }
            $width = count($headerCells);
            $dataRows = [];
            for ($i = 1; $i < count($lines); $i++) {
                if (trim($lines[$i]) === '') {
                    continue;
                }
                if (count(explode($delimiter, $lines[$i])) !== $width) {
                    return [];
                }
                $dataRows[] = $i;
            }
            if (count($dataRows) < PiiRegistry::TABLE_MIN_ROWS - 1) {
                continue;
            }
            $scopes = [];
            foreach ($dataRows as $row) {
                $cells = explode($delimiter, $lines[$row]);
                $rowStart = $offsets[$row];
                $rowEnd = $rowStart + strlen($lines[$row]);
                $cellStart = $rowStart;
                for ($col = 0; $col < $width; $col++) {
                    $scopes[] = [
                        'start' => $cellStart,
                        'end' => $cellStart + strlen($cells[$col]),
                        'header' => strtolower(trim($headerCells[$col])),
                        'rowStart' => $rowStart,
                        'rowEnd' => $rowEnd,
                    ];
                    $cellStart += strlen($cells[$col]) + strlen($delimiter);
                }
            }
            return $scopes;
        }
        return [];
    }

    /** A whole-word match, not a substring. */
    private static function headerNames(string $header, array $keywords): bool
    {
        $n = strlen($header);
        foreach ($keywords as $kw) {
            $i = strpos($header, $kw);
            if ($i === false) {
                continue;
            }
            $beforeOk = $i === 0 || !self::isAlnum($header[$i - 1]);
            $j = $i + strlen($kw);
            $afterOk = $j >= $n || !self::isAlnum($header[$j]);
            if ($beforeOk && $afterOk) {
                return true;
            }
        }
        return false;
    }

    /** null when the window should be consulted as usual. */
    private static function columnVerdict(string $content, array $scopes, int $start, int $end, array $all, array $specific): ?bool
    {
        if ($scopes === []) {
            return null;
        }
        $cell = null;
        foreach ($scopes as $s) {
            if ($start >= $s['start'] && $end <= $s['end']) {
                $cell = $s;
                break;
            }
        }
        if ($cell === null) {
            return null;
        }
        // A cell whose own row names the identifier is prose in a delimited block.
        $rowText = strtolower(substr($content, $cell['rowStart'], $cell['rowEnd'] - $cell['rowStart']));
        foreach ($all as $k) {
            if (str_contains($rowText, $k)) {
                return null;
            }
        }
        return $specific !== [] && self::headerNames($cell['header'], $specific);
    }

    // ── rule 7b: nearest label wins ─────────────────────────────────────────

    private static function closestBefore(string $before, array $keywords): ?int
    {
        $best = null;
        foreach ($keywords as $kw) {
            $i = strrpos($before, $kw);
            if ($i === false) {
                continue;
            }
            $d = strlen($before) - ($i + strlen($kw));
            if ($best === null || $d < $best) {
                $best = $d;
            }
        }
        return $best;
    }

    private static function closestAfter(string $after, array $keywords): ?int
    {
        $best = null;
        foreach ($keywords as $kw) {
            $i = strpos($after, $kw);
            if ($i === false) {
                continue;
            }
            if ($best === null || $i < $best) {
                $best = $i;
            }
        }
        return $best;
    }

    /**
     * Whether the number is labelled as a commercial reference more closely
     * than as an identifier. It can only ever close a gate, never open one.
     */
    public static function labelledAsReference(string $content, int $start, int $end, array $identifierKeywords): bool
    {
        $lo = max(0, $start - PiiRegistry::LABEL_WINDOW);
        $before = strtolower(substr($content, $lo, $start - $lo));
        $ref = self::closestBefore($before, PiiRegistry::REFERENCE_LABELS);
        if ($ref === null || $ref > PiiRegistry::LABEL_REACH) {
            return false;
        }
        if ($identifierKeywords === []) {
            return true;
        }
        $idBefore = self::closestBefore($before, $identifierKeywords);
        if ($idBefore !== null && $idBefore <= $ref) {
            return false;
        }
        $after = strtolower(substr($content, $end, PiiRegistry::LABEL_WINDOW));
        $idAfter = self::closestAfter($after, $identifierKeywords);
        if ($idAfter !== null && $idAfter <= $ref) {
            return false;
        }
        return true;
    }

    // ── the pass ────────────────────────────────────────────────────────────

    /** The span with leading and trailing non-alphanumeric characters removed. */
    private static function trimmedCore(string $content, int $start, int $end): array
    {
        $s = $start;
        $e = $end;
        while ($s < $e && !self::isAlnum($content[$s])) {
            $s++;
        }
        while ($e > $s && !self::isAlnum($content[$e - 1])) {
            $e--;
        }
        return $s === $e ? [$start, $end] : [$s, $e];
    }

    /**
     * Country matches for $content, de-overlapped and ordered by position.
     *
     * @param list<array<string,mixed>>|null $patterns bypasses activation
     * @param list<array{0:int,1:int}> $existingRanges your own L0 spans, for rule 5
     * @return array{matches:list<array<string,mixed>>,superseded:list<array{0:int,1:int}>}
     */
    public static function detectWithRanges(string $content, ?array $patterns = null, array $existingRanges = []): array
    {
        self::boot();
        if ($patterns !== null) {
            $active = $patterns;
        } else {
            $alwaysOn = self::alwaysOnPatterns();
            $alwaysOnNames = array_flip(array_column($alwaysOn, 'name'));
            $gated = array_values(array_filter(
                self::patternsForRegions(self::inferRegions($content)),
                static fn($p) => !isset($alwaysOnNames[$p['name']])
            ));
            $active = array_merge($alwaysOn, $gated);
        }
        if ($active === []) {
            return ['matches' => [], 'superseded' => []];
        }

        $tables = self::tableScopes($content);
        $activeExisting = $existingRanges;
        $superseded = [];
        $claimed = [];
        $found = [];
        $nearMisses = [];
        $checksums = PiiChecksums::functions();

        foreach ($active as $pattern) {
            $hits = [];
            preg_match_all(self::compile($pattern['regex']), $content, $hits, PREG_OFFSET_CAPTURE);
            foreach ($hits[0] as $hit) {
                [$text, $start] = $hit;
                if ($text === '') {
                    continue;
                }
                $end = $start + strlen($text);

                // Rules 3, 7 and 7b.
                if ($pattern['requires_keyword'] && $pattern['keywords'] !== []) {
                    $all = self::allKeywordsOf($pattern);
                    $ok = self::hasWholeWordContextAround($content, $start, $end, $pattern['whole_word_keywords']);
                    if (!$ok) {
                        $column = self::columnVerdict($content, $tables, $start, $end, $all, self::specificKeywords($all));
                        $ok = $column !== null ? $column : self::hasNearbyContext($content, $start, $end, $pattern['keywords']);
                    }
                    if (!$ok) {
                        continue;
                    }
                    if (self::labelledAsReference($content, $start, $end, $pattern['keywords'])) {
                        continue;
                    }
                }

                // Rule 4, and rule 6's candidate.
                if ($pattern['checksum_required'] && $pattern['checksum'] !== null) {
                    $fn = $checksums[$pattern['checksum']] ?? null;
                    if ($fn !== null && !$fn($text)) {
                        if ($pattern['near_miss_fallback']) {
                            $extra = $pattern['near_miss_keywords'] !== [] ? $pattern['near_miss_keywords'] : $pattern['keywords'];
                            $vocabulary = $extra !== [] ? array_merge(self::$nationalIdWords, $extra) : self::$nationalIdWords;
                            if (self::hasContextAround($content, $start, $end, $vocabulary)) {
                                $nearMisses[] = [$start, $end];
                            }
                        }
                        continue;
                    }
                }

                // Rule 5.
                $overlapping = [];
                foreach (array_merge($activeExisting, $claimed) as $r) {
                    if ($start < $r[1] && $end > $r[0]) {
                        $overlapping[] = $r;
                    }
                }
                if ($overlapping !== []) {
                    $supersedesAll = true;
                    foreach ($overlapping as $o) {
                        [$cs, $ce] = self::trimmedCore($content, $o[0], $o[1]);
                        if (!($start <= $cs && $end >= $ce)) {
                            $supersedesAll = false;
                            break;
                        }
                    }
                    if (!$supersedesAll) {
                        continue;
                    }
                    foreach ($overlapping as $o) {
                        foreach ($activeExisting as $i => $r) {
                            if ($r === $o) {
                                $superseded[] = $r;
                                unset($activeExisting[$i]);
                                $activeExisting = array_values($activeExisting);
                                break;
                            }
                        }
                        foreach ($claimed as $i => $r) {
                            if ($r === $o) {
                                unset($claimed[$i]);
                                $claimed = array_values($claimed);
                                break;
                            }
                        }
                        $found = array_values(array_filter(
                            $found,
                            static fn($f) => !($f['startIndex'] === $o[0] && $f['endIndex'] === $o[1])
                        ));
                    }
                }

                $claimed[] = [$start, $end];
                $found[] = [
                    'name' => $pattern['name'],
                    'country' => $pattern['country'],
                    'label' => $pattern['label'],
                    'type' => $pattern['type'],
                    'redaction' => $pattern['redaction'],
                    'startIndex' => $start,
                    'endIndex' => $end,
                ];
            }
        }

        // Rule 6, last: a near miss can only ever fill a hole.
        $taken = array_merge($activeExisting, $claimed);
        foreach ($nearMisses as $c) {
            $clash = false;
            foreach ($taken as $t) {
                if ($c[0] < $t[1] && $c[1] > $t[0]) {
                    $clash = true;
                    break;
                }
            }
            if ($clash) {
                continue;
            }
            $taken[] = $c;
            $found[] = [
                'name' => PiiRegistry::NEAR_MISS_TYPE,
                'country' => '',
                'label' => 'NATIONAL_ID',
                'type' => PiiRegistry::NEAR_MISS_TYPE,
                'redaction' => PiiRegistry::NEAR_MISS_REDACTION,
                'startIndex' => $c[0],
                'endIndex' => $c[1],
            ];
        }

        usort($found, static fn($a, $b) => $a['startIndex'] <=> $b['startIndex']);
        return ['matches' => $found, 'superseded' => $superseded];
    }

    /** @return list<array<string,mixed>> */
    public static function detect(string $content, ?array $patterns = null): array
    {
        return self::detectWithRanges($content, $patterns)['matches'];
    }

    /**
     * Replace every span with its redaction, right to left.
     *
     * Right to left is what keeps the earlier indices valid, and splicing whole
     * spans in one pass is what guarantees no partial redaction: a digit can
     * never be left standing beside a redaction token, because nothing is ever
     * matched against text a previous replacement has already rewritten.
     */
    public static function applyRedactions(string $text, array $spans): string
    {
        if ($spans === []) {
            return $text;
        }
        usort($spans, static fn($a, $b) => $a['startIndex'] <=> $b['startIndex']);
        $out = $text;
        for ($i = count($spans) - 1; $i >= 0; $i--) {
            $s = $spans[$i];
            $out = substr($out, 0, $s['startIndex']) . $s['redaction'] . substr($out, $s['endIndex']);
        }
        return $out;
    }
}
