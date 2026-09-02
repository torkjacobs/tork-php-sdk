<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * Tool-result scanning (DECIDED-TACT2-V2-C).
 *
 * A tool result returned by an MCP server -- or by any external system the
 * caller does not control -- is untrusted input that is about to be appended
 * to a model's context. This module scans it BEFORE that happens, on-device,
 * for two things:
 *
 *   1. PII, using the SAME on-device detector as Tork::govern() reuses
 *      (Pii::detect()). Same patterns, same redaction labels, same
 *      zero-network guarantee -- see Pii.php.
 *   2. Prompt injection, using the conservative heuristic pattern set below,
 *      ported verbatim from tool-result-scan.ts's INJECTION_PATTERNS. Every
 *      injection finding is labelled `heuristic:<type>` so no caller can
 *      mistake a regex hit for a verified determination.
 *
 * ZERO NETWORK. Every method here is pure and synchronous: no curl, no
 * stream-wrapper I/O, no clock. The payload never leaves the machine.
 *
 * WHAT THIS IS NOT: this is a client-side control that the CALLER runs and
 * the caller attests to. It is not gateway-side enforcement -- a compromised
 * or simply careless caller can skip it entirely, and Tork cannot tell.
 *
 * This is a port of tool-result-scan.ts (DECIDED-TACT2-V2-C). What matches
 * the JS SDK exactly: the `tool_result_scan` receipt block (snake_case keys,
 * emitted alphabetically, optional keys omitted rather than nulled),
 * attested_by='client', capture_mode='edge',
 * injection_ruleset='tork-injection-heuristics-v1', the `heuristic:`
 * finding-type prefix, the three injection type names (instruction_override,
 * role_reassignment, exfiltration_url), the four-way action mapping in
 * Tork::scanToolResult(), the location path grammar ($.a[0].b), and the
 * injection regex sources themselves (delimiter/flag translation only --
 * PCRE needs no lookaround rewriting for this pattern set).
 *
 * Traversal mechanics are reimplemented in PHP idiom because PHP's array
 * type serves as BOTH JSON array and JSON object, which JS/Python's
 * dict-vs-list distinction does not need to resolve:
 *
 *   RULE: a PHP `array` is walked as a JSON ARRAY when array_is_list() is
 *   true (sequential integer keys from 0), and as a JSON OBJECT (map)
 *   otherwise. An empty array `[]` is, by PHP's own definition, a list
 *   (array_is_list([]) === true) -- so an empty array is always treated as
 *   an empty JSON array, consistent with PHP's own json_encode([]) === '[]'
 *   default. stdClass instances (e.g. from json_decode($json) without the
 *   associative flag) are always walked as objects -- there is no ambiguity
 *   for them, and they are also where true reference cycles can occur, so
 *   the cycle guard (a spl_object_id 'seen' set, mirroring the JS WeakSet)
 *   only needs to track objects: plain PHP arrays are value types, so a
 *   self-assignment like `$a['self'] = $a` copies a snapshot rather than
 *   forming a cycle, and cannot loop `walk()` forever. maxDepth remains the
 *   backstop for the rare case of a genuine reference-built array cycle
 *   (`$a['self'] =& $a`).
 *
 * Identity preservation: for stdClass objects, an unchanged sub-tree returns
 * the exact same instance, so PHP's `===` (true reference identity for
 * objects) holds exactly as JS's `===` does. For arrays, PHP has no
 * reference identity distinct from value equality -- `===` on two arrays
 * already compares keys/values/types recursively -- so "identity
 * preservation" for arrays is a value-equality optimization (skip rebuilding
 * an unchanged array) rather than an observable reference guarantee.
 */
final class ToolResultScan
{
    /**
     * Prefix on every injection finding's `type`. Not cosmetic: these
     * patterns are regexes over untrusted text, they carry false positives
     * and false negatives, and the label travels with the finding into the
     * receipt.
     */
    public const INJECTION_HEURISTIC_PREFIX = 'heuristic:';

    /**
     * Identifies this exact pattern set in receipts. Every SDK mirroring
     * this implementation emits the SAME value for the same ruleset -- it
     * is a shared identifier, not a per-language one.
     */
    public const INJECTION_RULESET = 'tork-injection-heuristics-v1';

    /** Maximum nesting depth walked by default. Deeper values pass through unscanned. */
    public const DEFAULT_MAX_DEPTH = 32;

    private const IDENTIFIER = '~^[A-Za-z_$][A-Za-z0-9_$]*$~';

    /**
     * Conservative on purpose. Each pattern targets a phrase that has no
     * plausible reason to appear in a legitimate tool result -- a database
     * row, a search hit, a file listing.
     *
     * Regex sources ported verbatim from INJECTION_PATTERNS in
     * tool-result-scan.ts. JS's /gi -> PHP 'i'; JS's /gim -> PHP 'im'. The
     * '~' delimiter is used throughout (rather than '/') because the
     * exfiltration_url patterns contain literal 'https?://' sequences.
     *
     * @var list<array{type: string, pattern: string}>
     */
    private const INJECTION_PATTERNS = [
        // -- instruction override --------------------------------------------
        [
            'type' => 'instruction_override',
            'pattern' => '~\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|preceding|all|any)\b[^.\n]{0,30}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b~i',
        ],
        [
            'type' => 'instruction_override',
            'pattern' => '~\b(?:the\s+)?(?:instructions?|prompts?|rules?)\s+(?:above|below|before\s+this)\s+(?:are|is)\s+(?:now\s+)?(?:void|invalid|obsolete|outdated|no\s+longer\s+(?:valid|active|in\s+effect))\b~i',
        ],
        [
            'type' => 'instruction_override',
            'pattern' => '~\bdisregard\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\b~i',
        ],

        // -- role reassignment ------------------------------------------------
        [
            'type' => 'role_reassignment',
            'pattern' => '~\byou\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b~i',
        ],
        [
            'type' => 'role_reassignment',
            'pattern' => '~\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+this\s+(?:conversation|session))\b[^.\n]{0,30}\byou\s+(?:are|will|must|should)\b~i',
        ],
        [
            'type' => 'role_reassignment',
            'pattern' => '~\bnew\s+(?:system\s+)?(?:instructions?|prompt|persona|role)\s*:~i',
        ],
        [
            'type' => 'role_reassignment',
            'pattern' => '~\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak|unrestricted)\s+mode\b~i',
        ],
        [
            'type' => 'role_reassignment',
            'pattern' => '~\b(?:act|behave|respond|pretend\s+to\s+be)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken)\b~i',
        ],
        [
            // A role header smuggled into content -- "system:" / "<|im_start|>system"
            // at the start of a line is a conversation-structure forgery, not prose.
            'type' => 'role_reassignment',
            'pattern' => '~^[ \t>*-]*(?:<\|im_start\|>\s*)?(?:system|assistant|developer)\s*(?::|\]|>)~im',
        ],

        // -- exfiltration -----------------------------------------------------
        [
            // A markdown image/link whose URL carries the content out as a query
            // parameter -- the classic zero-click exfiltration shape.
            'type' => 'exfiltration_url',
            'pattern' => '~!?\[[^\]\n]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:data|payload|prompt|content|text|secret|token|key|conversation|history)=[^)\s]*\)~i',
        ],
        [
            'type' => 'exfiltration_url',
            'pattern' => '~\bhttps?://\S*[?&](?:data|payload|secret|token|api[_-]?key|apikey|password|credential|conversation|history)=~i',
        ],
        [
            'type' => 'exfiltration_url',
            'pattern' => '~\b(?:send|post|upload|forward|transmit|exfiltrate|leak|report)\b[^.\n]{0,60}\bto\s+https?://\S+~i',
        ],
    ];

    /** Distinct injection types the ruleset can emit, for documentation/tests. */
    public static function injectionTypes(): array
    {
        $types = array_unique(array_column(self::INJECTION_PATTERNS, 'type'));
        sort($types);
        return array_values($types);
    }

    private static function isIdentifier(string $key): bool
    {
        return (bool) preg_match(self::IDENTIFIER, $key);
    }

    private static function childPath(string $parent, string $key): string
    {
        return self::isIdentifier($key)
            ? "{$parent}.{$key}"
            : "{$parent}[" . json_encode($key, JSON_UNESCAPED_SLASHES) . ']';
    }

    /**
     * Scan one string: PII (via Pii::detect()) then injection heuristics.
     * Returns the masked string plus any findings, both keyed to $location.
     *
     * @param array<string, string>|null $customPatterns
     * @param list<ToolResultFinding> $findings
     */
    private static function scanString(
        string $text,
        string $location,
        ?array $customPatterns,
        array &$findings
    ): string {
        $pii = Pii::detect($text, $customPatterns);

        if ($pii['count'] > 0) {
            // Counts per type, emitted in a stable (sorted) order so two
            // runs over the same payload produce identical findings.
            $perType = [];
            foreach ($pii['matches'] as $match) {
                $perType[$match['type']] = ($perType[$match['type']] ?? 0) + 1;
            }
            ksort($perType);
            foreach ($perType as $type => $count) {
                $findings[] = new ToolResultFinding('pii', $type, $count, $location);
            }
        }

        $perInjectionType = [];
        foreach (self::INJECTION_PATTERNS as ['type' => $type, 'pattern' => $pattern]) {
            $count = preg_match_all($pattern, $text);
            if ($count) {
                $perInjectionType[$type] = ($perInjectionType[$type] ?? 0) + $count;
            }
        }
        ksort($perInjectionType);
        foreach ($perInjectionType as $type => $count) {
            $findings[] = new ToolResultFinding(
                'injection',
                self::INJECTION_HEURISTIC_PREFIX . $type,
                $count,
                $location
            );
        }

        return $pii['redactedText'];
    }

    /**
     * Walk the payload, scanning every string. Returns a structure with PII
     * masked in place; sub-trees with nothing to mask keep their original
     * value/identity (see the class docblock for the array-vs-object rule
     * and the identity-preservation caveat for arrays).
     *
     * Only strings are scanned. Numbers, booleans, and anything else
     * non-array/non-object passes through untouched -- a bank account
     * stored as a JSON number is NOT detected. Cycles among objects are
     * left as-is and not re-entered; array "cycles" cannot form through
     * ordinary PHP assignment (see class docblock).
     *
     * @param array<string, string>|null $customPatterns
     * @param list<ToolResultFinding> $findings
     * @param array<int, true> $seen spl_object_id() => true, for cycle guarding objects
     */
    private static function walk(
        mixed $value,
        string $location,
        int $depth,
        int $maxDepth,
        ?array $customPatterns,
        array &$findings,
        array &$seen
    ): mixed {
        if (is_string($value)) {
            return self::scanString($value, $location, $customPatterns, $findings);
        }

        if ($depth >= $maxDepth || $value === null || (!is_array($value) && !is_object($value))) {
            return $value;
        }

        if (is_object($value)) {
            $id = spl_object_id($value);
            if (isset($seen[$id])) {
                return $value;
            }
            $seen[$id] = true;

            $changed = false;
            $out = new \stdClass();
            foreach (get_object_vars($value) as $key => $item) {
                $next = self::walk(
                    $item,
                    self::childPath($location, (string) $key),
                    $depth + 1,
                    $maxDepth,
                    $customPatterns,
                    $findings,
                    $seen
                );
                if ($next !== $item) {
                    $changed = true;
                }
                $out->{$key} = $next;
            }
            return $changed ? $out : $value;
        }

        // is_array($value) from here on.
        if (array_is_list($value)) {
            $changed = false;
            $out = [];
            foreach ($value as $index => $item) {
                $next = self::walk(
                    $item,
                    "{$location}[{$index}]",
                    $depth + 1,
                    $maxDepth,
                    $customPatterns,
                    $findings,
                    $seen
                );
                if ($next !== $item) {
                    $changed = true;
                }
                $out[] = $next;
            }
            return $changed ? $out : $value;
        }

        $changed = false;
        $out = [];
        foreach ($value as $key => $item) {
            $next = self::walk(
                $item,
                self::childPath($location, (string) $key),
                $depth + 1,
                $maxDepth,
                $customPatterns,
                $findings,
                $seen
            );
            if ($next !== $item) {
                $changed = true;
            }
            $out[$key] = $next;
        }
        return $changed ? $out : $value;
    }

    /**
     * Scan a tool result for PII and prompt injection before it is appended
     * to model context. Pure, synchronous, on-device: makes no network call
     * and mutates nothing.
     *
     * @param array{toolName: string, serverUri?: ?string, payload: mixed} $input
     * @param array{blockOnInjection?: bool, customPatterns?: array<string,string>, maxDepth?: int} $options
     *
     * For the receipt-linked form (attested_by='client', capture_mode='edge'),
     * use Tork::scanToolResult(), which wraps this and records the scan.
     */
    public static function scan(array $input, array $options = []): ToolResultScanResult
    {
        $toolName = $input['toolName'] ?? '';
        $payload = $input['payload'] ?? null;

        $findings = [];
        $seen = [];
        $sanitized = self::walk(
            $payload,
            '$',
            0,
            $options['maxDepth'] ?? self::DEFAULT_MAX_DEPTH,
            $options['customPatterns'] ?? null,
            $findings,
            $seen
        );

        $injectionCount = self::scanInjectionCount($findings);
        $blocked = !empty($options['blockOnInjection']) && $injectionCount > 0;

        if ($blocked) {
            $types = array_unique(array_map(
                static fn(ToolResultFinding $f) => $f->type,
                array_filter($findings, static fn(ToolResultFinding $f) => $f->kind === 'injection')
            ));
            sort($types);
            $reason = sprintf(
                'Blocked: %d prompt-injection heuristic match(es) [%s] in the result of tool "%s". '
                . 'These are heuristic pattern matches (%s), not a verified determination. sanitized is '
                . 'null so no masked copy can be appended to context by accident.',
                $injectionCount,
                implode(', ', $types),
                $toolName,
                self::INJECTION_RULESET
            );
            return new ToolResultScanResult(null, $findings, true, $reason);
        }

        return new ToolResultScanResult($sanitized, $findings, false, null);
    }

    /**
     * @param list<ToolResultFinding> $findings
     * @return array<string, int>
     */
    private static function countsByType(array $findings, string $kind): array
    {
        $totals = [];
        foreach ($findings as $finding) {
            if ($finding->kind !== $kind) {
                continue;
            }
            $totals[$finding->type] = ($totals[$finding->type] ?? 0) + $finding->count;
        }
        ksort($totals);
        return $totals;
    }

    /**
     * A PHP associative array with string keys already json_encodes as an
     * object -- EXCEPT when it is empty, where PHP's json_encode([]) always
     * produces '[]', not '{}' (the same list/map ambiguity documented on the
     * class, now on the output side). findings.injection / findings.pii
     * must stay object-shaped even with zero counts, so an empty map is cast
     * to stdClass, which json_encode always renders as '{}'.
     *
     * @param array<string, int> $counts
     */
    private static function asJsonMap(array $counts): array|\stdClass
    {
        return $counts === [] ? new \stdClass() : $counts;
    }

    /**
     * Build the `tool_result_scan` receipt block for a completed scan.
     *
     * snake_case, keys emitted in alphabetical order (this is simply
     * insertion order below -- PHP arrays preserve it, and json_encode()
     * emits keys in that same order), optional keys OMITTED entirely rather
     * than set to null. Every SDK mirroring this must produce a
     * byte-identical block for the same scan. It carries COUNTS ONLY: no
     * payload, no matched substring, no location path, no tool argument
     * ever appears here.
     */
    public static function buildReceiptBlock(
        string $toolName,
        ?string $serverUri,
        ToolResultScanResult $result,
        string $sdkVersion
    ): array {
        $pii = self::countsByType($result->findings, 'pii');
        $injection = self::countsByType($result->findings, 'injection');
        $sum = static fn(array $counts): int => array_sum($counts);

        $block = [
            'attested_by' => 'client',
            'blocked' => $result->blocked,
            'capture_mode' => 'edge',
            'findings' => [
                'injection' => self::asJsonMap($injection),
                'pii' => self::asJsonMap($pii),
            ],
            'injection_ruleset' => self::INJECTION_RULESET,
        ];
        if ($result->reason !== null) {
            $block['reason'] = $result->reason;
        }
        $block['sdk_language'] = 'php';
        $block['sdk_version'] = $sdkVersion;
        if ($serverUri !== null) {
            $block['server_uri'] = $serverUri;
        }
        $block['tool_name'] = $toolName;
        $block['totals'] = ['injection' => $sum($injection), 'pii' => $sum($pii)];

        return $block;
    }

    /**
     * @param list<ToolResultFinding> $findings
     * @return list<string>
     */
    public static function scanPiiTypes(array $findings): array
    {
        $types = array_unique(array_map(
            static fn(ToolResultFinding $f) => $f->type,
            array_filter($findings, static fn(ToolResultFinding $f) => $f->kind === 'pii')
        ));
        sort($types);
        return array_values($types);
    }

    /** @param list<ToolResultFinding> $findings */
    public static function scanPiiCount(array $findings): int
    {
        $count = 0;
        foreach ($findings as $f) {
            if ($f->kind === 'pii') {
                $count += $f->count;
            }
        }
        return $count;
    }

    /** @param list<ToolResultFinding> $findings */
    public static function scanInjectionCount(array $findings): int
    {
        $count = 0;
        foreach ($findings as $f) {
            if ($f->kind === 'injection') {
                $count += $f->count;
            }
        }
        return $count;
    }
}
