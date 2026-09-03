<?php

declare(strict_types=1);

namespace Tork\Governance\Core;

/**
 * The on-device PII detector: Tier 1 basic vocabulary (10 types), ported
 * byte-for-byte from tork-js-sdk's pii.ts. This is the ONLY PII pattern
 * table in the PHP SDK -- Tork::govern() and the tool-result-scan port
 * (DECIDED-TACT2-V2-C) both detect through Pii::detect() so the two paths
 * cannot drift into two vocabularies. Prior to 1.0.0, govern() ran its own
 * separate 5-pattern table with uppercase type keys; that table has been
 * removed, not kept alongside this one as a shim.
 *
 * Type keys and redaction labels are JS-identical (lowercase snake_case
 * types, e.g. 'ip_address' -> '[IP_REDACTED]') so a receipt produced by this
 * SDK reads the same as one produced by the JS or Python SDK for the same
 * input. This is the PHP SDK's Tier 1 tier — the basic 10-type vocabulary
 * only; it does not implement Python's regional/industry tier.
 *
 * Regex sources are ported verbatim from PII_PATTERNS in pii.ts. PCRE
 * supports the same constructs used there (character classes, bounded
 * quantifiers, \b/\d/\s/\w) with no lookaround anywhere in this set, so no
 * pattern needed rewriting — only delimiter and flag translation:
 *   - JS /pattern/g   -> PHP '~pattern~'   (preg_match_all already returns
 *     every match, so there is no PHP equivalent of the `g` flag to carry)
 *   - JS /pattern/gi  -> PHP '~pattern~i'
 * The '~' delimiter (rather than '/') is used throughout because
 * date_of_birth's pattern contains a literal '/' (the date separator) and a
 * single consistent delimiter is used for every pattern in this table.
 * No '/u' (PCRE_UTF8) modifier is added: every pattern here is built purely
 * from ASCII character classes (\d \w \s \b and literal A-Z ranges), which
 * match identically in PCRE's default byte mode and JS's non-unicode regex
 * mode for the ASCII text these patterns target: multi-byte UTF-8 sequences
 * simply never satisfy \d/\w and pass through unmatched in both engines.
 *
 * Zero network, zero I/O, zero clock reads. Pure and synchronous.
 */
final class Pii
{
    /**
     * @var array<string, array{pattern: string, redaction: string}>
     *
     * Insertion order matters: it is the order patterns are applied to
     * produce `redactedText`, matching pii.ts's Object.entries() order
     * exactly, so overlapping patterns (e.g. bank_account's broad
     * \d{8,17} applied last) redact in the same sequence as the JS SDK.
     */
    public const PII_PATTERNS = [
        'ssn' => [
            'pattern' => '~\b\d{3}-\d{2}-\d{4}\b~',
            'redaction' => '[SSN_REDACTED]',
        ],
        'credit_card' => [
            'pattern' => '~\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b~',
            'redaction' => '[CARD_REDACTED]',
        ],
        'email' => [
            'pattern' => '~\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b~',
            'redaction' => '[EMAIL_REDACTED]',
        ],
        'phone' => [
            'pattern' => '~\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b~',
            'redaction' => '[PHONE_REDACTED]',
        ],
        'address' => [
            'pattern' => '~\b\d{1,5}\s+\w+(?:\s+\w+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b~i',
            'redaction' => '[ADDRESS_REDACTED]',
        ],
        'ip_address' => [
            'pattern' => '~\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b~',
            'redaction' => '[IP_REDACTED]',
        ],
        'date_of_birth' => [
            'pattern' => '~\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b~',
            'redaction' => '[DOB_REDACTED]',
        ],
        'passport' => [
            'pattern' => '~\b[A-Z]{1,2}\d{6,9}\b~',
            'redaction' => '[PASSPORT_REDACTED]',
        ],
        'drivers_license' => [
            'pattern' => '~\b[A-Z]\d{7,14}\b~',
            'redaction' => '[DL_REDACTED]',
        ],
        'bank_account' => [
            'pattern' => '~\b\d{8,17}\b~',
            'redaction' => '[ACCOUNT_REDACTED]',
        ],
    ];

    /**
     * Detect PII in text and return detection results with redacted text.
     *
     * @param array<string, string>|null $customPatterns Extra redaction
     *   patterns as name => PCRE pattern string (same shape as
     *   TorkConfig.customPatterns / config/tork.php's customPatterns).
     *   NOTE (inherited from pii.ts): custom patterns redact but are not
     *   counted, so they can change redactedText without producing a match.
     * @return array{hasPII: bool, types: list<string>, count: int, matches: list<array{type: string, value: string}>, redactedText: string}
     */
    public static function detect(string $text, ?array $customPatterns = null): array
    {
        $matches = [];
        $detectedTypes = [];
        $redactedText = $text;

        foreach (self::PII_PATTERNS as $type => $spec) {
            $count = preg_match_all($spec['pattern'], $text);
            if ($count) {
                $detectedTypes[$type] = true;
                for ($i = 0; $i < $count; $i++) {
                    $matches[] = ['type' => $type, 'value' => '[REDACTED]'];
                }
            }
            $redactedText = preg_replace($spec['pattern'], $spec['redaction'], $redactedText);
        }

        if ($customPatterns !== null) {
            foreach ($customPatterns as $name => $pattern) {
                $redactedText = preg_replace($pattern, '[' . strtoupper($name) . '_REDACTED]', $redactedText);
            }
        }

        return [
            'hasPII' => count($matches) > 0,
            'types' => array_keys($detectedTypes),
            'count' => count($matches),
            'matches' => $matches,
            'redactedText' => $redactedText,
        ];
    }
}
