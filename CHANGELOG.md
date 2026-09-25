# Changelog

## 1.1.0 - 2026-09-25

### Added
- PII registry bundle 1.2.0 (24 countries, incl. AU TFN/ABN/Medicare).
- **The country layer: 24 country profiles, 54 patterns, 20 check digits.**
  Patterns, keywords, redaction labels and checksum gates are generated from
  Tork's own country registry and consumed verbatim from the SDK bundle
  (`Registry-Version: 1.2.0`, content `cfd4f61ebaf45e74`). Countries: AU, US, GB, EU, AE, SA, NG, IN, JP,
  CN, KR, BR, CA, ZA, GH, IT, KE, MU, MX, MY, PK, SG, TH, ID.
- **`au_tfn`, `au_abn` and `au_medicare` run unconditionally (bundle rule 1a),
  before country activation, so a valid Australian TFN, ABN or Medicare
  number is caught even in a sentence that activates no AU signal at all** —
  the exact case the bundle's own README cites for why they are `alwaysOn`.
  `au_tfn`'s checksum is required with a near-miss fallback (a checksum-failing
  TFN is redacted generically, not dropped); `au_abn`'s is required with no
  fallback (a checksum-failing ABN is not matched, like `br_cnpj`);
  `au_medicare`'s is advisory only and never rejects a match, because Services
  Australia publishes no check-digit algorithm.
- New classes under `Tork\Governance\Pii`: `PiiRegistry` (the bundle's 50
  patterns), `PiiActivation` (the 51 signals and the country map),
  `PiiChecksums` (20 algorithms) and `PiiCountry` (the matcher). All pure and
  local: no network, no clock.
- `Pii::detect()` returns three further keys — `countryMatches`,
  `countryLabels` and `regions` — and takes an optional third argument,
  `$regionOverride`. The existing keys and the first two arguments are
  unchanged.
- **Nine check digits ported by hand.** The bundle names twenty algorithms and
  specifies the eleven that reduce to a weight vector and a modulus; the other
  nine (`br_cpf`, `br_cnpj`, `cn_resident_id`, `de_steuer_id`, `fr_nir`,
  `it_codice_fiscale`, `jp_my_number`, `kr_rrn`, `sg_nric`) are ported from the
  cloud's `lib/pii/checksums.ts`, each tested against the issuing authority's
  own worked example where one is published.

### Fixed
- **SDK-PHP-PARTIAL-REDACTION.** Until 1.0.0 each type was redacted with its own
  `preg_replace` over text a previous type had already rewritten, and the match
  list carried no offsets at all. Two types matching overlapping spans could
  leave half an identifier standing beside a redaction token -- digits exposed
  in output the caller had been told was redacted. Every match is now collected
  against the original text with `PREG_OFFSET_CAPTURE`, overlaps are resolved
  before anything is rewritten, and the surviving spans are spliced right to
  left in one pass. `testNothingIsEverPartiallyRedacted` asserts the invariant
  across all 2,092 vectors.
- **`Tork::govern()` ignored `$region`.** It was accepted, echoed back on the
  result, and never used to select a pattern. It now drives detection.

### Notes
- **The bundle now states the whole contract, and this SDK implements it.**
  Bundle 1.0.0's README documented three rules; measured against the cloud's
  golden snapshot they disagreed with it on 14 of 86 country-corpus cases, so
  this SDK carried two more of its own. Bundle **1.1.0 documents seven**, marks
  each SDK or cloud-only, and ships the data all seven need in every language
  file -- the activation signals, the country map, the asymmetric 60/40 window,
  the symmetric 60 context window, the whole-word vocabulary, the near-miss
  policy, the table constants and the reference labels. So the locally generated
  activation layer is **deleted**, no window is hard-coded any more, and rules 6
  (near miss), 7 (column header) and 7b (nearest label) are implemented here for
  the first time. Every rule now reads its data off the placed bundle.
- The registry's regexes carry no PCRE delimiter and one of them contains a
  forward slash, so `PiiCountry` wraps them in `#`. A test asserts no pattern in
  the bundle contains that character, so a future bundle cannot silently break
  the wrapping.
- Advisory checksums never reject a match: `ca_sin`, `emirates_id`,
  `de_tax_id`, `kr_rrn`, `sa_national_id`. Korea stopped issuing check digits on
  20 Oct 2020.
- Not ported, and still cloud-only: the slot, context,
  gravity and name layers, industry profiles, and org configuration.
- **Indonesia is the country 1.1.0 added, and it is the one that proves the
  whole-word rule.** `id_nik`'s only short spellings -- NIK, KTP, NPWP -- are
  `wholeWordKeywords`, not ordinary keywords, because `nik` sits inside
  *teknik*, *elektronik*, *klinik* and *pabrik*. Matching them by substring
  would open the gate on an Indonesian sales ledger; matching them on a word
  boundary catches "NIK 3171010101900001" and leaves *teknik* alone. An SDK that
  merged the two lists would be shipping a false-positive bug, so the boundary
  test is implemented rather than the shortcut, and four unit cases assert both
  halves.
- **FLAGGED, upstream: bundle 1.1.0 cannot detect Australia's TFN, ABN or
  Medicare number.** `checksums.json` declares `au_tfn` and `au_abn` as
  `requiredBy` and `au_medicare` as `advisoryFor` patterns of those names, and
  `patterns` ships none of them -- the AU profile carries only `au_acn` and
  `au_phone_intl`. The AU activation signals are still keyed on "tfn", "tax
  file" and "medicare", so the bundle switches Australia on for identifiers it
  then has no pattern to catch. The cloud detects all three. This is a recall
  gap no SDK can close from the bundle, and the six parity cases it costs are
  recorded in the fixture as `BUNDLE GAP` rather than silently accepted.

## 1.0.0 - 2026-09-03

### Breaking

`Tork::govern()` no longer runs its own separate 5-pattern PII detector.
It now detects through the same `Pii::PII_PATTERNS` table (`src/Core/Pii.php`)
that `Tork::scanToolResult()` already used — the two detection paths are
unified into one so PII is no longer caught on one public method and missed
on the other for the same input (SDK-PHP-GOVERN-USES-FIVE-PATTERN-DETECTOR-
BESIDE-TEN-PATTERN-SCAN). There is no compatibility shim: the old uppercase
type keys and old labels are gone, not kept alive alongside the new ones.

This changes, for every existing `Tork::govern()` caller:

- **`GovernanceResult::$receipt->piiTypesDetected`** — type keys are now
  lowercase `snake_case`, not `UPPER_SNAKE_CASE`.
- **`GovernanceResult::$output`** redaction labels — two of the five
  previously-supported types changed their label text (the other three are
  unchanged, listed for completeness).
- **Detection coverage** — five new PII types are now caught by `govern()`
  that were previously invisible to it (they were already caught by
  `scanToolResult()`): `address`, `date_of_birth`, `passport`,
  `drivers_license`, `bank_account`.
- **Custom patterns** (`Tork` constructor's `customPatterns` / Laravel's
  `config/tork.php` `customPatterns` / Symfony's `custom_patterns`) —
  previously counted as PII (added to `piiTypesDetected`, drove the
  `redact`/`deny`/`escalate` action). They now only redact `$output` text,
  matching `Pii::detect()`'s existing custom-pattern contract used by
  `scanToolResult()` — they no longer appear in `piiTypesDetected` and no
  longer by themselves change `$result->action` away from `allow`. Redaction
  labels for custom patterns are now always uppercased
  (`[{STRTOUPPER(name)}_REDACTED]`); previously the configured key's case was
  used as-is.

Old type key → new type key, and old redaction label → new redaction label,
for every type `govern()` supported before 1.0.0:

| Old type key  | New type key  | Old label                  | New label             |
|---------------|---------------|-----------------------------|------------------------|
| `SSN`         | `ssn`         | `[SSN_REDACTED]`            | `[SSN_REDACTED]` (unchanged) |
| `EMAIL`       | `email`       | `[EMAIL_REDACTED]`          | `[EMAIL_REDACTED]` (unchanged) |
| `PHONE`       | `phone`       | `[PHONE_REDACTED]`          | `[PHONE_REDACTED]` (unchanged) |
| `CREDIT_CARD` | `credit_card` | `[CREDIT_CARD_REDACTED]`    | `[CARD_REDACTED]`      |
| `IP_ADDRESS`  | `ip_address`  | `[IP_ADDRESS_REDACTED]`     | `[IP_REDACTED]`        |

New types `govern()` now also detects (no old equivalent — previously
undetected by `govern()`, already detected by `scanToolResult()`):

| New type key      | New label             |
|-------------------|-------------------------|
| `address`         | `[ADDRESS_REDACTED]`   |
| `date_of_birth`   | `[DOB_REDACTED]`       |
| `passport`        | `[PASSPORT_REDACTED]`  |
| `drivers_license` | `[DL_REDACTED]`        |
| `bank_account`    | `[ACCOUNT_REDACTED]`   |

**Migration:** update any code or tests asserting on `piiTypesDetected`
values or on the two changed redaction-label strings above (`CREDIT_CARD` /
`[CREDIT_CARD_REDACTED]` and `IP_ADDRESS` / `[IP_ADDRESS_REDACTED]`). If you
relied on a custom pattern alone driving `$result->action` to `redact` /
`deny` / `escalate`, add a corresponding entry (or an equivalent built-in
type) so the content is still classified as PII, not just cosmetically
redacted.

## 0.1.0 - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)
