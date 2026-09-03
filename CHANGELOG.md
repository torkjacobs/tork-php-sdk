# Changelog

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
