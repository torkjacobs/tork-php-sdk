<?php

declare(strict_types=1);

namespace Tork\Governance\Pii;

/**
 * Check digits for the country registry.
 *
 * The SDK bundle NAMES twenty algorithms and gives weights and a modulus for
 * the eleven that reduce to them; the other nine are marked kind:"custom" and
 * carry no specification, so they are ported here by hand from the cloud's
 * lib/pii/checksums.ts -- the single implementation the cloud and the country
 * corpus both use. Keeping the arithmetic identical is what makes a receipt
 * block from this SDK byte-identical to one from the JavaScript SDK.
 *
 * Every method is pure: a string in, a bool out. No I/O, no clock.
 */
final class PiiChecksums
{
    private static function digitsOf(string $s): string
    {
        return preg_replace('/\D/', '', $s) ?? '';
    }

    /** Remainder of a long decimal digit string modulo $m, digit by digit. */
    private static function modDigits(string $digits, int $m): int
    {
        $r = 0;
        $len = strlen($digits);
        for ($i = 0; $i < $len; $i++) {
            $r = ($r * 10 + (int) $digits[$i]) % $m;
        }
        return $r;
    }

    private static function allSameDigit(string $d): bool
    {
        return $d !== '' && strspn($d, $d[0]) === strlen($d);
    }

    /** Luhn / ISO-IEC 7812-1 mod-10. */
    public static function luhn(string $input): bool
    {
        $d = self::digitsOf($input);
        $len = strlen($d);
        if ($len < 2) {
            return false;
        }
        $sum = 0;
        $dbl = false;
        for ($i = $len - 1; $i >= 0; $i--) {
            $n = (int) $d[$i];
            if ($dbl) {
                $n *= 2;
                if ($n > 9) {
                    $n -= 9;
                }
            }
            $sum += $n;
            $dbl = !$dbl;
        }
        return $sum % 10 === 0;
    }

    private const VERHOEFF_MUL = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];

    private const VERHOEFF_PERM = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];

    /** Verhoeff, the Aadhaar check digit (UIDAI Circular No. 1 of 2018). */
    public static function verhoeff(string $input): bool
    {
        $d = self::digitsOf($input);
        $c = 0;
        $len = strlen($d);
        for ($i = 0; $i < $len; $i++) {
            $digit = (int) $d[$len - 1 - $i];
            $c = self::VERHOEFF_MUL[$c][self::VERHOEFF_PERM[$i % 8][$digit]];
        }
        return $c === 0;
    }

    /** Australian TFN (ATO): weights 1,4,3,7,5,8,6,9,10, sum mod 11 == 0. */
    public static function auTfn(string $input): bool
    {
        $d = self::digitsOf($input);
        if (strlen($d) !== 9) {
            return false;
        }
        $w = [1, 4, 3, 7, 5, 8, 6, 9, 10];
        $sum = 0;
        for ($i = 0; $i < 9; $i++) {
            $sum += (int) $d[$i] * $w[$i];
        }
        return $sum % 11 === 0;
    }

    /** Australian ABN (ABR): subtract 1 from the first digit, weights 10,1,3..19, mod 89. */
    public static function auAbn(string $input): bool
    {
        $d = self::digitsOf($input);
        if (strlen($d) !== 11) {
            return false;
        }
        $w = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
        $sum = ((int) $d[0] - 1) * $w[0];
        for ($i = 1; $i < 11; $i++) {
            $sum += (int) $d[$i] * $w[$i];
        }
        return $sum % 89 === 0;
    }

    /** Australian Medicare card number (Services Australia). */
    public static function auMedicare(string $input): bool
    {
        $d = self::digitsOf($input);
        if (strlen($d) < 10 || strpos('23456', $d[0]) === false) {
            return false;
        }
        $w = [1, 3, 7, 9, 1, 3, 7, 9];
        $sum = 0;
        for ($i = 0; $i < 8; $i++) {
            $sum += (int) $d[$i] * $w[$i];
        }
        return $sum % 10 === (int) $d[8];
    }

    /** UK NHS number (NHS Data Model and Dictionary): weights 10..2, check = 11 - (sum mod 11). */
    public static function ukNhs(string $input): bool
    {
        $d = self::digitsOf($input);
        if (strlen($d) !== 10) {
            return false;
        }
        $sum = 0;
        for ($i = 0; $i < 9; $i++) {
            $sum += (int) $d[$i] * (10 - $i);
        }
        $check = 11 - ($sum % 11);
        if ($check === 11) {
            $check = 0;
        }
        if ($check === 10) {
            return false;
        }
        return $check === (int) $d[9];
    }

    /** Brazil CPF (Receita Federal): two sequential mod-11 check digits. */
    public static function brCpf(string $input): bool
    {
        $d = self::digitsOf($input);
        if (strlen($d) !== 11 || self::allSameDigit($d)) {
            return false;
        }
        $calc = static function (int $len) use ($d): int {
            $sum = 0;
            for ($i = 0; $i < $len; $i++) {
                $sum += (int) $d[$i] * ($len + 1 - $i);
            }
            $r = ($sum * 10) % 11;
            return $r === 10 ? 0 : $r;
        };
        return $calc(9) === (int) $d[9] && $calc(10) === (int) $d[10];
    }

    /** Brazil CNPJ (Receita Federal): two mod-11 check digits with different weight vectors. */
    public static function brCnpj(string $input): bool
    {
        $d = self::digitsOf($input);
        if (strlen($d) !== 14 || self::allSameDigit($d)) {
            return false;
        }
        $calc = static function (array $weights) use ($d): int {
            $sum = 0;
            foreach ($weights as $i => $w) {
                $sum += (int) $d[$i] * $w;
            }
            $r = $sum % 11;
            return $r < 2 ? 0 : 11 - $r;
        };
        return $calc([5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) === (int) $d[12]
            && $calc([6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) === (int) $d[13];
    }

    /** Japan My Number (MIC Ordinance No. 85 of 2014). */
    public static function jpMyNumber(string $input): bool
    {
        $d = self::digitsOf($input);
        if (strlen($d) !== 12) {
            return false;
        }
        $sum = 0;
        for ($n = 1; $n <= 11; $n++) {
            $p = (int) $d[11 - $n];
            $q = $n <= 6 ? $n + 1 : $n - 5;
            $sum += $p * $q;
        }
        $r = $sum % 11;
        $check = $r <= 1 ? 0 : 11 - $r;
        return $check === (int) $d[11];
    }

    /** China resident ID (GB 11643-1999): ISO 7064 MOD 11-2, check character may be X. */
    public static function cnResidentId(string $input): bool
    {
        $s = strtoupper(preg_replace('/\s/', '', $input) ?? '');
        if (preg_match('/^\d{17}[\dX]$/', $s) !== 1) {
            return false;
        }
        $w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
        $sum = 0;
        for ($i = 0; $i < 17; $i++) {
            $sum += (int) $s[$i] * $w[$i];
        }
        return '10X98765432'[$sum % 11] === $s[17];
    }

    /**
     * Korea RRN, for numbers issued before 20 Oct 2020.
     *
     * ADVISORY ONLY, never a gate: numbers issued from 20 Oct 2020 are randomly
     * assigned and carry no check digit.
     */
    public static function krRrn(string $input): bool
    {
        $d = self::digitsOf($input);
        if (strlen($d) !== 13) {
            return false;
        }
        $w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
        $sum = 0;
        for ($i = 0; $i < 12; $i++) {
            $sum += (int) $d[$i] * $w[$i];
        }
        return (11 - ($sum % 11)) % 10 === (int) $d[12];
    }

    /** Singapore NRIC/FIN (ICA): weights 2,7,6,5,4,3,2 and a prefix-dependent letter table. */
    public static function sgNric(string $input): bool
    {
        $s = strtoupper(preg_replace('/\s/', '', $input) ?? '');
        if (preg_match('/^[STFGM]\d{7}[A-Z]$/', $s) !== 1) {
            return false;
        }
        $w = [2, 7, 6, 5, 4, 3, 2];
        $sum = 0;
        for ($i = 0; $i < 7; $i++) {
            $sum += (int) $s[1 + $i] * $w[$i];
        }
        $prefix = $s[0];
        if ($prefix === 'T' || $prefix === 'G') {
            $sum += 4;
        }
        if ($prefix === 'M') {
            $sum += 3;
        }
        if ($prefix === 'S' || $prefix === 'T') {
            $table = 'JZIHGFEDCBA';
        } elseif ($prefix === 'M') {
            $table = 'KLJNPQRTUWX';
        } else {
            $table = 'XWUTRQPNMLK';
        }
        return $table[$sum % 11] === $s[8];
    }

    private const CF_ODD = [
        '0' => 1, '1' => 0, '2' => 5, '3' => 7, '4' => 9, '5' => 13, '6' => 15,
        '7' => 17, '8' => 19, '9' => 21,
        'A' => 1, 'B' => 0, 'C' => 5, 'D' => 7, 'E' => 9, 'F' => 13, 'G' => 15,
        'H' => 17, 'I' => 19, 'J' => 21, 'K' => 2, 'L' => 4, 'M' => 18, 'N' => 20,
        'O' => 11, 'P' => 3, 'Q' => 6, 'R' => 8, 'S' => 12, 'T' => 14, 'U' => 16,
        'V' => 10, 'W' => 22, 'X' => 25, 'Y' => 24, 'Z' => 23,
    ];

    /** Italy codice fiscale (Agenzia delle Entrate): odd/even tables, mod 26, check letter. */
    public static function itCodiceFiscale(string $input): bool
    {
        $s = strtoupper(preg_replace('/\s/', '', $input) ?? '');
        if (preg_match('/^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$/', $s) !== 1) {
            return false;
        }
        $sum = 0;
        for ($i = 0; $i < 15; $i++) {
            $c = $s[$i];
            if ($i % 2 === 0) {
                $sum += self::CF_ODD[$c];
            } elseif ($c >= '0' && $c <= '9') {
                $sum += (int) $c;
            } else {
                $sum += ord($c) - 65;
            }
        }
        return chr(65 + ($sum % 26)) === $s[15];
    }

    /** France NIR (Insee): 97-complement, Corsican 2A/2B mapped to 19/18 first. */
    public static function frNir(string $input): bool
    {
        $s = strtoupper(preg_replace('/\s/', '', $input) ?? '');
        if (preg_match('/^[12]\d{2}\d{2}(\d{2}|2A|2B)\d{3}\d{3}\d{2}$/', $s) !== 1) {
            return false;
        }
        $s = preg_replace('/2A/', '19', $s, 1) ?? $s;
        $s = preg_replace('/2B/', '18', $s, 1) ?? $s;
        $body = substr($s, 0, 13);
        $key = (int) substr($s, 13);
        return 97 - self::modDigits($body, 97) === $key;
    }

    /** Germany Steuer-IdNr (BZSt): ISO 7064 MOD 11,10 over 10 digits. */
    public static function deSteuerId(string $input): bool
    {
        $d = self::digitsOf($input);
        if (strlen($d) !== 11 || $d[0] === '0') {
            return false;
        }
        $product = 10;
        for ($i = 0; $i < 10; $i++) {
            $sum = ((int) $d[$i] + $product) % 10;
            if ($sum === 0) {
                $sum = 10;
            }
            $product = ($sum * 2) % 11;
        }
        $check = 11 - $product;
        if ($check === 10) {
            $check = 0;
        }
        return $check === (int) $d[10];
    }

    /** Thailand national ID (DOPA): weights 13..2, check = (11 - sum mod 11) mod 10. */
    public static function thNationalId(string $input): bool
    {
        $d = self::digitsOf($input);
        if (strlen($d) !== 13) {
            return false;
        }
        $sum = 0;
        for ($i = 0; $i < 12; $i++) {
            $sum += (int) $d[$i] * (13 - $i);
        }
        return (11 - ($sum % 11)) % 10 === (int) $d[12];
    }

    /** Canada SIN (Service Canada): Luhn over 9 digits. Advisory -- community-sourced. */
    public static function caSin(string $input): bool
    {
        return strlen(self::digitsOf($input)) === 9 && self::luhn($input);
    }

    /** South Africa ID (SARS PAYE BRS Appendix B 8.3): Luhn over 13 digits. */
    public static function zaId(string $input): bool
    {
        return strlen(self::digitsOf($input)) === 13 && self::luhn($input);
    }

    /** UAE Emirates ID (ICP): Luhn over 15 digits starting 784. Advisory. */
    public static function aeEmiratesId(string $input): bool
    {
        $d = self::digitsOf($input);
        return strlen($d) === 15 && str_starts_with($d, '784') && self::luhn($d);
    }

    /** Saudi national ID / iqama: Luhn over 10 digits starting 1 or 2. Advisory. */
    public static function saNationalId(string $input): bool
    {
        $d = self::digitsOf($input);
        return strlen($d) === 10 && ($d[0] === '1' || $d[0] === '2') && self::luhn($d);
    }

    /**
     * Keyed by the bundle's `checksum` field.
     *
     * @return array<string, callable(string): bool>
     */
    public static function functions(): array
    {
        return [
            'luhn' => [self::class, 'luhn'],
            'verhoeff' => [self::class, 'verhoeff'],
            'au_tfn' => [self::class, 'auTfn'],
            'au_abn' => [self::class, 'auAbn'],
            'au_medicare' => [self::class, 'auMedicare'],
            'uk_nhs' => [self::class, 'ukNhs'],
            'br_cpf' => [self::class, 'brCpf'],
            'br_cnpj' => [self::class, 'brCnpj'],
            'jp_my_number' => [self::class, 'jpMyNumber'],
            'cn_resident_id' => [self::class, 'cnResidentId'],
            'kr_rrn' => [self::class, 'krRrn'],
            'sg_nric' => [self::class, 'sgNric'],
            'it_codice_fiscale' => [self::class, 'itCodiceFiscale'],
            'fr_nir' => [self::class, 'frNir'],
            'de_steuer_id' => [self::class, 'deSteuerId'],
            'th_national_id' => [self::class, 'thNationalId'],
            'ca_sin' => [self::class, 'caSin'],
            'za_id' => [self::class, 'zaId'],
            'ae_emirates_id' => [self::class, 'aeEmiratesId'],
            'sa_national_id' => [self::class, 'saNationalId'],
        ];
    }
}
