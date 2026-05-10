<?php
/**
 * Distro-aware version ordering for vulnerability correlation (no shell; no arbitrary regex from feeds).
 *
 * - dpkg: epoch + verrevcmp (~ ordering, digit runs, alpha) — aligned with dpkg string_version.c
 * - rpm: rpmvercmp-style digit / non-digit segment compare (foundation)
 * - generic: PHP version_compare when both look semver-ish; else binary-safe strcmp
 */

declare(strict_types=1);

/** @return -1 if $a < $b, 0 if equal, 1 if $a > $b */
function st_vcmp_dpkg_order_char(?string $c): int
{
    if ($c === null || $c === '') {
        return 0;
    }
    $o = ord($c);
    if ($c === '~') {
        return -1;
    }
    if ($o >= 48 && $o <= 57) {
        return 0;
    }
    if (($o >= 65 && $o <= 90) || ($o >= 97 && $o <= 122)) {
        return 256 + $o;
    }

    return 256 + $o;
}

/**
 * dpkg verrevcmp on one segment (no epoch here).
 *
 * @return -1|0|1
 */
function st_vcmp_dpkg_verrevcmp(string $a, string $b): int
{
    $la = strlen($a);
    $lb = strlen($b);
    $i = 0;
    $j = 0;
    while ($i < $la || $j < $lb) {
        while (($i < $la && ($a[$i] < '0' || $a[$i] > '9')) || ($j < $lb && ($b[$j] < '0' || $b[$j] > '9'))) {
            $vc = st_vcmp_dpkg_order_char($i < $la ? $a[$i] : null);
            $rc = st_vcmp_dpkg_order_char($j < $lb ? $b[$j] : null);
            if ($vc !== $rc) {
                return $vc < $rc ? -1 : 1;
            }
            if ($i < $la) {
                ++$i;
            }
            if ($j < $lb) {
                ++$j;
            }
        }
        if (($i < $la && ($a[$i] < '0' || $a[$i] > '9')) || ($j < $lb && ($b[$j] < '0' || $b[$j] > '9'))) {
            continue;
        }
        if ($i >= $la || $j >= $lb) {
            break;
        }
        $sa = $i;
        while ($i < $la && $a[$i] >= '0' && $a[$i] <= '9') {
            ++$i;
        }
        $sb = $j;
        while ($j < $lb && $b[$j] >= '0' && $b[$j] <= '9') {
            ++$j;
        }
        $na = (int) substr($a, $sa, $i - $sa);
        $nb = (int) substr($b, $sb, $j - $sb);
        if ($na !== $nb) {
            return $na < $nb ? -1 : 1;
        }
    }

    return 0;
}

/**
 * Compare two Debian/dpkg version strings (installed vs advisory threshold).
 *
 * @return -1 if $a < $b, 0 if equal, 1 if $a > $b
 */
function st_vcmp_dpkg(string $a, string $b): int
{
    $a = trim($a);
    $b = trim($b);
    if ($a === $b) {
        return 0;
    }
    $ea = 0;
    $eb = 0;
    $ra = $a;
    $rb = $b;
    $pa = strpos($a, ':');
    if ($pa !== false && $pa > 0) {
        $ep = substr($a, 0, $pa);
        if (preg_match('/^\d+$/', $ep) === 1) {
            $ea = (int) $ep;
            $ra = substr($a, $pa + 1);
        }
    }
    $pb = strpos($b, ':');
    if ($pb !== false && $pb > 0) {
        $ep = substr($b, 0, $pb);
        if (preg_match('/^\d+$/', $ep) === 1) {
            $eb = (int) $ep;
            $rb = substr($b, $pb + 1);
        }
    }
    if ($ea !== $eb) {
        return $ea < $eb ? -1 : 1;
    }

    return st_vcmp_dpkg_verrevcmp($ra, $rb);
}

/**
 * rpmvercmp-style compare (foundation; NEVRA parsing stays upstream of this).
 *
 * @return -1|0|1
 */
function st_vcmp_rpm(string $a, string $b): int
{
    $a = trim($a);
    $b = trim($b);
    if ($a === $b) {
        return 0;
    }
    $la = strlen($a);
    $lb = strlen($b);
    $i = 0;
    $j = 0;
    while ($i < $la || $j < $lb) {
        while ($i < $la && ! ctype_alnum($a[$i])) {
            ++$i;
        }
        while ($j < $lb && ! ctype_alnum($b[$j])) {
            ++$j;
        }
        if ($i >= $la || $j >= $lb) {
            break;
        }
        $isa = ctype_digit($a[$i]);
        $isb = ctype_digit($b[$j]);
        if ($isa !== $isb) {
            return $isa ? 1 : -1;
        }
        if ($isa) {
            $sa = $i;
            while ($i < $la && ctype_digit($a[$i])) {
                ++$i;
            }
            $sb = $j;
            while ($j < $lb && ctype_digit($b[$j])) {
                ++$j;
            }
            $na = (int) substr($a, $sa, $i - $sa);
            $nb = (int) substr($b, $sb, $j - $sb);
            if ($na !== $nb) {
                return $na < $nb ? -1 : 1;
            }
        } else {
            $sa = $i;
            while ($i < $la && ctype_alpha($a[$i])) {
                ++$i;
            }
            $sb = $j;
            while ($j < $lb && ctype_alpha($b[$j])) {
                ++$j;
            }
            $ca = strtolower(substr($a, $sa, $i - $sa));
            $cb = strtolower(substr($b, $sb, $j - $sb));
            $c = strcmp($ca, $cb);
            if ($c !== 0) {
                return $c < 0 ? -1 : 1;
            }
        }
    }
    if ($i >= $la && $j >= $lb) {
        return 0;
    }

    return $i >= $la ? -1 : 1;
}

/**
 * @return -1|0|1
 */
function st_vcmp_generic(string $a, string $b): int
{
    $a = trim($a);
    $b = trim($b);
    if ($a === $b) {
        return 0;
    }
    if (preg_match('/^\d+\.\d+/', $a) === 1 && preg_match('/^\d+\.\d+/', $b) === 1) {
        $va = @version_compare($a, $b);
        if ($va !== null && $va !== false) {
            return $va < 0 ? -1 : ($va > 0 ? 1 : 0);
        }
    }

    $c = strcmp($a, $b);

    return $c === 0 ? 0 : ($c < 0 ? -1 : 1);
}

/**
 * @return -1|0|1
 */
function st_vcmp_for_ecosystem(string $ecosystem, string $a, string $b): int
{
    $e = strtolower(trim($ecosystem));
    if ($e === 'dpkg' || $e === 'debian' || $e === 'ubuntu') {
        return st_vcmp_dpkg($a, $b);
    }
    if ($e === 'rpm' || $e === 'redhat' || $e === 'fedora') {
        return st_vcmp_rpm($a, $b);
    }

    return st_vcmp_generic($a, $b);
}

function st_vcmp_confidence_for_ecosystem(string $ecosystem): string
{
    $e = strtolower(trim($ecosystem));
    if ($e === 'dpkg' || $e === 'debian' || $e === 'ubuntu') {
        return 'high';
    }
    if ($e === 'rpm' || $e === 'redhat' || $e === 'fedora') {
        return 'medium';
    }

    return 'low';
}
