<?php
/**
 * Ubuntu advisory → import_distro_advisories.php JSON (pure transforms; no I/O).
 */

declare(strict_types=1);

/** @return list<string> */
function st_ubuntu_allowed_releases(): array
{
    return ['noble', 'resolute', 'jammy', 'focal', 'bionic', 'mantic', 'lunar', 'kinetic', 'impish', 'hirsute', 'groovy', 'eoan', 'disco', 'cosmic', 'artful', 'xenial', 'trusty'];
}

function st_ubuntu_validate_release(string $r): bool
{
    $r = strtolower(trim($r));

    return in_array($r, st_ubuntu_allowed_releases(), true);
}

function st_ubuntu_strip_html(string $s, int $maxLen = 16_000): string
{
    $s = strip_tags($s);
    $s = preg_replace('/\s+/u', ' ', $s) ?? $s;

    return strlen($s) > $maxLen ? substr($s, 0, $maxLen) : $s;
}

/**
 * Bound and normalize references for import_distro_advisories (stored in advisory row if importer extended — currently importer sets references NULL; still useful in output for future / manual merge).
 *
 * @param mixed $refs
 * @return list<array{url: string}>
 */
function st_ubuntu_bound_references($refs, int $maxRefs = 24, int $maxUrl = 2000): array
{
    if (! is_array($refs)) {
        return [];
    }
    $out = [];
    foreach ($refs as $row) {
        if (count($out) >= $maxRefs) {
            break;
        }
        if (! is_array($row)) {
            continue;
        }
        $u = isset($row['url']) ? trim((string) $row['url']) : '';
        if ($u === '' || ! str_starts_with($u, 'http')) {
            continue;
        }
        if (strlen($u) > $maxUrl) {
            $u = substr($u, 0, $maxUrl);
        }
        $out[] = ['url' => $u];
    }

    return $out;
}

/**
 * @param array<string, mixed> $pkg
 * @return array{binary_package: string, source_package: string, fixed_version: string, status: string}|null
 */
function st_ubuntu_normalize_package_row(array $pkg): ?array
{
    $bin = strtolower(trim((string) ($pkg['binary_package'] ?? $pkg['binary'] ?? $pkg['name'] ?? '')));
    $bin = preg_replace('/[^a-z0-9._+\\-]+/', '', $bin) ?? '';
    if ($bin === '' || strlen($bin) > 500) {
        return null;
    }
    $fv = isset($pkg['fixed_version']) ? trim((string) $pkg['fixed_version']) : '';
    if ($fv === '') {
        return null;
    }
    if (strlen($fv) > 500) {
        $fv = substr($fv, 0, 500);
    }
    $src = isset($pkg['source_package']) ? trim((string) $pkg['source_package']) : '';
    if (strlen($src) > 500) {
        $src = substr($src, 0, 500);
    }
    $st = strtolower(trim((string) ($pkg['status'] ?? 'released')));
    if (! in_array($st, ['released', 'needed', 'not-affected', 'deferred', 'ignored', 'pending'], true)) {
        $st = 'released';
    }

    return [
        'binary_package' => $bin,
        'source_package' => $src,
        'fixed_version' => $fv,
        'status' => $st,
    ];
}

/**
 * surveytrace_ubuntu_intermediate_v1 → distro_advisories import shape.
 *
 * @param array<string, mixed> $doc
 * @return array{distro_source: string, advisories: list<array<string, mixed>>}
 */
function st_ubuntu_intermediate_v1_to_import(array $doc): array
{
    $globalRel = isset($doc['distro_release']) ? strtolower(trim((string) $doc['distro_release'])) : '';
    $cves = $doc['cves'] ?? null;
    if (! is_array($cves)) {
        return ['distro_source' => 'ubuntu', 'advisories' => []];
    }
    $out = [];
    foreach ($cves as $rec) {
        if (! is_array($rec)) {
            continue;
        }
        $key = trim((string) ($rec['cve_id'] ?? $rec['advisory_key'] ?? ''));
        if (! preg_match('/^CVE-\d{4}-\d{4,12}$/i', $key)) {
            continue;
        }
        $dr = isset($rec['distro_release']) ? strtolower(trim((string) $rec['distro_release'])) : $globalRel;
        if ($dr === '' || ! st_ubuntu_validate_release($dr)) {
            continue;
        }
        $pks = $rec['packages'] ?? [];
        if (! is_array($pks)) {
            continue;
        }
        $normPkgs = [];
        foreach ($pks as $p) {
            if (! is_array($p)) {
                continue;
            }
            if (count($normPkgs) >= 200) {
                break;
            }
            $np = st_ubuntu_normalize_package_row($p);
            if ($np === null) {
                continue;
            }
            if (($np['status'] ?? '') !== 'released') {
                continue;
            }
            $normPkgs[] = $np;
        }
        if ($normPkgs === []) {
            continue;
        }
        $sev = strtolower(trim((string) ($rec['severity'] ?? 'unknown')));
        $cvss = null;
        if (isset($rec['cvss_score']) && $rec['cvss_score'] !== null && $rec['cvss_score'] !== '') {
            $cvss = (float) $rec['cvss_score'];
            if ($cvss < 0.0 || $cvss > 10.0) {
                $cvss = null;
            }
        }
        $desc = isset($rec['description']) ? st_ubuntu_strip_html((string) $rec['description']) : null;
        $pub = isset($rec['published_at']) ? substr(preg_replace('/[^0-9T:\\-\\.Z+ ]/', '', (string) $rec['published_at']), 0, 40) : null;
        $mod = isset($rec['modified_at']) ? substr(preg_replace('/[^0-9T:\\-\\.Z+ ]/', '', (string) $rec['modified_at']), 0, 40) : null;
        if ($pub === '') {
            $pub = null;
        }
        if ($mod === '') {
            $mod = null;
        }
        $refs = st_ubuntu_bound_references($rec['references'] ?? []);
        $adv = [
            'cve_id' => $key,
            'description' => $desc,
            'severity' => $sev,
            'cvss_score' => $cvss,
            'published_at' => $pub,
            'modified_at' => $mod,
            'distro_release' => $dr,
            'withdrawn' => ! empty($rec['withdrawn']),
            'packages' => $normPkgs,
        ];
        if ($refs !== []) {
            $adv['references'] = $refs;
        }
        $out[] = $adv;
    }

    return ['distro_source' => 'ubuntu', 'advisories' => $out];
}

/**
 * Validate / filter existing import_distro_advisories JSON.
 *
 * @param array<string, mixed> $doc
 * @return array{distro_source: string, advisories: list<array<string, mixed>>}
 */
function st_ubuntu_normalize_pass_through(array $doc, ?string $releaseFilter, int $limit): array
{
    $ds = strtolower(trim((string) ($doc['distro_source'] ?? '')));
    if ($ds !== 'ubuntu' && $ds !== 'debian') {
        return ['distro_source' => 'ubuntu', 'advisories' => []];
    }
    $list = $doc['advisories'] ?? [];
    if (! is_array($list)) {
        return ['distro_source' => $ds, 'advisories' => []];
    }
    $out = [];
    foreach ($list as $rec) {
        if (count($out) >= $limit) {
            break;
        }
        if (! is_array($rec)) {
            continue;
        }
        $dr = isset($rec['distro_release']) ? strtolower(trim((string) $rec['distro_release'])) : '';
        if ($releaseFilter !== null && $releaseFilter !== '' && strcasecmp($dr, $releaseFilter) !== 0) {
            continue;
        }
        $pks = $rec['packages'] ?? [];
        if (! is_array($pks)) {
            continue;
        }
        $normPkgs = [];
        foreach ($pks as $p) {
            if (! is_array($p)) {
                continue;
            }
            if (count($normPkgs) >= 200) {
                break;
            }
            $np = st_ubuntu_normalize_package_row($p);
            if ($np === null) {
                continue;
            }
            if (($np['status'] ?? '') !== 'released') {
                continue;
            }
            $normPkgs[] = $np;
        }
        if ($normPkgs === []) {
            continue;
        }
        $key = trim((string) ($rec['cve_id'] ?? $rec['advisory_key'] ?? ''));
        if (! preg_match('/^CVE-\d{4}-\d{4,12}$/i', $key)) {
            continue;
        }
        $adv = $rec;
        $adv['cve_id'] = $key;
        $adv['packages'] = $normPkgs;
        $adv['description'] = isset($rec['description']) ? st_ubuntu_strip_html((string) $rec['description']) : null;
        if (isset($adv['references'])) {
            $adv['references'] = st_ubuntu_bound_references($adv['references']);
        }
        $out[] = $adv;
    }

    return ['distro_source' => $ds, 'advisories' => $out];
}
