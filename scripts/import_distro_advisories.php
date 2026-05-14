<?php
/**
 * Ubuntu/Debian-style bounded advisory import (vendor package rules: fixed_version + distro_release).
 *
 * Usage: php scripts/import_distro_advisories.php /path/to/distro_advisories.json
 *
 * JSON shape:
 * {
 *   "distro_source": "ubuntu",
 *   "advisories": [
 *     {
 *       "cve_id": "CVE-2024-12345",
 *       "description": "optional",
 *       "severity": "high",
 *       "cvss_score": 7.5,
 *       "published_at": "...",
 *       "modified_at": "...",
 *       "distro_release": "jammy",
 *       "withdrawn": false,
 *       "packages": [
 *         {
 *           "binary_package": "openssl",
 *           "source_package": "openssl3",
 *           "fixed_version": "3.0.2-0ubuntu1.15",
 *           "status": "released"
 *         }
 *       ]
 *     }
 *   ]
 * }
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

require_once dirname(__DIR__) . '/api/db.php';
require_once dirname(__DIR__) . '/api/lib_vulnerability_correlation.php';
require_once dirname(__DIR__) . '/api/lib_vulnerability_advisory_import.php';

$maxAdvisories = 5000;
$maxBytes = 256 * 1024 * 1024;
$maxPackageRows = 250_000;

foreach (array_slice($argv, 1) as $_a) {
    if (str_starts_with($_a, '--max-advisories=')) {
        $maxAdvisories = max(1, min(100_000, (int) substr($_a, 17)));
    } elseif (str_starts_with($_a, '--max-size=')) {
        $mb = max(1, min(2048, (int) substr($_a, 11)));
        $maxBytes = $mb * 1024 * 1024;
    } elseif (str_starts_with($_a, '--max-package-rows=')) {
        $maxPackageRows = max(5_000, min(500_000, (int) substr($_a, strlen('--max-package-rows='))));
    } elseif ($_a === '--help' || $_a === '-h') {
        fwrite(STDOUT, "Usage: php scripts/import_distro_advisories.php /path/to/distro_advisories.json [--max-advisories=5000] [--max-size=256] [--max-package-rows=250000]\n");
        exit(0);
    }
}

$path = '';
foreach (array_slice($argv, 1) as $_a) {
    if (!str_starts_with($_a, '--')) {
        $path = $_a;
        break;
    }
}
if ($path === '' || ! is_readable($path)) {
    fwrite(STDERR, "Usage: php scripts/import_distro_advisories.php /path/to/distro_advisories.json [--max-advisories=5000]\n");
    exit(1);
}

$raw = @file_get_contents($path);
if ($raw === false || strlen($raw) > $maxBytes) {
    $limitMB = (int) round($maxBytes / 1024 / 1024);
    fwrite(STDERR, "File missing or larger than {$limitMB}MB (bounded import; use --max-size=N to raise).\n");
    exit(1);
}

$data = json_decode($raw, true);
if (! is_array($data) || ! isset($data['advisories']) || ! is_array($data['advisories'])) {
    fwrite(STDERR, "Invalid JSON: top-level advisories[] required.\n");
    exit(1);
}

$ds = isset($data['distro_source']) ? st_vuln_normalize_source((string) $data['distro_source']) : null;
if ($ds !== 'ubuntu' && $ds !== 'debian') {
    fwrite(STDERR, "distro_source must be ubuntu or debian.\n");
    exit(1);
}

$list = $data['advisories'];
if (count($list) > $maxAdvisories) {
    fwrite(STDERR, "Too many advisories in one file (max {$maxAdvisories}; use --max-advisories=N to raise).\n");
    exit(1);
}

$pdo = st_db();
if (! st_vuln_tables_ready($pdo)) {
    fwrite(STDERR, "Vulnerability tables not ready (migration pending?).\n");
    exit(1);
}

$flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
    $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
}

$selEx = $pdo->prepare('SELECT id, source, package_authority FROM vulnerability_advisories WHERE advisory_key = ? LIMIT 1');

$upAdv = $pdo->prepare(
    'INSERT INTO vulnerability_advisories (advisory_key, source, severity, cvss_score, description, references_json, package_authority, published_at, modified_at, withdrawn, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, datetime(\'now\'), datetime(\'now\'))
     ON CONFLICT(advisory_key) DO UPDATE SET
        source = CASE
            WHEN excluded.source IN (\'ubuntu\',\'debian\',\'redhat\',\'alpine\') THEN excluded.source
            WHEN vulnerability_advisories.source IN (\'ubuntu\',\'debian\',\'redhat\',\'alpine\') THEN vulnerability_advisories.source
            WHEN excluded.source IN (\'internal\',\'sample\') THEN excluded.source
            WHEN vulnerability_advisories.source IN (\'internal\',\'sample\') THEN vulnerability_advisories.source
            ELSE excluded.source
        END,
        severity = excluded.severity,
        cvss_score = excluded.cvss_score,
        description = CASE
            WHEN length(ifnull(excluded.description,\'\')) > length(ifnull(vulnerability_advisories.description,\'\')) THEN excluded.description
            ELSE vulnerability_advisories.description
        END,
        package_authority = CASE
            WHEN excluded.package_authority = \'vendor_distro\' OR ifnull(vulnerability_advisories.package_authority,\'internal\') = \'vendor_distro\' THEN \'vendor_distro\'
            WHEN excluded.package_authority = \'internal\' OR ifnull(vulnerability_advisories.package_authority,\'internal\') = \'internal\' THEN \'internal\'
            ELSE \'metadata_only\'
        END,
        published_at = excluded.published_at,
        modified_at = excluded.modified_at,
        withdrawn = excluded.withdrawn,
        updated_at = datetime(\'now\')'
);

$delPkgRelease = $pdo->prepare('DELETE FROM vulnerability_advisory_packages WHERE advisory_id = ? AND distro_release = ?');
$insPkg = $pdo->prepare(
    'INSERT INTO vulnerability_advisory_packages (advisory_id, ecosystem, normalized_name, version_operator, version_value, distro_release, architecture, fixed_version, metadata_json, created_at)
     VALUES (?, \'dpkg\', ?, \'=\', \'0\', ?, NULL, ?, ?, datetime(\'now\'))'
);

$ok = 0;
$rej = 0;
$pkgRows = 0;

try {
    $pdo->exec('BEGIN IMMEDIATE');
    foreach ($list as $rec) {
        if (! is_array($rec)) {
            ++$rej;
            continue;
        }
        $key = isset($rec['cve_id']) ? trim((string) $rec['cve_id']) : '';
        if ($key === '' && isset($rec['advisory_key'])) {
            $key = trim((string) $rec['advisory_key']);
        }
        if (! st_vuln_validate_advisory_key($key)) {
            ++$rej;
            continue;
        }
        $drAdv = isset($rec['distro_release']) ? trim((string) $rec['distro_release']) : '';
        if ($drAdv === '' || strlen($drAdv) > 120) {
            ++$rej;
            continue;
        }
        $sev = strtolower(trim((string) ($rec['severity'] ?? 'unknown')));
        if (! in_array($sev, st_vuln_allowed_severities(), true)) {
            $sev = 'unknown';
        }
        $cvss = null;
        if (array_key_exists('cvss_score', $rec) && $rec['cvss_score'] !== null && $rec['cvss_score'] !== '') {
            $cvss = (float) $rec['cvss_score'];
            if ($cvss < 0.0 || $cvss > 10.0) {
                $cvss = null;
            }
        }
        $desc = isset($rec['description']) ? substr(strip_tags((string) $rec['description']), 0, 16_000) : null;
        $pub = isset($rec['published_at']) ? substr(preg_replace('/[^0-9T:\\-\\.Z+]/', '', (string) $rec['published_at']), 0, 40) : null;
        $mod = isset($rec['modified_at']) ? substr(preg_replace('/[^0-9T:\\-\\.Z+]/', '', (string) $rec['modified_at']), 0, 40) : null;
        if ($mod === '') {
            $mod = null;
        }
        if ($pub === '') {
            $pub = null;
        }
        $wd = ! empty($rec['withdrawn']) ? 1 : 0;

        $pks = $rec['packages'] ?? [];
        if (! is_array($pks) || count($pks) === 0) {
            ++$rej;
            continue;
        }
        if (count($pks) > 200) {
            ++$rej;
            continue;
        }
        $validRows = [];
        foreach ($pks as $p) {
            if (! is_array($p)) {
                continue;
            }
            $bin = strtolower(trim((string) ($p['binary_package'] ?? '')));
            if ($bin === '') {
                $bin = strtolower(trim((string) ($p['normalized_name'] ?? '')));
            }
            $bin = preg_replace('/[^a-z0-9._+\\-]+/', '', $bin) ?? '';
            if ($bin === '' || strlen($bin) > 500) {
                continue;
            }
            $fv = isset($p['fixed_version']) ? substr(trim((string) $p['fixed_version']), 0, 500) : '';
            if ($fv === '') {
                continue;
            }
            $srcPkg = isset($p['source_package']) ? substr(trim((string) $p['source_package']), 0, 500) : '';
            $stPkg = isset($p['status']) ? substr(trim((string) $p['status']), 0, 120) : '';
            $meta = [
                'source_package' => $srcPkg !== '' ? $srcPkg : null,
                'status' => $stPkg !== '' ? $stPkg : null,
                'distro_source' => $ds,
            ];
            $mj = json_encode($meta, $flags) ?: '{}';
            if (strlen($mj) > 8000) {
                $mj = substr($mj, 0, 8000);
            }
            $validRows[] = ['bin' => $bin, 'fv' => $fv, 'mj' => $mj];
        }
        if ($validRows === []) {
            ++$rej;
            continue;
        }

        $incomingPa = st_vuln_incoming_package_authority($ds, count($validRows));
        $selEx->execute([$key]);
        $exRow = $selEx->fetch(PDO::FETCH_ASSOC);
        $mergedPa = is_array($exRow)
            ? st_vuln_package_authority_merge((string) ($exRow['package_authority'] ?? 'internal'), $incomingPa)
            : $incomingPa;
        $mergedSrc = is_array($exRow)
            ? st_vuln_advisory_source_prefer((string) ($exRow['source'] ?? ''), $ds)
            : $ds;

        $upAdv->execute([$key, $mergedSrc, $sev, $cvss, $desc, $mergedPa, $pub, $mod, $wd]);
        $idSt = $pdo->prepare('SELECT id FROM vulnerability_advisories WHERE advisory_key = ? LIMIT 1');
        $idSt->execute([$key]);
        $aid = (int) $idSt->fetchColumn();
        if ($aid < 1) {
            ++$rej;
            continue;
        }

        $delPkgRelease->execute([$aid, $drAdv]);
        foreach ($validRows as $vr) {
            $insPkg->execute([$aid, $vr['bin'], $drAdv, $vr['fv'], $vr['mj']]);
            ++$pkgRows;
        }
        ++$ok;
        if ($pkgRows > $maxPackageRows) {
            throw new RuntimeException('package_row_cap (raise with --max-package-rows=N)');
        }
    }
    $pdo->exec('COMMIT');
} catch (Throwable $e) {
    try {
        $pdo->exec('ROLLBACK');
    } catch (Throwable $e2) {
    }
    fwrite(STDERR, 'Import failed: ' . $e->getMessage() . "\n");
    exit(1);
}

echo "OK advisories_accepted={$ok} advisories_rejected={$rej} package_rules_written={$pkgRows}\n";
exit(0);
