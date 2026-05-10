<?php
/**
 * Local advisory JSON import (transactional, bounded, upsert-safe).
 *
 * Usage: php scripts/import_advisories.php /path/to/advisories.json
 *
 * JSON shape:
 * {
 *   "advisories": [
 *     {
 *       "advisory_key": "CVE-2024-12345",
 *       "source": "nvd",
 *       "severity": "high",
 *       "cvss_score": 7.5,
 *       "description": "text",
 *       "published_at": "2024-01-01T00:00:00Z",
 *       "modified_at": "2024-01-02T00:00:00Z",
 *       "withdrawn": false,
 *       "packages": [
 *         {
 *           "ecosystem": "dpkg",
 *           "normalized_name": "openssl",
 *           "version_operator": "<",
 *           "version_value": "3.0.12-1",
 *           "fixed_version": "3.0.12-1",
 *           "distro_release": null,
 *           "architecture": null,
 *           "metadata_json": {}
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

$path = $argv[1] ?? '';
if ($path === '' || ! is_readable($path)) {
    fwrite(STDERR, "Usage: php scripts/import_advisories.php /path/to/advisories.json\n");
    exit(1);
}

$maxBytes = 2 * 1024 * 1024;
$raw = @file_get_contents($path);
if ($raw === false || strlen($raw) > $maxBytes) {
    fwrite(STDERR, "File missing or larger than 2MB (bounded import).\n");
    exit(1);
}

$data = json_decode($raw, true);
if (! is_array($data) || ! isset($data['advisories']) || ! is_array($data['advisories'])) {
    fwrite(STDERR, "Invalid JSON: top-level advisories[] required.\n");
    exit(1);
}

$list = $data['advisories'];
if (count($list) > 500) {
    fwrite(STDERR, "Too many advisories in one file (max 500).\n");
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

$ok = 0;
$rej = 0;
$pkgRows = 0;

$upAdv = $pdo->prepare(
    'INSERT INTO vulnerability_advisories (advisory_key, source, severity, cvss_score, description, published_at, modified_at, withdrawn, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime(\'now\'), datetime(\'now\'))
     ON CONFLICT(advisory_key) DO UPDATE SET
        source = excluded.source,
        severity = excluded.severity,
        cvss_score = excluded.cvss_score,
        description = excluded.description,
        published_at = excluded.published_at,
        modified_at = excluded.modified_at,
        withdrawn = excluded.withdrawn,
        updated_at = datetime(\'now\')'
);

$delPkg = $pdo->prepare('DELETE FROM vulnerability_advisory_packages WHERE advisory_id = ?');
$insPkg = $pdo->prepare(
    'INSERT INTO vulnerability_advisory_packages (advisory_id, ecosystem, normalized_name, version_operator, version_value, distro_release, architecture, fixed_version, metadata_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime(\'now\'))'
);

try {
    $pdo->exec('BEGIN IMMEDIATE');
    foreach ($list as $rec) {
        if (! is_array($rec)) {
            ++$rej;
            continue;
        }
        $key = isset($rec['advisory_key']) ? trim((string) $rec['advisory_key']) : '';
        if (! st_vuln_validate_advisory_key($key)) {
            ++$rej;
            continue;
        }
        $src = isset($rec['source']) ? st_vuln_normalize_source((string) $rec['source']) : null;
        if ($src === null) {
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

        $upAdv->execute([$key, $src, $sev, $cvss, $desc, $pub, $mod, $wd]);
        $idSt = $pdo->prepare('SELECT id FROM vulnerability_advisories WHERE advisory_key = ? LIMIT 1');
        $idSt->execute([$key]);
        $aid = (int) $idSt->fetchColumn();
        if ($aid < 1) {
            ++$rej;
            continue;
        }

        $delPkg->execute([$aid]);
        $pks = $rec['packages'] ?? [];
        if (! is_array($pks)) {
            $pks = [];
        }
        if (count($pks) > 200) {
            ++$rej;
            continue;
        }
        foreach ($pks as $p) {
            if (! is_array($p)) {
                continue;
            }
            $eco = strtolower(trim((string) ($p['ecosystem'] ?? '')));
            if (! in_array($eco, ['dpkg', 'rpm', 'generic'], true)) {
                continue;
            }
            $nn = strtolower(trim((string) ($p['normalized_name'] ?? '')));
            $nn = preg_replace('/[^a-z0-9._+\\-]+/', '', $nn) ?? '';
            if ($nn === '' || strlen($nn) > 500) {
                continue;
            }
            $op = st_vuln_normalize_operator((string) ($p['version_operator'] ?? ''));
            if ($op === null) {
                continue;
            }
            $vv = substr(trim((string) ($p['version_value'] ?? '')), 0, 500);
            if ($vv === '') {
                continue;
            }
            $fv = isset($p['fixed_version']) ? substr(trim((string) $p['fixed_version']), 0, 500) : '';
            $fv = $fv === '' ? null : $fv;
            $dr = isset($p['distro_release']) ? substr(trim((string) $p['distro_release']), 0, 120) : null;
            $dr = $dr === '' ? null : $dr;
            $ar = isset($p['architecture']) ? substr(trim((string) $p['architecture']), 0, 64) : null;
            $ar = $ar === '' ? null : $ar;
            $meta = $p['metadata_json'] ?? [];
            $mj = is_array($meta) ? (json_encode($meta, $flags) ?: null) : null;
            if ($mj !== null && strlen($mj) > 8000) {
                $mj = substr($mj, 0, 8000);
            }
            $insPkg->execute([$aid, $eco, $nn, $op, $vv, $dr, $ar, $fv, $mj]);
            ++$pkgRows;
        }
        ++$ok;
        if ($pkgRows > 20_000) {
            throw new RuntimeException('package_row_cap');
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
