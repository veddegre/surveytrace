<?php
/**
 * Bounded NVD-style CVE metadata import (no package rules; does not claim distro package truth).
 *
 * Usage: php scripts/import_nvd_metadata.php /path/to/nvd_metadata.json
 *
 * JSON shape:
 * {
 *   "vulnerabilities": [
 *     {
 *       "cve_id": "CVE-2024-12345",
 *       "severity": "high",
 *       "cvss_score": 7.5,
 *       "description": "...",
 *       "published_at": "2024-01-01T00:00:00Z",
 *       "modified_at": "2024-01-02T00:00:00Z",
 *       "references": [ {"url": "https://nvd.nist.gov/..."} ],
 *       "withdrawn": false
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

$path = $argv[1] ?? '';
if ($path === '' || ! is_readable($path)) {
    fwrite(STDERR, "Usage: php scripts/import_nvd_metadata.php /path/to/nvd_metadata.json\n");
    exit(1);
}

$maxBytes = 2 * 1024 * 1024;
$raw = @file_get_contents($path);
if ($raw === false || strlen($raw) > $maxBytes) {
    fwrite(STDERR, "File missing or larger than 2MB (bounded import).\n");
    exit(1);
}

$data = json_decode($raw, true);
if (! is_array($data) || ! isset($data['vulnerabilities']) || ! is_array($data['vulnerabilities'])) {
    fwrite(STDERR, "Invalid JSON: top-level vulnerabilities[] required.\n");
    exit(1);
}

$list = $data['vulnerabilities'];
if (count($list) > 500) {
    fwrite(STDERR, "Too many records in one file (max 500).\n");
    exit(1);
}

$pdo = st_db();
if (! st_vuln_tables_ready($pdo)) {
    fwrite(STDERR, "Vulnerability tables not ready (migration pending?).\n");
    exit(1);
}

$up = $pdo->prepare(
    'INSERT INTO vulnerability_advisories (advisory_key, source, severity, cvss_score, description, references_json, package_authority, published_at, modified_at, withdrawn, created_at, updated_at)
     VALUES (?, \'nvd\', ?, ?, ?, ?, \'metadata_only\', ?, ?, ?, datetime(\'now\'), datetime(\'now\'))
     ON CONFLICT(advisory_key) DO UPDATE SET
        source = CASE
            WHEN vulnerability_advisories.source IN (\'ubuntu\',\'debian\',\'redhat\',\'alpine\') THEN vulnerability_advisories.source
            WHEN excluded.source IN (\'ubuntu\',\'debian\',\'redhat\',\'alpine\') THEN excluded.source
            WHEN vulnerability_advisories.source IN (\'internal\',\'sample\') THEN vulnerability_advisories.source
            WHEN excluded.source IN (\'internal\',\'sample\') THEN excluded.source
            ELSE \'nvd\'
        END,
        severity = excluded.severity,
        cvss_score = excluded.cvss_score,
        description = CASE
            WHEN length(ifnull(excluded.description,\'\')) > length(ifnull(vulnerability_advisories.description,\'\')) THEN excluded.description
            ELSE vulnerability_advisories.description
        END,
        references_json = CASE
            WHEN excluded.references_json IS NOT NULL AND length(trim(excluded.references_json)) > 0 THEN excluded.references_json
            ELSE vulnerability_advisories.references_json
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

$ok = 0;
$rej = 0;

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
        $refsJson = st_vuln_encode_references_json($rec['references'] ?? null);
        $up->execute([$key, $sev, $cvss, $desc, $refsJson, $pub, $mod, $wd]);
        ++$ok;
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

echo "OK nvd_metadata_accepted={$ok} nvd_metadata_rejected={$rej} (package rules untouched)\n";
exit(0);
