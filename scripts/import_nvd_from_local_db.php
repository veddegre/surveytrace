<?php
/**
 * NVD metadata bridge: import CVE metadata from existing data/nvd.db into vulnerability_advisories.
 *
 * Reads the SQLite database produced by daemon/sync_nvd.py (CPE-based NVD sync) and writes
 * CVE metadata (key, severity, CVSS, description, published/modified) into the advisory model
 * as package_authority=metadata_only rows. This enriches the advisory model with NVD data
 * without asserting package-level affected state — vendor/internal rules remain the authority
 * for "which packages are affected."
 *
 * Usage:
 *   php scripts/import_nvd_from_local_db.php                   # dry-run, default path
 *   php scripts/import_nvd_from_local_db.php --apply           # write to surveytrace.db
 *   php scripts/import_nvd_from_local_db.php --apply --limit=500
 *   php scripts/import_nvd_from_local_db.php --apply --since=2026-01-01
 *   php scripts/import_nvd_from_local_db.php --nvd-db=/path/to/nvd.db --apply
 *
 * Options:
 *   --apply           Write changes (default is dry-run)
 *   --limit=N         Max CVEs to process per run (default 2000)
 *   --since=DATE      Only import CVEs modified on/after DATE (YYYY-MM-DD)
 *   --nvd-db=PATH     Path to nvd.db (default: data/nvd.db relative to project root)
 *   --incremental     Only process CVEs newer than last import (stored in config)
 *   --json            Output JSON summary instead of human-readable
 *
 * Guarantees:
 *   - Does NOT write vulnerability_advisory_packages rows
 *   - Does NOT create asset_vulnerabilities rows
 *   - package_authority always set to 'metadata_only' for new rows
 *   - Existing vendor_distro/internal authority is never downgraded
 *   - Bounded: respects --limit, transactions are batched
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

require_once dirname(__DIR__) . '/api/db.php';
require_once dirname(__DIR__) . '/api/lib_vulnerability_correlation.php';
require_once dirname(__DIR__) . '/api/lib_vulnerability_advisory_import.php';

// --- Arg parsing ---

$opt = [
    'apply'       => false,
    'limit'       => 2000,
    'since'       => null,
    'nvd_db'      => null,
    'incremental' => false,
    'json'        => false,
];

foreach (array_slice($argv, 1) as $a) {
    if ($a === '--apply') {
        $opt['apply'] = true;
    } elseif ($a === '--incremental') {
        $opt['incremental'] = true;
    } elseif ($a === '--json') {
        $opt['json'] = true;
    } elseif (str_starts_with($a, '--limit=')) {
        $opt['limit'] = max(1, min(50000, (int) substr($a, 8)));
    } elseif (str_starts_with($a, '--since=')) {
        $opt['since'] = substr($a, 8);
    } elseif (str_starts_with($a, '--nvd-db=')) {
        $opt['nvd_db'] = substr($a, 9);
    } elseif ($a === '--help' || $a === '-h') {
        fwrite(STDOUT, "Usage: php scripts/import_nvd_from_local_db.php [--apply] [--limit=N] [--since=YYYY-MM-DD] [--nvd-db=PATH] [--incremental] [--json]\n");
        exit(0);
    } else {
        fwrite(STDERR, "Unknown option: {$a}\n");
        exit(1);
    }
}

// --- Resolve nvd.db path ---

$nvdDbPath = $opt['nvd_db'];
if ($nvdDbPath === null) {
    $nvdDbPath = (defined('ST_DATA_DIR') ? ST_DATA_DIR : dirname(__DIR__) . '/data') . '/nvd.db';
}

if (!is_file($nvdDbPath) || !is_readable($nvdDbPath)) {
    $msg = "NVD database not found or not readable: {$nvdDbPath}";
    if ($opt['json']) {
        echo json_encode(['ok' => false, 'error' => $msg], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n";
    } else {
        fwrite(STDERR, "{$msg}\n");
        fwrite(STDERR, "Hint: Run daemon/sync_nvd.py first to populate the NVD database.\n");
    }
    exit(1);
}

// --- Open NVD database (read-only) ---

try {
    $nvd = new PDO("sqlite:{$nvdDbPath}", null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $nvd->exec("PRAGMA query_only = ON");
} catch (Throwable $e) {
    $msg = "Cannot open NVD database: " . $e->getMessage();
    if ($opt['json']) {
        echo json_encode(['ok' => false, 'error' => $msg]) . "\n";
    } else {
        fwrite(STDERR, "{$msg}\n");
    }
    exit(1);
}

// Validate expected schema
try {
    $nvd->query("SELECT cve_id, cvss, severity, description, published, modified FROM cves LIMIT 0");
} catch (Throwable $e) {
    $msg = "NVD database schema mismatch (expected cves table with cve_id, cvss, severity, description, published, modified): " . $e->getMessage();
    if ($opt['json']) {
        echo json_encode(['ok' => false, 'error' => $msg]) . "\n";
    } else {
        fwrite(STDERR, "{$msg}\n");
    }
    exit(1);
}

// --- Open main surveytrace.db ---

$pdo = st_db();
if (!st_vuln_tables_ready($pdo)) {
    $msg = "Vulnerability tables not ready (migration pending?).";
    if ($opt['json']) {
        echo json_encode(['ok' => false, 'error' => $msg]) . "\n";
    } else {
        fwrite(STDERR, "{$msg}\n");
    }
    exit(1);
}

// --- Determine --since threshold ---

$sinceDate = $opt['since'];

if ($sinceDate === null && $opt['incremental']) {
    try {
        $lastRun = $pdo->query(
            "SELECT value FROM st_config WHERE key = 'nvd_bridge_last_modified_at' LIMIT 1"
        )->fetchColumn();
        if ($lastRun && strlen($lastRun) >= 10) {
            $sinceDate = substr($lastRun, 0, 10);
        }
    } catch (Throwable $e) {
        // st_config may not exist; ignore
    }
}

// --- Query NVD CVEs ---

$sql = "SELECT cve_id, cvss, severity, description, published, modified FROM cves";
$params = [];
if ($sinceDate !== null && preg_match('/^\d{4}-\d{2}-\d{2}$/', $sinceDate)) {
    $sql .= " WHERE modified >= ?";
    $params[] = $sinceDate;
}
$sql .= " ORDER BY modified DESC LIMIT " . (int) $opt['limit'];

$stmt = $nvd->prepare($sql);
$stmt->execute($params);
$cves = $stmt->fetchAll();

$totalInNvd = (int) $nvd->query("SELECT COUNT(*) FROM cves")->fetchColumn();

// --- Diagnostics ---

$stats = [
    'nvd_db_path'       => $nvdDbPath,
    'nvd_db_cve_count'  => $totalInNvd,
    'queried'           => count($cves),
    'since_filter'      => $sinceDate,
    'limit'             => $opt['limit'],
    'dry_run'           => !$opt['apply'],
    'imported'          => 0,
    'updated'           => 0,
    'skipped'           => 0,
    'rejected'          => 0,
    'max_modified_at'   => null,
];

if (count($cves) === 0) {
    $stats['note'] = $sinceDate
        ? "No CVEs modified since {$sinceDate} in NVD database."
        : "NVD database is empty.";
    if ($opt['json']) {
        echo json_encode(['ok' => true] + $stats, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n";
    } else {
        echo "OK No CVEs to import (nvd_db_count={$totalInNvd}, since={$sinceDate}).\n";
    }
    exit(0);
}

// --- Upsert prepared statement ---

$upsert = $pdo->prepare(
    "INSERT INTO vulnerability_advisories
        (advisory_key, source, severity, cvss_score, description, references_json, package_authority, published_at, modified_at, withdrawn, created_at, updated_at)
     VALUES (?, 'nvd', ?, ?, ?, NULL, 'metadata_only', ?, ?, 0, datetime('now'), datetime('now'))
     ON CONFLICT(advisory_key) DO UPDATE SET
        severity = CASE
            WHEN excluded.severity IS NOT NULL AND excluded.severity != 'unknown' THEN excluded.severity
            ELSE vulnerability_advisories.severity
        END,
        cvss_score = CASE
            WHEN excluded.cvss_score IS NOT NULL AND excluded.cvss_score > 0 THEN excluded.cvss_score
            ELSE vulnerability_advisories.cvss_score
        END,
        description = CASE
            WHEN length(ifnull(excluded.description,'')) > length(ifnull(vulnerability_advisories.description,'')) THEN excluded.description
            ELSE vulnerability_advisories.description
        END,
        package_authority = CASE
            WHEN vulnerability_advisories.package_authority = 'vendor_distro' THEN 'vendor_distro'
            WHEN vulnerability_advisories.package_authority = 'internal' THEN 'internal'
            ELSE 'metadata_only'
        END,
        source = CASE
            WHEN vulnerability_advisories.source IN ('ubuntu','debian','redhat','alpine') THEN vulnerability_advisories.source
            WHEN vulnerability_advisories.source IN ('internal','sample') THEN vulnerability_advisories.source
            ELSE 'nvd'
        END,
        published_at = CASE
            WHEN excluded.published_at IS NOT NULL THEN excluded.published_at
            ELSE vulnerability_advisories.published_at
        END,
        modified_at = CASE
            WHEN excluded.modified_at IS NOT NULL THEN excluded.modified_at
            ELSE vulnerability_advisories.modified_at
        END,
        updated_at = datetime('now')"
);

$selExisting = $pdo->prepare("SELECT id FROM vulnerability_advisories WHERE advisory_key = ? LIMIT 1");

// --- Process in bounded batches ---

$batchSize = 200;
$maxModified = null;

if ($opt['apply']) {
    $pdo->exec('BEGIN IMMEDIATE');
}

foreach ($cves as $row) {
    $cveId = trim((string) ($row['cve_id'] ?? ''));
    if (!preg_match('/^CVE-\d{4}-\d{4,}$/i', $cveId)) {
        $stats['rejected']++;
        continue;
    }

    $severity = strtolower(trim((string) ($row['severity'] ?? 'unknown')));
    $allowed = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
    if (!in_array($severity, $allowed, true)) {
        $severity = 'unknown';
    }

    $cvss = ($row['cvss'] !== null && $row['cvss'] !== '') ? (float) $row['cvss'] : null;
    if ($cvss !== null && ($cvss < 0.0 || $cvss > 10.0)) {
        $cvss = null;
    }

    $desc = ($row['description'] !== null && $row['description'] !== '')
        ? substr(strip_tags((string) $row['description']), 0, 16_000)
        : null;

    $published = ($row['published'] !== null && strlen((string) $row['published']) >= 10)
        ? substr((string) $row['published'], 0, 40)
        : null;
    $modified = ($row['modified'] !== null && strlen((string) $row['modified']) >= 10)
        ? substr((string) $row['modified'], 0, 40)
        : null;

    if ($modified !== null && ($maxModified === null || $modified > $maxModified)) {
        $maxModified = $modified;
    }

    if ($opt['apply']) {
        $selExisting->execute([$cveId]);
        $existed = $selExisting->fetchColumn();

        $upsert->execute([$cveId, $severity, $cvss, $desc, $published, $modified]);

        if ($existed) {
            $stats['updated']++;
        } else {
            $stats['imported']++;
        }
    } else {
        $selExisting->execute([$cveId]);
        $existed = $selExisting->fetchColumn();
        if ($existed) {
            $stats['updated']++;
        } else {
            $stats['imported']++;
        }
    }

    if (($stats['imported'] + $stats['updated'] + $stats['skipped']) % $batchSize === 0 && $opt['apply']) {
        $pdo->exec('COMMIT');
        $pdo->exec('BEGIN IMMEDIATE');
    }
}

if ($opt['apply']) {
    $pdo->exec('COMMIT');

    // Store last-modified watermark for --incremental
    if ($maxModified !== null) {
        try {
            $pdo->exec("CREATE TABLE IF NOT EXISTS st_config (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)");
            $pdo->prepare(
                "INSERT INTO st_config (key, value, updated_at) VALUES ('nvd_bridge_last_modified_at', ?, datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')"
            )->execute([$maxModified]);
        } catch (Throwable $e) {
            // Non-critical; log but don't fail
            fwrite(STDERR, "Warning: could not store incremental watermark: " . $e->getMessage() . "\n");
        }
    }
}

$stats['max_modified_at'] = $maxModified;

// --- Output ---

if ($opt['json']) {
    echo json_encode(['ok' => true] + $stats, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n";
} else {
    $mode = $opt['apply'] ? 'APPLIED' : 'DRY-RUN';
    echo "[{$mode}] NVD bridge: imported={$stats['imported']} updated={$stats['updated']} skipped={$stats['skipped']} rejected={$stats['rejected']} (nvd_db_cves={$totalInNvd}, queried={$stats['queried']})\n";
    if (!$opt['apply']) {
        echo "  → No changes written. Use --apply to commit.\n";
    }
    if ($maxModified) {
        echo "  → Latest modified_at: {$maxModified}\n";
    }
}

exit(0);
