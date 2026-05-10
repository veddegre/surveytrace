<?php
/**
 * Safe advisory removal for test / internal advisories (CLI; dry-run default).
 *
 * Hard-deletes the advisory row; SQLite FK cascades remove correlated asset_vulnerabilities,
 * triage, notes, and activity for those rows. Intended for CVE-TEST-* and internal/sample
 * cleanup only — not for production vendor feeds unless --force is explicitly used.
 *
 * Usage:
 *   php scripts/remove_advisory.php --advisory-key=CVE-TEST-0001 [--source=internal] [--db=...]
 *   php scripts/remove_advisory.php --advisory-key=CVE-TEST-0001 --apply [--source=internal]
 *
 * Options:
 *   --advisory-key=KEY   (required) non-empty canonical advisory key
 *   --source=SRC         optional guard: refuse if DB row source differs
 *   --apply              perform delete (default is dry-run)
 *   --force              allow removing vendor_distro / non-test advisories (dangerous)
 *   --db=PATH            sqlite path (default: data/surveytrace.db or st_db())
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

require_once dirname(__DIR__) . '/api/db.php';
require_once dirname(__DIR__) . '/api/lib_vulnerability_correlation.php';
require_once dirname(__DIR__) . '/api/lib_vulnerability_advisory_import.php';

/**
 * @param list<string> $argv
 * @return array{apply: bool, force: bool, advisory_key: string, source_guard: ?string, db_path: ?string}
 */
function st_remove_advisory_parse_args(array $argv): array
{
    $out = [
        'apply' => false,
        'force' => false,
        'advisory_key' => '',
        'source_guard' => null,
        'db_path' => null,
    ];
    $rest = [];
    foreach (array_slice($argv, 1) as $arg) {
        if ($arg === '-h' || $arg === '--help') {
            fwrite(STDOUT, "Usage: php scripts/remove_advisory.php --advisory-key=KEY [--source=internal] [--apply] [--force] [--db=PATH]\n" .
                "Dry-run (default) prints JSON counts only; --apply deletes the advisory row (cascades packages + asset_vulnerabilities + triage/notes/activity).\n");
            exit(0);
        }
        if ($arg === '--apply') {
            $out['apply'] = true;
            continue;
        }
        if ($arg === '--force') {
            $out['force'] = true;
            continue;
        }
        if (str_starts_with($arg, '--advisory-key=')) {
            $out['advisory_key'] = trim((string) substr($arg, 15));
            continue;
        }
        if (str_starts_with($arg, '--source=')) {
            $g = trim((string) substr($arg, 9));
            $out['source_guard'] = $g === '' ? null : $g;
            continue;
        }
        if (str_starts_with($arg, '--db=')) {
            $out['db_path'] = (string) substr($arg, 5);
            continue;
        }
        $rest[] = $arg;
    }
    // --advisory-key VALUE (two-token form)
    for ($i = 0; $i < count($rest); ++$i) {
        if ($rest[$i] === '--advisory-key' && isset($rest[$i + 1])) {
            $out['advisory_key'] = trim((string) $rest[$i + 1]);
            ++$i;
            continue;
        }
        if ($rest[$i] === '--source' && isset($rest[$i + 1])) {
            $g = trim((string) $rest[$i + 1]);
            $out['source_guard'] = $g === '' ? null : $g;
            ++$i;
        }
    }

    return $out;
}

/** @param array<string, mixed> $counts */
function st_remove_advisory_emit_json(array $counts): void
{
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    fwrite(STDOUT, (json_encode($counts, $flags) ?: '{}') . "\n");
}

$args = st_remove_advisory_parse_args($argv);
$key = trim($args['advisory_key']);
if ($key === '') {
    st_remove_advisory_emit_json(['error' => 'advisory_key_required', 'hint' => 'Use --advisory-key=CVE-TEST-0001']);
    exit(2);
}
if (! st_vuln_validate_advisory_key($key)) {
    st_remove_advisory_emit_json(['error' => 'advisory_key_invalid']);
    exit(2);
}

$srcGuard = $args['source_guard'];
if ($srcGuard !== null) {
    $norm = st_vuln_normalize_source($srcGuard);
    if ($norm === null) {
        st_remove_advisory_emit_json(['error' => 'source_invalid', 'source' => $srcGuard]);
        exit(2);
    }
    $srcGuard = $norm;
}

$dbPath = $args['db_path'];
$explicitDb = $dbPath !== null && $dbPath !== '';
if ($explicitDb) {
    if ($dbPath === '' || ! is_file($dbPath)) {
        st_remove_advisory_emit_json(['error' => 'db_not_found', 'db' => $dbPath]);
        exit(1);
    }
    $pdo = new PDO('sqlite:' . $dbPath, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    $pdo->exec('PRAGMA foreign_keys=ON');
} else {
    $pdo = st_db();
}

if (! st_vuln_tables_ready($pdo)) {
    st_remove_advisory_emit_json(['error' => 'vulnerability_tables_missing']);
    exit(1);
}

$st0 = $pdo->prepare(
    'SELECT id, advisory_key, source, IFNULL(package_authority, \'internal\') AS package_authority
     FROM vulnerability_advisories WHERE advisory_key = ? LIMIT 1'
);
$st0->execute([$key]);
$row = $st0->fetch(PDO::FETCH_ASSOC);
if (! is_array($row)) {
    st_remove_advisory_emit_json([
        'error' => 'not_found',
        'advisory_key' => $key,
        'source_guard' => $srcGuard,
    ]);
    exit(2);
}
if ($srcGuard !== null && strcasecmp((string) ($row['source'] ?? ''), $srcGuard) !== 0) {
    st_remove_advisory_emit_json([
        'error' => 'source_mismatch',
        'advisory_key' => $key,
        'expected_source' => $srcGuard,
        'actual_source' => $row['source'] ?? '',
    ]);
    exit(2);
}

$aid = (int) ($row['id'] ?? 0);
if ($aid < 1) {
    st_remove_advisory_emit_json(['error' => 'invalid_advisory_id']);
    exit(2);
}

$refused = st_vuln_advisory_removal_refused_reason($row, $args['force']);
if ($refused !== null) {
    st_remove_advisory_emit_json([
        'error' => 'refused',
        'reason' => $refused,
        'advisory_id' => $aid,
        'advisory_key' => $row['advisory_key'],
        'source' => $row['source'],
        'package_authority' => $row['package_authority'],
        'hint' => 'Use --force only after operator review (removes row and cascades triage/notes/activity for matched assets).',
    ]);
    exit(2);
}

$stc = $pdo->prepare('SELECT COUNT(*) FROM vulnerability_advisory_packages WHERE advisory_id = ?');
$stc->execute([$aid]);
$pkg = (int) $stc->fetchColumn();

$stAv = $pdo->prepare('SELECT status, COUNT(*) AS c FROM asset_vulnerabilities WHERE advisory_id = ? GROUP BY status');
$stAv->execute([$aid]);
$avByStatus = [];
foreach ($stAv->fetchAll(PDO::FETCH_ASSOC) ?: [] as $r) {
    if (is_array($r)) {
        $avByStatus[(string) ($r['status'] ?? '')] = (int) ($r['c'] ?? 0);
    }
}
$stIds = $pdo->prepare('SELECT id FROM asset_vulnerabilities WHERE advisory_id = ?');
$stIds->execute([$aid]);
$avIds = $stIds->fetchAll(PDO::FETCH_COLUMN, 0) ?: [];
$avIds = array_values(array_filter(array_map(static fn ($x) => (int) $x, $avIds), static fn ($x) => $x > 0));
$avTotal = count($avIds);

$notes = 0;
$triage = 0;
$activity = 0;
if ($avIds !== []) {
    $ph = implode(',', array_fill(0, count($avIds), '?'));
    $stN = $pdo->prepare("SELECT COUNT(*) FROM vulnerability_notes WHERE asset_vulnerability_id IN ($ph)");
    $stN->execute($avIds);
    $notes = (int) $stN->fetchColumn();
    $stT = $pdo->prepare("SELECT COUNT(*) FROM asset_vulnerability_triage WHERE asset_vulnerability_id IN ($ph)");
    $stT->execute($avIds);
    $triage = (int) $stT->fetchColumn();
    $stA = $pdo->prepare("SELECT COUNT(*) FROM vulnerability_activity_log WHERE asset_vulnerability_id IN ($ph)");
    $stA->execute($avIds);
    $activity = (int) $stA->fetchColumn();
}

$counts = [
    'dry_run' => ! $args['apply'],
    'advisory_id' => $aid,
    'advisory_key' => $row['advisory_key'],
    'source' => $row['source'],
    'package_authority' => $row['package_authority'],
    'package_rules' => $pkg,
    'asset_vulnerabilities_by_status' => $avByStatus,
    'asset_vulnerabilities_total' => $avTotal,
    'triage_rows' => $triage,
    'notes_rows' => $notes,
    'activity_log_rows' => $activity,
    'cascade_notice' => 'Deleting the advisory removes asset_vulnerability rows and cascades triage, notes, and activity for those rows (test/internal cleanup only).',
];

if (! $args['apply']) {
    st_remove_advisory_emit_json($counts);
    exit(0);
}

try {
    $pdo->exec('BEGIN IMMEDIATE');
    $del = $pdo->prepare('DELETE FROM vulnerability_advisories WHERE id = ?');
    $del->execute([$aid]);
    $chk = $pdo->prepare('SELECT 1 FROM vulnerability_advisories WHERE id = ? LIMIT 1');
    $chk->execute([$aid]);
    if ($chk->fetchColumn()) {
        throw new RuntimeException('delete_verify_failed');
    }
    $pdo->exec('COMMIT');
} catch (Throwable $e) {
    try {
        $pdo->exec('ROLLBACK');
    } catch (Throwable $e2) {
    }
    st_remove_advisory_emit_json(['error' => 'delete_failed', 'message_safe' => substr($e->getMessage(), 0, 200)]);
    exit(1);
}

$counts['applied'] = true;
$counts['dry_run'] = false;
st_remove_advisory_emit_json($counts);
exit(0);
