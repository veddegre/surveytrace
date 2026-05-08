#!/usr/bin/env php
<?php
/**
 * Read-only scan / collector ingest diagnostics for one scan_jobs row.
 *
 * Usage:
 *   php scripts/diagnose_scan_failure.php --job=123 [--db=/path/to/surveytrace.db]
 */
declare(strict_types=1);

/**
 * @return array{db_path:string, job_id:int}
 */
function st_scan_diag_parse_args(array $argv): array
{
    $dbPath = dirname(__DIR__) . '/data/surveytrace.db';
    $jobId = 0;
    foreach (array_slice($argv, 1) as $arg) {
        if (str_starts_with($arg, '--db=')) {
            $dbPath = (string) substr($arg, strlen('--db='));
            continue;
        }
        if (str_starts_with($arg, '--job=')) {
            $jobId = max(0, (int) substr($arg, strlen('--job=')));
            continue;
        }
        if ($arg === '--help' || $arg === '-h') {
            fwrite(STDOUT, "Usage: php scripts/diagnose_scan_failure.php --job=<scan_jobs.id> [--db=/path/to/surveytrace.db]\n");
            exit(0);
        }
        fwrite(STDERR, "Unknown argument: {$arg}\n");
        exit(2);
    }

    return ['db_path' => $dbPath, 'job_id' => $jobId];
}

function st_scan_diag_has_table(PDO $pdo, string $name): bool
{
    $st = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1");
    $st->execute([$name]);
    $v = $st->fetchColumn();

    return $v !== false && $v !== null;
}

$opt = st_scan_diag_parse_args($argv);
if ($opt['job_id'] < 1) {
    fwrite(STDERR, "FAIL: pass --job=<positive scan_jobs.id>\n");
    exit(2);
}

try {
    $pdo = new PDO('sqlite:' . $opt['db_path'], null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA busy_timeout = 60000');
} catch (Throwable) {
    fwrite(STDERR, "FAIL: unable to open database.\n");
    exit(1);
}

if (! st_scan_diag_has_table($pdo, 'scan_jobs')) {
    fwrite(STDERR, "FAIL: scan_jobs table not found.\n");
    exit(1);
}

$jid = $opt['job_id'];
$st = $pdo->prepare('SELECT * FROM scan_jobs WHERE id = ? LIMIT 1');
$st->execute([$jid]);
$job = $st->fetch();
if (! is_array($job)) {
    fwrite(STDERR, "FAIL: scan_jobs id {$jid} not found.\n");
    exit(1);
}

$out = [
    'scan_job' => $job,
    'scan_log_tail' => [],
    'collector_submissions' => [],
    'collector_ingest_queue' => [],
    'worker_jobs_mirror' => [],
    'artifact_paths' => [],
    'collector_ingest_status_file' => null,
];

if (st_scan_diag_has_table($pdo, 'scan_log')) {
    $lg = $pdo->prepare("SELECT id, ts, level, ip, message FROM scan_log WHERE job_id = ? ORDER BY id DESC LIMIT 40");
    $lg->execute([$jid]);
    $out['scan_log_tail'] = array_reverse($lg->fetchAll() ?: []);
}

if (st_scan_diag_has_table($pdo, 'collector_submissions')) {
    $cs = $pdo->prepare('SELECT * FROM collector_submissions WHERE job_id = ? ORDER BY id ASC');
    $cs->execute([$jid]);
    $out['collector_submissions'] = $cs->fetchAll() ?: [];
}

if (st_scan_diag_has_table($pdo, 'collector_ingest_queue')) {
    $q = $pdo->prepare('SELECT * FROM collector_ingest_queue WHERE job_id = ? ORDER BY id ASC');
    $q->execute([$jid]);
    $rows = $q->fetchAll() ?: [];
    $out['collector_ingest_queue'] = $rows;
    $dataDir = dirname($opt['db_path']);
    foreach ($rows as $r) {
        if (! is_array($r)) {
            continue;
        }
        $rel = trim((string) ($r['local_relpath'] ?? ''));
        if ($rel === '') {
            continue;
        }
        $full = $dataDir . '/collector_ingest/' . $rel;
        $out['artifact_paths'][] = [
            'queue_id' => (int) ($r['id'] ?? 0),
            'local_relpath' => $rel,
            'exists' => is_file($full),
            'bytes' => is_file($full) ? (int) @filesize($full) : null,
        ];
    }
}

if (st_scan_diag_has_table($pdo, 'worker_jobs') && st_scan_diag_has_table($pdo, 'collector_submissions')) {
    $wj = $pdo->prepare(
        "SELECT wj.id, wj.job_type, wj.entity_type, wj.entity_id, wj.status, wj.error_code, wj.error_message,
                wj.created_at, wj.updated_at, wj.finished_at, wj.attempts, wj.max_attempts
         FROM worker_jobs wj
         JOIN collector_submissions cs ON cs.id = wj.entity_id
         WHERE wj.job_type = 'collector_ingest'
           AND wj.entity_type = 'collector_submission'
           AND cs.job_id = ?
         ORDER BY wj.id DESC
         LIMIT 8"
    );
    $wj->execute([$jid]);
    $out['worker_jobs_mirror'] = $wj->fetchAll() ?: [];
}

$statusPath = dirname($opt['db_path']) . '/collector_ingest_status.json';
if (is_readable($statusPath)) {
    $raw = @file_get_contents($statusPath);
    if (is_string($raw) && $raw !== '') {
        try {
            $parsed = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
            $out['collector_ingest_status_file'] = is_array($parsed) ? $parsed : null;
        } catch (Throwable) {
            $out['collector_ingest_status_file'] = ['_parse_error' => true];
        }
    }
}

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
