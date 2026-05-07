#!/usr/bin/env php
<?php
/**
 * Read-only diagnostics for collector_ingest_queue eligibility and stall reasons.
 *
 * Usage:
 *   php scripts/diagnose_collector_ingest_queue.php [--db=/path/to/surveytrace.db] [--limit=20]
 */
declare(strict_types=1);

/**
 * @return array{db_path:string,limit:int}
 */
function st_diag_parse_args(array $argv): array
{
    $dbPath = dirname(__DIR__) . '/data/surveytrace.db';
    $limit = 20;
    foreach (array_slice($argv, 1) as $arg) {
        if (str_starts_with($arg, '--db=')) {
            $dbPath = (string) substr($arg, strlen('--db='));
            continue;
        }
        if (str_starts_with($arg, '--limit=')) {
            $limit = max(1, min(200, (int) substr($arg, strlen('--limit='))));
            continue;
        }
        if ($arg === '--help' || $arg === '-h') {
            fwrite(STDOUT, "Usage: php scripts/diagnose_collector_ingest_queue.php [--db=/path/to/surveytrace.db] [--limit=20]\n");
            exit(0);
        }
        fwrite(STDERR, "Unknown argument: {$arg}\n");
        exit(2);
    }

    return ['db_path' => $dbPath, 'limit' => $limit];
}

function st_diag_has_table(PDO $pdo, string $name): bool
{
    $st = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1");
    $st->execute([$name]);
    $v = $st->fetchColumn();
    return $v !== false && $v !== null;
}

$opt = st_diag_parse_args($argv);

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

if (! st_diag_has_table($pdo, 'collector_ingest_queue')) {
    fwrite(STDERR, "FAIL: collector_ingest_queue table not found.\n");
    exit(1);
}

$summary = [];
$summary['pending_total'] = (int) $pdo->query("SELECT COUNT(*) FROM collector_ingest_queue WHERE status='pending'")->fetchColumn();
$summary['failed_total'] = (int) $pdo->query("SELECT COUNT(*) FROM collector_ingest_queue WHERE status='failed'")->fetchColumn();
$summary['processing_total'] = (int) $pdo->query("SELECT COUNT(*) FROM collector_ingest_queue WHERE status='processing'")->fetchColumn();
$summary['eligible_now'] = (int) $pdo->query(
    "SELECT COUNT(*) FROM collector_ingest_queue
     WHERE status='pending' AND (next_attempt_at IS NULL OR datetime(next_attempt_at) <= datetime('now'))"
)->fetchColumn();
$summary['blocked_future_next_attempt'] = (int) $pdo->query(
    "SELECT COUNT(*) FROM collector_ingest_queue
     WHERE status='pending' AND next_attempt_at IS NOT NULL AND datetime(next_attempt_at) > datetime('now')"
)->fetchColumn();
$summary['oldest_pending_age_sec'] = max(0, (int) ($pdo->query(
    "SELECT CAST((strftime('%s','now') - strftime('%s', MIN(created_at))) AS INTEGER)
     FROM collector_ingest_queue WHERE status='pending'"
)->fetchColumn() ?: 0));
$summary['oldest_eligible_pending_age_sec'] = max(0, (int) ($pdo->query(
    "SELECT CAST((strftime('%s','now') - strftime('%s', MIN(created_at))) AS INTEGER)
     FROM collector_ingest_queue
     WHERE status='pending' AND (next_attempt_at IS NULL OR datetime(next_attempt_at) <= datetime('now'))"
)->fetchColumn() ?: 0));

$rows = [];
$sql = "SELECT id, collector_id, job_id, submission_id, chunk_index, chunk_count, status, attempts,
               next_attempt_at, created_at, processed_at, processing_started_at, local_relpath, artifact_uri, error_msg
        FROM collector_ingest_queue
        WHERE status IN ('pending','failed','processing')
        ORDER BY created_at ASC, id ASC
        LIMIT " . (int) $opt['limit'];
$st = $pdo->query($sql);
foreach ($st->fetchAll(PDO::FETCH_ASSOC) ?: [] as $r) {
    if (! is_array($r)) {
        continue;
    }
    $localRel = (string) ($r['local_relpath'] ?? '');
    $localExists = null;
    if ($localRel !== '') {
        $p = dirname(__DIR__) . '/data/collector_ingest/' . ltrim($localRel, '/');
        $localExists = is_file($p);
    }

    $submissionStatus = null;
    if (st_diag_has_table($pdo, 'collector_submissions')) {
        $subSt = $pdo->prepare(
            "SELECT status, chunk_count, received_chunks, processed_chunks
             FROM collector_submissions
             WHERE collector_id=? AND job_id=? AND submission_id=? LIMIT 1"
        );
        $subSt->execute([(int) ($r['collector_id'] ?? 0), (int) ($r['job_id'] ?? 0), (string) ($r['submission_id'] ?? '')]);
        $sub = $subSt->fetch(PDO::FETCH_ASSOC);
        if (is_array($sub)) {
            $submissionStatus = [
                'status' => (string) ($sub['status'] ?? ''),
                'chunk_count' => (int) ($sub['chunk_count'] ?? 0),
                'received_chunks' => (int) ($sub['received_chunks'] ?? 0),
                'processed_chunks' => (int) ($sub['processed_chunks'] ?? 0),
            ];
        }
    }

    $scanJobStatus = null;
    if (st_diag_has_table($pdo, 'scan_jobs')) {
        $js = $pdo->prepare("SELECT status FROM scan_jobs WHERE id=? LIMIT 1");
        $js->execute([(int) ($r['job_id'] ?? 0)]);
        $scanJobStatus = (string) ($js->fetchColumn() ?: '');
    }

    $mirror = null;
    if (st_diag_has_table($pdo, 'worker_jobs')) {
        $wm = $pdo->prepare(
            "SELECT status, attempts, updated_at
             FROM worker_jobs
             WHERE job_type='collector_ingest' AND entity_type='collector_submission'
               AND entity_id = (
                   SELECT id FROM collector_submissions WHERE collector_id=? AND job_id=? AND submission_id=? LIMIT 1
               )
             LIMIT 1"
        );
        $wm->execute([(int) ($r['collector_id'] ?? 0), (int) ($r['job_id'] ?? 0), (string) ($r['submission_id'] ?? '')]);
        $w = $wm->fetch(PDO::FETCH_ASSOC);
        if (is_array($w)) {
            $mirror = [
                'status' => (string) ($w['status'] ?? ''),
                'attempts' => (int) ($w['attempts'] ?? 0),
                'updated_at' => (string) ($w['updated_at'] ?? ''),
            ];
        }
    }

    $rows[] = [
        'id' => (int) ($r['id'] ?? 0),
        'collector_id' => (int) ($r['collector_id'] ?? 0),
        'job_id' => (int) ($r['job_id'] ?? 0),
        'submission_id' => (string) ($r['submission_id'] ?? ''),
        'chunk_index' => (int) ($r['chunk_index'] ?? 0),
        'chunk_count' => (int) ($r['chunk_count'] ?? 0),
        'status' => (string) ($r['status'] ?? ''),
        'attempts' => (int) ($r['attempts'] ?? 0),
        'next_attempt_at' => (string) ($r['next_attempt_at'] ?? ''),
        'created_at' => (string) ($r['created_at'] ?? ''),
        'processed_at' => (string) ($r['processed_at'] ?? ''),
        'processing_started_at' => (string) ($r['processing_started_at'] ?? ''),
        'local_relpath' => $localRel,
        'local_artifact_exists' => $localExists,
        'artifact_uri' => (string) ($r['artifact_uri'] ?? ''),
        'error_msg_safe' => (string) ($r['error_msg'] ?? ''),
        'scan_job_status' => $scanJobStatus,
        'submission' => $submissionStatus,
        'mirror_worker_job' => $mirror,
    ];
}

fwrite(STDOUT, json_encode([
    'ok' => true,
    'db_path' => $opt['db_path'],
    'summary' => $summary,
    'rows' => $rows,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n");
exit(0);
