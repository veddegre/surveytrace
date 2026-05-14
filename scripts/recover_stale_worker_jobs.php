#!/usr/bin/env php
<?php
/**
 * Manual stale worker/job recovery helper (dry-run by default).
 *
 * Stale job detection matches api/health.php maintenance snapshot: any past-due lease, OR
 * updated_at/created_at older than --older-than-minutes (UTC cutoff passed as bound param).
 * Default --job-type=credentialed_check; use all to include collector_ingest (health counts all types).
 *
 * Usage:
 *   php scripts/recover_stale_worker_jobs.php [--apply] [--db=/path/to/surveytrace.db]
 *     [--older-than-minutes=60] [--job-type=credentialed_check|collector_ingest|all]
 *     [--mode=mark-failed|requeue|cancel-finalize] [--run-sync]
 */
declare(strict_types=1);

const ST_RECOVER_ACTION = 'maintenance.recover_stale_worker_jobs';
const ST_RECOVER_ACTOR = 'system_maintenance';
const ST_RECOVER_STALE_STATUSES = ['leased', 'running', 'retrying'];

/**
 * @return array{
 *   apply:bool,
 *   db_path:string,
 *   older_minutes:int,
 *   job_type:string,
 *   mode:string,
 *   run_sync:bool
 * }
 */
function st_recover_parse_args(array $argv): array
{
    $out = [
        'apply' => false,
        'db_path' => dirname(__DIR__) . '/data/surveytrace.db',
        'older_minutes' => 60,
        'job_type' => 'credentialed_check',
        'mode' => 'mark-failed',
        'run_sync' => false,
    ];
    foreach (array_slice($argv, 1) as $arg) {
        if ($arg === '--apply') {
            $out['apply'] = true;
            continue;
        }
        if ($arg === '--dry-run') {
            $out['apply'] = false;
            continue;
        }
        if ($arg === '--run-sync') {
            $out['run_sync'] = true;
            continue;
        }
        if ($arg === '--help' || $arg === '-h') {
            fwrite(STDOUT, "Usage: php scripts/recover_stale_worker_jobs.php [--apply] [--db=/path/to/db] [--older-than-minutes=60] [--job-type=credentialed_check|collector_ingest|all] [--mode=mark-failed|requeue|cancel-finalize] [--run-sync]\n");
            exit(0);
        }
        if (str_starts_with($arg, '--db=')) {
            $out['db_path'] = (string) substr($arg, strlen('--db='));
            continue;
        }
        if (str_starts_with($arg, '--older-than-minutes=')) {
            $out['older_minutes'] = max(1, (int) substr($arg, strlen('--older-than-minutes=')));
            continue;
        }
        if (str_starts_with($arg, '--job-type=')) {
            $out['job_type'] = trim((string) substr($arg, strlen('--job-type=')));
            continue;
        }
        if (str_starts_with($arg, '--mode=')) {
            $out['mode'] = trim((string) substr($arg, strlen('--mode=')));
            continue;
        }
        fwrite(STDERR, "Unknown argument: {$arg}\n");
        exit(2);
    }
    if (! in_array($out['job_type'], ['credentialed_check', 'collector_ingest', 'all'], true)) {
        fwrite(STDERR, "Invalid --job-type value.\n");
        exit(2);
    }
    if (! in_array($out['mode'], ['mark-failed', 'requeue', 'cancel-finalize'], true)) {
        fwrite(STDERR, "Invalid --mode value.\n");
        exit(2);
    }

    return $out;
}

function st_recover_has_table(PDO $pdo, string $name): bool
{
    $st = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1");
    $st->execute([$name]);
    $v = $st->fetchColumn();

    return $v !== false && $v !== null;
}

/**
 * @return list<array<string,mixed>>
 */
function st_recover_detect_stale_jobs(PDO $pdo, string $cutoff, string $jobType): array
{
    if (! st_recover_has_table($pdo, 'worker_jobs')) {
        return [];
    }
    $filter = '';
    $params = [];
    if ($jobType !== 'all') {
        $filter = " AND w.job_type = ?";
        $params[] = $jobType;
    }
    $params[] = $cutoff;
    $st = $pdo->prepare(
        "SELECT w.id, w.job_type, w.status, w.cancel_requested_at, w.lease_node_id, w.entity_id,
                COALESCE(w.lease_expires_at, '') AS lease_expires_at,
                COALESCE(w.updated_at, w.created_at, '1970-01-01 00:00:00') AS updated_at,
                (
                  SELECT MAX(h.heartbeat_at)
                  FROM worker_heartbeats h
                  WHERE h.node_id = w.lease_node_id
                ) AS last_heartbeat_at
         FROM worker_jobs w
         WHERE w.status IN ('leased','running','retrying')
           {$filter}
           AND (
             (w.lease_expires_at IS NOT NULL AND w.lease_expires_at <> '' AND w.lease_expires_at < datetime('now'))
             OR COALESCE(w.updated_at, w.created_at, '1970-01-01 00:00:00') < ?
           )"
    );
    $st->execute($params);

    return $st->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * @return list<array<string,mixed>>
 */
function st_recover_detect_cancelled_queued(PDO $pdo, string $cutoff, string $jobType): array
{
    if (! st_recover_has_table($pdo, 'worker_jobs')) {
        return [];
    }
    $filter = '';
    $params = [$cutoff];
    if ($jobType !== 'all') {
        $filter = " AND job_type = ?";
        $params[] = $jobType;
    }
    $st = $pdo->prepare(
        "SELECT id, job_type, status, entity_id
         FROM worker_jobs
         WHERE status = 'queued'
           AND cancel_requested_at IS NOT NULL
           AND cancel_requested_at <> ''
           AND cancel_requested_at < ?
           {$filter}"
    );
    $st->execute($params);

    return $st->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * @param list<int> $jobIds
 * @return list<array<string,mixed>>
 */
function st_recover_detect_stale_attempts(PDO $pdo, string $cutoff, array $jobIds): array
{
    if (! st_recover_has_table($pdo, 'worker_job_attempts')) {
        return [];
    }
    if ($jobIds === []) {
        $st = $pdo->prepare(
            "SELECT a.id, a.job_id, a.status
             FROM worker_job_attempts a
             JOIN worker_jobs w ON w.id = a.job_id
             WHERE a.status = 'running'
               AND a.started_at < ?
               AND w.status IN ('completed','failed','cancelled','expired')"
        );
        $st->execute([$cutoff]);

        return $st->fetchAll(PDO::FETCH_ASSOC);
    }
    $ph = implode(',', array_fill(0, count($jobIds), '?'));
    $st = $pdo->prepare(
        "SELECT id, job_id, status
         FROM worker_job_attempts
         WHERE status = 'running'
           AND started_at < ?
           AND job_id IN ({$ph})"
    );
    $st->execute(array_merge([$cutoff], $jobIds));

    return $st->fetchAll(PDO::FETCH_ASSOC);
}

function st_recover_insert_event(PDO $pdo, int $jobId, string $eventType, string $msg): void
{
    if (! st_recover_has_table($pdo, 'worker_job_events')) {
        return;
    }
    $st = $pdo->prepare(
        "INSERT INTO worker_job_events (job_id, event_type, level, message, details_json, created_at)
         VALUES (?, ?, 'warning', ?, NULL, datetime('now'))"
    );
    $st->execute([$jobId, $eventType, $msg]);
}

function st_recover_apply_job(PDO $pdo, array $row, string $mode): string
{
    $id = (int) ($row['id'] ?? 0);
    $status = (string) ($row['status'] ?? '');
    if ($id < 1 || ! in_array($status, ST_RECOVER_STALE_STATUSES, true)) {
        return 'skipped';
    }
    if ($mode === 'requeue') {
        $pdo->prepare(
            "UPDATE worker_jobs
             SET status='queued', lease_node_id=NULL, lease_token=NULL, leased_at=NULL, lease_expires_at=NULL,
                 next_attempt_at=datetime('now'), updated_at=datetime('now')
             WHERE id=?"
        )->execute([$id]);
        st_recover_insert_event($pdo, $id, 'maintenance.recovered_stale_job', 'stale job manually requeued');

        return 'requeued';
    }
    if ($mode === 'cancel-finalize') {
        $pdo->prepare(
            "UPDATE worker_jobs
             SET status='cancelled', error_code='maintenance_recovered', error_message='manual stale recovery finalize',
                 finished_at=datetime('now'), updated_at=datetime('now')
             WHERE id=?"
        )->execute([$id]);
        st_recover_insert_event($pdo, $id, 'maintenance.finalized_cancelled_job', 'stale job manually finalized cancelled');

        return 'cancelled';
    }
    $pdo->prepare(
        "UPDATE worker_jobs
         SET status='failed', error_code='maintenance_recovered', error_message='manual stale recovery mark-failed',
             finished_at=datetime('now'), updated_at=datetime('now')
         WHERE id=?"
    )->execute([$id]);
    st_recover_insert_event($pdo, $id, 'maintenance.recovered_stale_job', 'stale job manually marked failed');

    return 'failed';
}

function st_recover_finalize_attempt(PDO $pdo, int $attemptId): int
{
    if ($attemptId < 1 || ! st_recover_has_table($pdo, 'worker_job_attempts')) {
        return 0;
    }
    $st = $pdo->prepare(
        "UPDATE worker_job_attempts
         SET status='failed', error_code='maintenance_recovered', error_message='manual stale recovery finalize',
             finished_at=datetime('now')
         WHERE id=? AND status='running'"
    );
    $st->execute([$attemptId]);

    return (int) $st->rowCount();
}

function st_recover_finalize_queued_cancel(PDO $pdo, int $jobId): int
{
    $st = $pdo->prepare(
        "UPDATE worker_jobs
         SET status='cancelled', error_code='cancelled', error_message='cancel finalized by maintenance helper',
             finished_at=datetime('now'), updated_at=datetime('now')
         WHERE id=? AND status='queued' AND cancel_requested_at IS NOT NULL AND cancel_requested_at <> ''"
    );
    $st->execute([$jobId]);
    $n = (int) $st->rowCount();
    if ($n > 0) {
        st_recover_insert_event($pdo, $jobId, 'maintenance.finalized_cancelled_job', 'queued cancel request finalized by maintenance helper');
    }

    return $n;
}

/**
 * @return list<array<string,mixed>>
 */
function st_recover_run_sync_candidates(PDO $pdo, string $cutoff): array
{
    if (! st_recover_has_table($pdo, 'credential_check_runs') || ! st_recover_has_table($pdo, 'worker_jobs')) {
        return [];
    }
    $st = $pdo->prepare(
        "SELECT r.id, r.status, r.worker_job_id, w.status AS worker_status, w.error_code AS worker_error
         FROM credential_check_runs r
         JOIN worker_jobs w ON w.id = r.worker_job_id
         WHERE r.status IN ('queued','running','ready','resolving_targets')
           AND (
             w.status IN ('failed','cancelled','expired')
             OR (
               w.status IN ('leased','running','retrying')
               AND (
                 (w.lease_expires_at IS NOT NULL AND w.lease_expires_at <> '' AND w.lease_expires_at < datetime('now'))
                 OR COALESCE(w.updated_at,w.created_at,'1970-01-01 00:00:00') < ?
               )
             )
           )"
    );
    $st->execute([$cutoff]);

    return $st->fetchAll(PDO::FETCH_ASSOC);
}

function st_recover_sync_run(PDO $pdo, array $r): int
{
    $runId = (int) ($r['id'] ?? 0);
    $workerStatus = (string) ($r['worker_status'] ?? '');
    if ($runId < 1) {
        return 0;
    }
    $newStatus = in_array($workerStatus, ['cancelled', 'expired'], true) ? 'cancelled' : 'failed';
    $code = in_array($workerStatus, ['cancelled', 'expired'], true) ? 'user_cancelled' : 'maintenance_recovered';
    $summary = ['maintenance_recovery' => true, 'worker_status' => $workerStatus, 'at' => gmdate('Y-m-d H:i:s')];
    $enc = json_encode($summary, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $st = $pdo->prepare(
        "UPDATE credential_check_runs
         SET status=?, finished_at=datetime('now'), summary_json=?
         WHERE id=? AND status IN ('queued','running','ready','resolving_targets')"
    );
    $st->execute([$newStatus, $enc !== false ? $enc : null, $runId]);
    $n = (int) $st->rowCount();
    if ($n > 0 && st_recover_has_table($pdo, 'credential_check_run_targets')) {
        $pdo->prepare(
            "UPDATE credential_check_run_targets
             SET status=?, error_code=?, error_message_safe='recovered by maintenance helper',
                 finished_at=COALESCE(finished_at, datetime('now'))
             WHERE run_id=? AND status IN ('pending','running')"
        )->execute([$newStatus === 'cancelled' ? 'skipped' : 'failed', $code, $runId]);
    }

    return $n;
}

function st_recover_write_audit(PDO $pdo, array $details): void
{
    if (! st_recover_has_table($pdo, 'user_audit_log')) {
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS user_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_id INTEGER,
                actor_username TEXT,
                target_user_id INTEGER,
                target_username TEXT,
                action TEXT NOT NULL,
                details_json TEXT,
                source_ip TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"
        );
    }
    $enc = json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $st = $pdo->prepare(
        "INSERT INTO user_audit_log
         (actor_user_id, actor_username, target_user_id, target_username, action, details_json, source_ip)
         VALUES (NULL, ?, NULL, NULL, ?, ?, '127.0.0.1')"
    );
    $st->execute([ST_RECOVER_ACTOR, ST_RECOVER_ACTION, $enc !== false ? $enc : null]);
}

$opt = st_recover_parse_args($argv);
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

$cutoffTs = time() - ($opt['older_minutes'] * 60);
$cutoff = gmdate('Y-m-d H:i:s', $cutoffTs);

$staleJobs = st_recover_detect_stale_jobs($pdo, $cutoff, $opt['job_type']);
$queuedCancels = st_recover_detect_cancelled_queued($pdo, $cutoff, $opt['job_type']);
$jobIds = array_map(static fn($r) => (int) ($r['id'] ?? 0), $staleJobs);
$staleAttempts = st_recover_detect_stale_attempts($pdo, $cutoff, $jobIds);
$runSync = $opt['run_sync'] ? st_recover_run_sync_candidates($pdo, $cutoff) : [];

$changed = [
    'worker_jobs_failed' => 0,
    'worker_jobs_requeued' => 0,
    'worker_jobs_cancelled' => 0,
    'worker_attempts_finalized' => 0,
    'queued_cancels_finalized' => 0,
    'runs_synced' => 0,
];

if ($opt['apply']) {
    $pdo->beginTransaction();
}
try {
    if ($opt['apply']) {
        foreach ($staleJobs as $row) {
            $res = st_recover_apply_job($pdo, $row, $opt['mode']);
            if ($res === 'failed') {
                $changed['worker_jobs_failed']++;
            } elseif ($res === 'requeued') {
                $changed['worker_jobs_requeued']++;
            } elseif ($res === 'cancelled') {
                $changed['worker_jobs_cancelled']++;
            }
        }
        foreach ($queuedCancels as $row) {
            $changed['queued_cancels_finalized'] += st_recover_finalize_queued_cancel($pdo, (int) ($row['id'] ?? 0));
        }
        foreach ($staleAttempts as $row) {
            $changed['worker_attempts_finalized'] += st_recover_finalize_attempt($pdo, (int) ($row['id'] ?? 0));
        }
        if ($opt['run_sync']) {
            $runSyncNow = st_recover_run_sync_candidates($pdo, $cutoff);
            foreach ($runSyncNow as $r) {
                $changed['runs_synced'] += st_recover_sync_run($pdo, $r);
            }
            $runSync = $runSyncNow;
        }
        st_recover_write_audit($pdo, [
            'cutoff_utc' => $cutoff,
            'older_than_minutes' => $opt['older_minutes'],
            'job_type' => $opt['job_type'],
            'mode' => $opt['mode'],
            'run_sync' => $opt['run_sync'],
            'candidates' => [
                'stale_jobs' => count($staleJobs),
                'queued_cancels' => count($queuedCancels),
                'stale_attempts' => count($staleAttempts),
                'run_sync' => count($runSync),
            ],
            'changed' => $changed,
        ]);
        $pdo->commit();
    }
} catch (Throwable) {
    if ($opt['apply'] && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    fwrite(STDERR, "FAIL: stale recovery failed safely.\n");
    exit(1);
}

fwrite(STDOUT, json_encode([
    'ok' => true,
    'mode' => $opt['apply'] ? 'apply' : 'dry_run',
    'db_path' => $opt['db_path'],
    'older_than_minutes' => $opt['older_minutes'],
    'cutoff_utc' => $cutoff,
    'job_type' => $opt['job_type'],
    'recovery_mode' => $opt['mode'],
    'run_sync' => $opt['run_sync'],
    'candidates' => [
        'stale_jobs' => count($staleJobs),
        'queued_cancelled_jobs' => count($queuedCancels),
        'stale_running_attempts' => count($staleAttempts),
        'run_sync_candidates' => count($runSync),
    ],
    'changed' => $changed,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n");

exit(0);
