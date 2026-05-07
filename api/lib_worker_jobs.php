<?php
/**
 * SurveyTrace — worker execution substrate helpers.
 *
 * Small explicit PDO helpers for worker_nodes, worker_jobs, attempts, events, heartbeats.
 * Helpers stay safe to load without side effects until production callers adopt the substrate.
 *
 * Structured error_code values align with docs/WORKER_EXECUTION_SUBSTRATE.md §6.
 *
 * @see docs/WORKER_EXECUTION_SUBSTRATE.md
 * @see docs/WORKER_EXECUTION_MVP_PLAN.md
 */

declare(strict_types=1);

/** @var list<string> */
const ST_WORKER_ERROR_CODES = [
    'transport_error',
    'auth_error',
    'timeout',
    'policy_blocked',
    'validation_error',
    'dependency_missing',
    'storage_error',
    'internal_error',
];

function st_worker_error_code_valid(?string $code): bool
{
    if ($code === null || $code === '') {
        return false;
    }

    return in_array($code, ST_WORKER_ERROR_CODES, true);
}

function st_worker_tables_ready(PDO $pdo): bool
{
    try {
        $m = $pdo->query(
            "SELECT value FROM config WHERE key = 'migration_worker_execution_substrate_v1' LIMIT 1"
        )->fetchColumn();
        if ($m !== '1' && $m !== 1) {
            return false;
        }
        $t = $pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'worker_jobs' LIMIT 1"
        )->fetchColumn();

        return $t !== false && $t !== null;
    } catch (Throwable) {
        return false;
    }
}

/**
 * @param array<string, mixed> $value
 */
function st_worker_json_encode(?array $value): ?string
{
    if ($value === null || $value === []) {
        return null;
    }
    $flags = JSON_UNESCAPED_SLASHES;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    $j = json_encode($value, $flags);

    return $j === false ? null : $j;
}

function st_worker_safe_message(?string $msg, int $maxLen = 2000): string
{
    if ($msg === null) {
        return '';
    }
    $msg = trim($msg);
    if (strlen($msg) > $maxLen) {
        return substr($msg, 0, $maxLen);
    }

    return $msg;
}

/**
 * Register or refresh a worker node by unique node_key.
 *
 * Options: node_key (string, required), hostname?, role?, status?, meta_json? (array)
 *
 * @param array<string, mixed> $opts
 *
 * @return int node id or 0 on failure / tables not ready
 */
function st_worker_register_node(PDO $pdo, array $opts): int
{
    if (! st_worker_tables_ready($pdo)) {
        return 0;
    }
    $key = isset($opts['node_key']) ? trim((string) $opts['node_key']) : '';
    if ($key === '') {
        return 0;
    }
    $host = isset($opts['hostname']) ? trim((string) $opts['hostname']) : null;
    $role = isset($opts['role']) ? trim((string) $opts['role']) : null;
    $status = isset($opts['status']) ? trim((string) $opts['status']) : 'starting';
    if ($status === '') {
        $status = 'starting';
    }
    $meta = isset($opts['meta_json']) && is_array($opts['meta_json']) ? st_worker_json_encode($opts['meta_json']) : null;

    try {
        $st = $pdo->prepare(
            'INSERT INTO worker_nodes (node_key, hostname, role, status, meta_json, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, datetime(\'now\'), datetime(\'now\'))
             ON CONFLICT(node_key) DO UPDATE SET
               hostname = excluded.hostname,
               role = excluded.role,
               status = excluded.status,
               meta_json = excluded.meta_json,
               updated_at = datetime(\'now\')'
        );
        $st->execute([$key, $host ?: null, $role ?: null, $status, $meta]);
        $sel = $pdo->prepare('SELECT id FROM worker_nodes WHERE node_key = ? LIMIT 1');
        $sel->execute([$key]);
        $id = (int) $sel->fetchColumn();

        return $id > 0 ? $id : 0;
    } catch (Throwable) {
        return 0;
    }
}

/**
 * Append a heartbeat row and bump worker_nodes.updated_at when node_id matches.
 *
 * Options: node_id (int, required), worker_type (string, required), worker_key?, status?, details_json? (array)
 *
 * @param array<string, mixed> $opts
 */
function st_worker_heartbeat(PDO $pdo, array $opts): void
{
    if (! st_worker_tables_ready($pdo)) {
        return;
    }
    $nid = isset($opts['node_id']) ? (int) $opts['node_id'] : 0;
    $wtype = isset($opts['worker_type']) ? trim((string) $opts['worker_type']) : '';
    if ($nid < 1 || $wtype === '') {
        return;
    }
    $wkey = isset($opts['worker_key']) ? trim((string) $opts['worker_key']) : null;
    $status = isset($opts['status']) ? trim((string) $opts['status']) : 'healthy';
    if ($status === '') {
        $status = 'healthy';
    }
    $det = isset($opts['details_json']) && is_array($opts['details_json']) ? st_worker_json_encode($opts['details_json']) : null;

    try {
        $pdo->prepare(
            'INSERT INTO worker_heartbeats (node_id, worker_key, worker_type, status, heartbeat_at, details_json)
             VALUES (?, ?, ?, ?, datetime(\'now\'), ?)'
        )->execute([$nid, $wkey ?: null, $wtype, $status, $det]);
        $pdo->prepare('UPDATE worker_nodes SET updated_at = datetime(\'now\') WHERE id = ?')->execute([$nid]);
    } catch (Throwable) {
        // best-effort
    }
}

/**
 * Enqueue a new job (status queued).
 *
 * Job keys: job_type (required), entity_type?, entity_id?, priority?, max_attempts?, payload_json? (array)
 *
 * @param array<string, mixed> $job
 *
 * @return int job id or 0
 */
function st_worker_enqueue_job(PDO $pdo, array $job): int
{
    if (! st_worker_tables_ready($pdo)) {
        return 0;
    }
    $jtype = isset($job['job_type']) ? trim((string) $job['job_type']) : '';
    if ($jtype === '') {
        return 0;
    }
    $etype = isset($job['entity_type']) ? trim((string) $job['entity_type']) : null;
    $eid = array_key_exists('entity_id', $job) && $job['entity_id'] !== null && $job['entity_id'] !== ''
        ? (int) $job['entity_id'] : null;
    $pri = isset($job['priority']) ? (int) $job['priority'] : 0;
    $max = isset($job['max_attempts']) ? max(1, (int) $job['max_attempts']) : 3;
    $payload = isset($job['payload_json']) && is_array($job['payload_json']) ? st_worker_json_encode($job['payload_json']) : null;

    try {
        $st = $pdo->prepare(
            'INSERT INTO worker_jobs (job_type, entity_type, entity_id, status, priority, max_attempts, payload_json, created_at, updated_at)
             VALUES (?, ?, ?, \'queued\', ?, ?, ?, datetime(\'now\'), datetime(\'now\'))'
        );
        $st->execute([$jtype, $etype ?: null, $eid, $pri, $max, $payload]);

        return (int) $pdo->lastInsertId();
    } catch (Throwable) {
        return 0;
    }
}

/**
 * Claim the next eligible queued job for a worker node.
 *
 * Options: lease_node_id (int, required), lease_token (string, optional — generated if empty),
 * lease_ttl_sec (int, default 300), allowed_job_types (list<string> — empty = all types)
 *
 * @param array<string, mixed> $opts
 *
 * @return array<string, mixed>|null full job row or null
 */
function st_worker_lease_next_job(PDO $pdo, array $opts): ?array
{
    if (! st_worker_tables_ready($pdo)) {
        return null;
    }
    $nodeId = isset($opts['lease_node_id']) ? (int) $opts['lease_node_id'] : 0;
    if ($nodeId < 1) {
        return null;
    }
    $token = isset($opts['lease_token']) ? trim((string) $opts['lease_token']) : '';
    if ($token === '') {
        try {
            $token = bin2hex(random_bytes(16));
        } catch (Throwable) {
            $token = (string) mt_rand();
        }
    }
    $ttl = isset($opts['lease_ttl_sec']) ? max(30, min(86400, (int) $opts['lease_ttl_sec'])) : 300;
    $allowed = isset($opts['allowed_job_types']) && is_array($opts['allowed_job_types'])
        ? array_values(array_filter(array_map('strval', $opts['allowed_job_types']))) : [];

    try {
        $pdo->exec('BEGIN IMMEDIATE');
        $sql = 'SELECT id FROM worker_jobs WHERE status = \'queued\'
            AND cancel_requested_at IS NULL
            AND (next_attempt_at IS NULL OR datetime(next_attempt_at) <= datetime(\'now\'))';
        $params = [];
        if ($allowed !== []) {
            $placeholders = implode(',', array_fill(0, count($allowed), '?'));
            $sql .= " AND job_type IN ($placeholders)";
            foreach ($allowed as $t) {
                $params[] = $t;
            }
        }
        $sql .= ' ORDER BY priority DESC, id ASC LIMIT 1';
        $st = $pdo->prepare($sql);
        $st->execute($params);
        $jid = $st->fetchColumn();
        if ($jid === false || $jid === null) {
            $pdo->exec('COMMIT');

            return null;
        }
        $jid = (int) $jid;
        $upd = $pdo->prepare(
            'UPDATE worker_jobs SET status = \'leased\', lease_node_id = ?, lease_token = ?, leased_at = datetime(\'now\'),
                lease_expires_at = datetime(\'now\', ?), updated_at = datetime(\'now\')
             WHERE id = ? AND status = \'queued\''
        );
        $upd->execute([$nodeId, $token, '+' . $ttl . ' seconds', $jid]);
        if ($upd->rowCount() !== 1) {
            $pdo->exec('ROLLBACK');

            return null;
        }
        $pdo->exec('COMMIT');
        $sel = $pdo->prepare('SELECT * FROM worker_jobs WHERE id = ? LIMIT 1');
        $sel->execute([$jid]);
        $row = $sel->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    } catch (Throwable) {
        try {
            $pdo->exec('ROLLBACK');
        } catch (Throwable) {
        }

        return null;
    }
}

/**
 * Start a new attempt for a job; sets job status to running when successful.
 *
 * Options: node_id? (int)
 *
 * @param array<string, mixed> $opts
 *
 * @return int attempt id or 0
 */
function st_worker_start_attempt(PDO $pdo, int $jobId, array $opts): int
{
    if (! st_worker_tables_ready($pdo) || $jobId < 1) {
        return 0;
    }
    $nodeId = isset($opts['node_id']) ? (int) $opts['node_id'] : null;
    if ($nodeId !== null && $nodeId < 1) {
        $nodeId = null;
    }

    try {
        $pdo->exec('BEGIN IMMEDIATE');
        $q = $pdo->prepare('SELECT id, status, cancel_requested_at FROM worker_jobs WHERE id = ? LIMIT 1');
        $q->execute([$jobId]);
        $chk = $q->fetch(PDO::FETCH_ASSOC);
        if (! is_array($chk)) {
            $pdo->exec('ROLLBACK');

            return 0;
        }
        if (($chk['status'] ?? '') === 'cancelled' || ($chk['status'] ?? '') === 'completed' || ($chk['status'] ?? '') === 'failed') {
            $pdo->exec('ROLLBACK');

            return 0;
        }
        if (isset($chk['cancel_requested_at']) && $chk['cancel_requested_at'] !== null && $chk['cancel_requested_at'] !== '') {
            $pdo->exec('ROLLBACK');

            return 0;
        }
        $pdo->prepare(
            'INSERT INTO worker_job_attempts (job_id, attempt_no, node_id, status, started_at)
             SELECT ?, COALESCE(MAX(attempt_no), 0) + 1, ?, \'running\', datetime(\'now\')
             FROM worker_job_attempts WHERE job_id = ?'
        )->execute([$jobId, $nodeId, $jobId]);
        $aid = (int) $pdo->lastInsertId();
        if ($aid < 1) {
            $pdo->exec('ROLLBACK');

            return 0;
        }
        $pdo->prepare(
            'UPDATE worker_jobs SET status = \'running\', attempts = (SELECT MAX(attempt_no) FROM worker_job_attempts WHERE job_id = ?),
                updated_at = datetime(\'now\') WHERE id = ?'
        )->execute([$jobId, $jobId]);
        $pdo->exec('COMMIT');

        return $aid;
    } catch (Throwable) {
        try {
            $pdo->exec('ROLLBACK');
        } catch (Throwable) {
        }

        return 0;
    }
}

/**
 * @param array<string, mixed> $opts status (required), error_code?, error_message?, metrics_json? (array)
 */
function st_worker_finish_attempt(PDO $pdo, int $attemptId, array $opts): void
{
    if (! st_worker_tables_ready($pdo) || $attemptId < 1) {
        return;
    }
    $status = isset($opts['status']) ? trim((string) $opts['status']) : '';
    if ($status === '') {
        $status = 'completed';
    }
    $ec = isset($opts['error_code']) ? trim((string) $opts['error_code']) : null;
    if ($ec !== null && $ec !== '' && ! st_worker_error_code_valid($ec)) {
        $ec = 'internal_error';
    }
    $em = isset($opts['error_message']) ? st_worker_safe_message((string) $opts['error_message']) : null;
    $met = isset($opts['metrics_json']) && is_array($opts['metrics_json']) ? st_worker_json_encode($opts['metrics_json']) : null;

    try {
        $pdo->prepare(
            'UPDATE worker_job_attempts SET status = ?, finished_at = datetime(\'now\'), error_code = ?, error_message = ?, metrics_json = ?
             WHERE id = ?'
        )->execute([$status, $ec ?: null, $em ?: null, $met, $attemptId]);
    } catch (Throwable) {
    }
}

/**
 * @param array<string, mixed> $opts result_summary_json? (array)
 */
function st_worker_finish_job(PDO $pdo, int $jobId, array $opts): void
{
    if (! st_worker_tables_ready($pdo) || $jobId < 1) {
        return;
    }
    $sum = isset($opts['result_summary_json']) && is_array($opts['result_summary_json'])
        ? st_worker_json_encode($opts['result_summary_json']) : null;

    try {
        $pdo->prepare(
            'UPDATE worker_jobs SET status = \'completed\', finished_at = datetime(\'now\'), updated_at = datetime(\'now\'),
                lease_node_id = NULL, lease_token = NULL, leased_at = NULL, lease_expires_at = NULL,
                result_summary_json = COALESCE(?, result_summary_json), error_code = NULL, error_message = NULL
             WHERE id = ?'
        )->execute([$sum, $jobId]);
    } catch (Throwable) {
    }
}

/**
 * @param array<string, mixed> $opts error_code (required or defaulted), error_message?
 */
function st_worker_fail_job(PDO $pdo, int $jobId, array $opts): void
{
    if (! st_worker_tables_ready($pdo) || $jobId < 1) {
        return;
    }
    $ec = isset($opts['error_code']) ? trim((string) $opts['error_code']) : 'internal_error';
    if (! st_worker_error_code_valid($ec)) {
        $ec = 'internal_error';
    }
    $em = isset($opts['error_message']) ? st_worker_safe_message((string) $opts['error_message']) : null;

    try {
        $pdo->prepare(
            'UPDATE worker_jobs SET status = \'failed\', finished_at = datetime(\'now\'), updated_at = datetime(\'now\'),
                error_code = ?, error_message = ?,
                lease_node_id = NULL, lease_token = NULL, leased_at = NULL, lease_expires_at = NULL
             WHERE id = ?'
        )->execute([$ec, $em ?: '', $jobId]);
    } catch (Throwable) {
    }
}

function st_worker_request_cancel(PDO $pdo, int $jobId, string $actor): void
{
    if (! st_worker_tables_ready($pdo) || $jobId < 1) {
        return;
    }
    $actor = st_worker_safe_message($actor, 512);
    try {
        $st = $pdo->prepare(
            'UPDATE worker_jobs SET cancel_requested_at = datetime(\'now\'), updated_at = datetime(\'now\') WHERE id = ? AND finished_at IS NULL'
        );
        $st->execute([$jobId]);
        if ($st->rowCount() < 1) {
            return;
        }
        st_worker_log_event($pdo, [
            'job_id'     => $jobId,
            'event_type' => 'cancel_requested',
            'level'      => 'info',
            'message'    => 'Cancellation requested',
            'details_json' => ['actor' => $actor],
        ]);
    } catch (Throwable) {
    }
}

/**
 * When cancel was requested while the job is still queued, move it to a terminal cancelled row
 * so lease workers never see it stuck in queued+cancel_requested (lease excludes those rows).
 *
 * @return bool true if a row was updated
 */
function st_worker_finalize_queued_cancel(PDO $pdo, int $jobId): bool
{
    if (! st_worker_tables_ready($pdo) || $jobId < 1) {
        return false;
    }
    try {
        $st = $pdo->prepare(
            "UPDATE worker_jobs SET status = 'cancelled', finished_at = datetime('now'), updated_at = datetime('now'),
                lease_node_id = NULL, lease_token = NULL, leased_at = NULL, lease_expires_at = NULL,
                error_code = NULL, error_message = NULL
             WHERE id = ? AND status = 'queued' AND cancel_requested_at IS NOT NULL AND finished_at IS NULL"
        );
        $st->execute([$jobId]);

        return $st->rowCount() === 1;
    } catch (Throwable) {
        return false;
    }
}

/**
 * Mark a worker job cancelled (terminal). Clears lease fields. Optional result_summary_json.
 *
 * @param array<string, mixed> $opts result_summary_json? (array)
 */
function st_worker_finish_job_cancelled(PDO $pdo, int $jobId, array $opts = []): void
{
    if (! st_worker_tables_ready($pdo) || $jobId < 1) {
        return;
    }
    $sum = isset($opts['result_summary_json']) && is_array($opts['result_summary_json'])
        ? st_worker_json_encode($opts['result_summary_json']) : null;
    try {
        $pdo->prepare(
            "UPDATE worker_jobs SET status = 'cancelled', finished_at = datetime('now'), updated_at = datetime('now'),
                lease_node_id = NULL, lease_token = NULL, leased_at = NULL, lease_expires_at = NULL,
                result_summary_json = COALESCE(?, result_summary_json), error_code = NULL, error_message = NULL
             WHERE id = ? AND finished_at IS NULL"
        )->execute([$sum, $jobId]);
    } catch (Throwable) {
    }
}

/**
 * If cancel was requested while status is leased (e.g. worker saw cancel before start_attempt),
 * promote to cancelled so the job does not remain leased indefinitely.
 *
 * @return bool true if a row was updated
 */
function st_worker_finalize_leased_cancel(PDO $pdo, int $jobId): bool
{
    if (! st_worker_tables_ready($pdo) || $jobId < 1) {
        return false;
    }
    try {
        $st = $pdo->prepare(
            "UPDATE worker_jobs SET status = 'cancelled', finished_at = datetime('now'), updated_at = datetime('now'),
                lease_node_id = NULL, lease_token = NULL, leased_at = NULL, lease_expires_at = NULL,
                error_code = NULL, error_message = NULL
             WHERE id = ? AND status = 'leased' AND cancel_requested_at IS NOT NULL AND finished_at IS NULL"
        );
        $st->execute([$jobId]);

        return $st->rowCount() === 1;
    } catch (Throwable) {
        return false;
    }
}

/**
 * @param array<string, mixed> $event job_id, event_type (required); attempt_id?, level?, message?, details_json? (array)
 */
function st_worker_log_event(PDO $pdo, array $event): void
{
    if (! st_worker_tables_ready($pdo)) {
        return;
    }
    $jid = isset($event['job_id']) ? (int) $event['job_id'] : 0;
    $etype = isset($event['event_type']) ? trim((string) $event['event_type']) : '';
    if ($jid < 1 || $etype === '') {
        return;
    }
    $aid = isset($event['attempt_id']) ? (int) $event['attempt_id'] : null;
    if ($aid !== null && $aid < 1) {
        $aid = null;
    }
    $level = isset($event['level']) ? trim((string) $event['level']) : 'info';
    if ($level === '') {
        $level = 'info';
    }
    $msg = isset($event['message']) ? st_worker_safe_message((string) $event['message']) : null;
    $det = isset($event['details_json']) && is_array($event['details_json']) ? st_worker_json_encode($event['details_json']) : null;

    try {
        $pdo->prepare(
            'INSERT INTO worker_job_events (job_id, attempt_id, event_type, level, message, details_json, created_at)
             VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))'
        )->execute([$jid, $aid, $etype, $level, $msg ?: null, $det]);
    } catch (Throwable) {
    }
}

/**
 * Read-only snapshot for System Health. Cheap COUNT/MIN queries only.
 *
 * @return array{
 *   tables_ready: bool,
 *   node_count: int,
 *   heartbeat_count: int,
 *   stale_heartbeat_count: int,
 *   queued_jobs: int,
 *   leased_jobs: int,
 *   running_jobs: int,
 *   retrying_jobs: int,
 *   failed_jobs: int,
 *   cancelled_jobs: int,
 *   oldest_queued_age_sec: int|null,
 *   oldest_running_age_sec: int|null,
 *   recent_failed_jobs_24h: int,
 *   recent_error_events_24h: int,
 *   last_error_message: string|null,
 *   status: 'ok'|'warn'|'error'|'unavailable',
 *   summary: string,
 *   warning_hints: list<string>
 * }
 */
function st_worker_substrate_health_snapshot(PDO $pdo): array
{
    $staleHbSec = 300;
    $warnQueuedSec = 600;
    $warnRunningSec = 3600;
    $errorFailedTotal = 50;
    $errorRecentFailed24h = 25;
    $errorRecentEvents24h = 200;
    $errorQueuedStuckSec = 172800; // 48h

    $out = [
        'tables_ready'               => false,
        'node_count'                 => 0,
        'heartbeat_count'            => 0,
        'stale_heartbeat_count'       => 0,
        'queued_jobs'                => 0,
        'leased_jobs'                => 0,
        'running_jobs'               => 0,
        'retrying_jobs'              => 0,
        'failed_jobs'                => 0,
        'cancelled_jobs'             => 0,
        'oldest_queued_age_sec'      => null,
        'oldest_running_age_sec'     => null,
        'recent_failed_jobs_24h'     => 0,
        'recent_error_events_24h'    => 0,
        'last_error_message'         => null,
        'status'                     => 'unavailable',
        'summary'                    => 'Worker substrate tables are not present or the migration has not run yet.',
        'warning_hints'              => [],
    ];

    try {
        if (! st_worker_tables_ready($pdo)) {
            return $out;
        }

        $jobsTbl = $pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'worker_jobs' LIMIT 1"
        )->fetchColumn();
        if ($jobsTbl === false || $jobsTbl === null) {
            return $out;
        }

        $nodesTbl = (bool) $pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'worker_nodes' LIMIT 1"
        )->fetchColumn();
        $hbTbl = (bool) $pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'worker_heartbeats' LIMIT 1"
        )->fetchColumn();
        $evTbl = (bool) $pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'worker_job_events' LIMIT 1"
        )->fetchColumn();

        $out['tables_ready'] = true;

        if ($nodesTbl) {
            $out['node_count'] = (int) $pdo->query('SELECT COUNT(*) FROM worker_nodes')->fetchColumn();
        }
        if ($hbTbl) {
            $out['heartbeat_count'] = (int) $pdo->query('SELECT COUNT(*) FROM worker_heartbeats')->fetchColumn();
            $stSql = 'SELECT COUNT(*) FROM worker_nodes n
                LEFT JOIN (
                    SELECT node_id, MAX(heartbeat_at) AS mx FROM worker_heartbeats GROUP BY node_id
                ) t ON t.node_id = n.id
                WHERE t.mx IS NULL OR datetime(t.mx) < datetime(\'now\', \'-' . (int) $staleHbSec . ' seconds\')';
            $out['stale_heartbeat_count'] = (int) $pdo->query($stSql)->fetchColumn();
        }

        $agg = $pdo->query(
            "SELECT
                SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queued_jobs,
                SUM(CASE WHEN status = 'leased' THEN 1 ELSE 0 END) AS leased_jobs,
                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running_jobs,
                SUM(CASE WHEN status = 'retrying' THEN 1 ELSE 0 END) AS retrying_jobs,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_jobs,
                SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled_jobs
             FROM worker_jobs"
        )->fetch(PDO::FETCH_ASSOC);
        if (is_array($agg)) {
            $out['queued_jobs'] = (int) ($agg['queued_jobs'] ?? 0);
            $out['leased_jobs'] = (int) ($agg['leased_jobs'] ?? 0);
            $out['running_jobs'] = (int) ($agg['running_jobs'] ?? 0);
            $out['retrying_jobs'] = (int) ($agg['retrying_jobs'] ?? 0);
            $out['failed_jobs'] = (int) ($agg['failed_jobs'] ?? 0);
            $out['cancelled_jobs'] = (int) ($agg['cancelled_jobs'] ?? 0);
        }

        if ($out['queued_jobs'] > 0) {
            $oq = $pdo->query(
                "SELECT CAST((strftime('%s','now') - strftime('%s', MIN(created_at))) AS INTEGER) FROM worker_jobs WHERE status = 'queued'"
            )->fetchColumn();
            $out['oldest_queued_age_sec'] = max(0, (int) ($oq ?: 0));
        }
        if ($out['running_jobs'] > 0) {
            $or = $pdo->query(
                "SELECT CAST((strftime('%s','now') - strftime('%s', MIN(COALESCE(leased_at, updated_at, created_at)))) AS INTEGER)
                 FROM worker_jobs WHERE status = 'running'"
            )->fetchColumn();
            $out['oldest_running_age_sec'] = max(0, (int) ($or ?: 0));
        }

        $out['recent_failed_jobs_24h'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM worker_jobs WHERE status = 'failed' AND finished_at IS NOT NULL
             AND datetime(finished_at) >= datetime('now', '-1 day')"
        )->fetchColumn();

        if ($evTbl) {
            $out['recent_error_events_24h'] = (int) $pdo->query(
                "SELECT COUNT(*) FROM worker_job_events
                 WHERE datetime(created_at) >= datetime('now', '-1 day')
                 AND lower(level) IN ('error', 'warn')"
            )->fetchColumn();
        }

        $lastJob = $pdo->query(
            "SELECT error_message FROM worker_jobs
             WHERE error_message IS NOT NULL AND TRIM(error_message) != ''
             ORDER BY COALESCE(finished_at, updated_at) DESC LIMIT 1"
        )->fetchColumn();
        $lastEv = null;
        if ($evTbl) {
            $lastEv = $pdo->query(
                "SELECT message FROM worker_job_events
                 WHERE message IS NOT NULL AND TRIM(message) != '' AND lower(level) = 'error'
                 ORDER BY created_at DESC LIMIT 1"
            )->fetchColumn();
        }
        $pick = is_string($lastJob) && trim($lastJob) !== '' ? trim((string) $lastJob) : null;
        if ($pick === null && is_string($lastEv) && trim($lastEv) !== '') {
            $pick = trim((string) $lastEv);
        }
        if ($pick !== null) {
            $out['last_error_message'] = st_worker_safe_message($pick, 500);
        }

        $hints = [];
        if ($out['stale_heartbeat_count'] > 0) {
            $hints[] = $out['stale_heartbeat_count'] . ' worker node(s) have no heartbeat within the last ' . (int) ($staleHbSec / 60) . ' minutes.';
        }
        if ($out['failed_jobs'] > 0) {
            $hints[] = $out['failed_jobs'] . ' job(s) in failed state.';
        }
        if ($out['retrying_jobs'] > 0) {
            $hints[] = $out['retrying_jobs'] . ' job(s) in retrying state.';
        }
        if ($out['queued_jobs'] > 0 && $out['oldest_queued_age_sec'] !== null && $out['oldest_queued_age_sec'] >= $warnQueuedSec) {
            $hints[] = 'Oldest queued worker job is about ' . (int) round($out['oldest_queued_age_sec'] / 60) . ' minutes old.';
        }
        if ($out['running_jobs'] > 0 && $out['oldest_running_age_sec'] !== null && $out['oldest_running_age_sec'] >= $warnRunningSec) {
            $hints[] = 'A worker job has been running for about ' . (int) round($out['oldest_running_age_sec'] / 3600) . ' hour(s) without finishing.';
        }
        if ($out['recent_failed_jobs_24h'] > 0) {
            $hints[] = $out['recent_failed_jobs_24h'] . ' worker job(s) failed in the last 24 hours.';
        }
        if ($out['recent_error_events_24h'] > 0) {
            $hints[] = $out['recent_error_events_24h'] . ' worker job event(s) at warn/error level in the last 24 hours.';
        }

        $out['warning_hints'] = array_values(array_unique($hints));

        $severe = ($out['failed_jobs'] >= $errorFailedTotal)
            || ($out['recent_failed_jobs_24h'] >= $errorRecentFailed24h)
            || ($out['recent_error_events_24h'] >= $errorRecentEvents24h)
            || ($out['queued_jobs'] > 0 && $out['oldest_queued_age_sec'] !== null && $out['oldest_queued_age_sec'] >= $errorQueuedStuckSec);

        if ($severe) {
            $out['status'] = 'error';
        } elseif ($out['warning_hints'] !== []) {
            $out['status'] = 'warn';
        } else {
            $out['status'] = 'ok';
        }

        if ($out['status'] === 'ok') {
            $out['summary'] = 'Worker substrate is ready; no actionable backlog or liveness issues.';
            if (
                $out['queued_jobs'] + $out['leased_jobs'] + $out['running_jobs'] + $out['retrying_jobs']
                + $out['failed_jobs'] + $out['cancelled_jobs'] + $out['node_count'] === 0
            ) {
                $out['summary'] = 'Worker substrate is ready (idle — no jobs or nodes recorded yet).';
            }
        } elseif ($out['status'] === 'warn') {
            $out['summary'] = 'Worker substrate needs review: ' . ($out['warning_hints'][0] ?? 'see warning hints.');
        } else {
            $out['summary'] = 'Worker substrate reports elevated failures or backlog — investigate job events and worker processes.';
        }
        $out['summary'] = st_worker_safe_message($out['summary'], 400);
    } catch (Throwable) {
        return [
            'tables_ready'            => false,
            'node_count'              => 0,
            'heartbeat_count'         => 0,
            'stale_heartbeat_count'   => 0,
            'queued_jobs'             => 0,
            'leased_jobs'             => 0,
            'running_jobs'            => 0,
            'retrying_jobs'           => 0,
            'failed_jobs'             => 0,
            'cancelled_jobs'          => 0,
            'oldest_queued_age_sec'   => null,
            'oldest_running_age_sec'  => null,
            'recent_failed_jobs_24h'  => 0,
            'recent_error_events_24h' => 0,
            'last_error_message'      => null,
            'status'                  => 'unavailable',
            'summary'                 => 'Worker substrate health could not be read (temporary database error).',
            'warning_hints'           => [],
        ];
    }

    return $out;
}

// ---------------------------------------------------------------------------
// Collector ingest → worker_jobs mirror (observability only)
// ---------------------------------------------------------------------------

/**
 * @return array<string, mixed>|null
 */
function st_worker_mirror_collector_build_payload(PDO $pdo, int $collectorId, int $jobId, string $submissionId): ?array
{
    try {
        $st = $pdo->prepare(
            'SELECT id, chunk_count, received_chunks, processed_chunks, status
             FROM collector_submissions WHERE collector_id = ? AND job_id = ? AND submission_id = ? LIMIT 1'
        );
        $st->execute([$collectorId, $jobId, $submissionId]);
        $r = $st->fetch(PDO::FETCH_ASSOC);
        if (! is_array($r)) {
            return null;
        }
        $q = $pdo->prepare(
            "SELECT
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_chunks,
                SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END) AS applied_chunks,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_chunks
             FROM collector_ingest_queue
             WHERE collector_id = ? AND job_id = ? AND submission_id = ?"
        );
        $q->execute([$collectorId, $jobId, $submissionId]);
        $qcRow = $q->fetch(PDO::FETCH_ASSOC);
        $qc = is_array($qcRow) ? $qcRow : [];

        return [
            'mirror'                    => 'collector_ingest_v1',
            'collector_id'              => $collectorId,
            'scan_job_id'               => $jobId,
            'submission_id'             => $submissionId,
            'collector_submission_pk'   => (int) ($r['id'] ?? 0),
            'chunk_count'               => (int) ($r['chunk_count'] ?? 0),
            'received_chunks'           => (int) ($r['received_chunks'] ?? 0),
            'processed_chunks'          => (int) ($r['processed_chunks'] ?? 0),
            'submission_status'        => (string) ($r['status'] ?? ''),
            'ingest_queue_pending'      => (int) ($qc['pending_chunks'] ?? 0),
            'ingest_queue_applied'      => (int) ($qc['applied_chunks'] ?? 0),
            'ingest_queue_failed'       => (int) ($qc['failed_chunks'] ?? 0),
        ];
    } catch (Throwable) {
        return null;
    }
}

/**
 * Upsert one mirror worker_jobs row keyed by collector_submissions.id (entity_id).
 *
 * @param array<string, mixed>|null $payload
 */
function st_worker_mirror_collector_ensure_job(
    PDO $pdo,
    int $submissionPk,
    int $collectorId,
    int $jobId,
    string $submissionId,
    ?array $payload = null
): int {
    if (! st_worker_tables_ready($pdo) || $submissionPk < 1) {
        return 0;
    }
    $payload = $payload ?? st_worker_mirror_collector_build_payload($pdo, $collectorId, $jobId, $submissionId);
    if ($payload === null) {
        return 0;
    }
    $pj = st_worker_json_encode($payload);
    if ($pj === null) {
        return 0;
    }
    try {
        $sel = $pdo->prepare(
            "SELECT id FROM worker_jobs WHERE job_type = 'collector_ingest' AND entity_type = 'collector_submission' AND entity_id = ? LIMIT 1"
        );
        $sel->execute([$submissionPk]);
        $id = (int) $sel->fetchColumn();
        if ($id > 0) {
            $pdo->prepare('UPDATE worker_jobs SET payload_json = ?, updated_at = datetime(\'now\') WHERE id = ?')->execute([$pj, $id]);

            return $id;
        }
        $ins = $pdo->prepare(
            "INSERT INTO worker_jobs (job_type, entity_type, entity_id, status, priority, max_attempts, payload_json, created_at, updated_at)
             VALUES ('collector_ingest', 'collector_submission', ?, 'queued', 0, 8, ?, datetime('now'), datetime('now'))"
        );
        $ins->execute([$submissionPk, $pj]);
        $newId = (int) $pdo->lastInsertId();
        if ($newId > 0) {
            return $newId;
        }
        // Race: another writer inserted the same entity; resolve by re-select.
        $sel->execute([$submissionPk]);
        $id = (int) $sel->fetchColumn();

        return $id > 0 ? $id : 0;
    } catch (Throwable) {
        try {
            $sel = $pdo->prepare(
                "SELECT id FROM worker_jobs WHERE job_type = 'collector_ingest' AND entity_type = 'collector_submission' AND entity_id = ? LIMIT 1"
            );
            $sel->execute([$submissionPk]);
            $id = (int) $sel->fetchColumn();

            return $id > 0 ? $id : 0;
        } catch (Throwable) {
            return 0;
        }
    }
}

/**
 * Best-effort mirror after collector_submit.php commits queue rows.
 */
function st_worker_mirror_collector_after_submit(
    PDO $pdo,
    int $collectorId,
    int $jobId,
    string $submissionId,
    int $chunkIndex,
    int $chunkCount,
    bool $submissionComplete
): void {
    if (! st_worker_tables_ready($pdo)) {
        return;
    }
    try {
        $pkStmt = $pdo->prepare(
            'SELECT id FROM collector_submissions WHERE collector_id = ? AND job_id = ? AND submission_id = ? LIMIT 1'
        );
        $pkStmt->execute([$collectorId, $jobId, $submissionId]);
        $pk = (int) $pkStmt->fetchColumn();
        if ($pk < 1) {
            return;
        }
        $payload = st_worker_mirror_collector_build_payload($pdo, $collectorId, $jobId, $submissionId);
        if ($payload === null) {
            return;
        }
        $payload['last_chunk_index'] = $chunkIndex;
        $payload['last_chunk_count'] = $chunkCount;
        $wj = st_worker_mirror_collector_ensure_job($pdo, $pk, $collectorId, $jobId, $submissionId, $payload);
        if ($wj < 1) {
            return;
        }
        st_worker_log_event($pdo, [
            'job_id'       => $wj,
            'event_type'   => 'collector_mirror_chunk_queued',
            'level'        => 'info',
            'message'      => 'Collector chunk stored; queued for master ingest.',
            'details_json' => [
                'chunk_index' => $chunkIndex,
                'chunk_count' => $chunkCount,
            ],
        ]);
        if ($submissionComplete) {
            st_worker_log_event($pdo, [
                'job_id'       => $wj,
                'event_type'   => 'collector_mirror_all_chunks_received',
                'level'        => 'info',
                'message'      => 'All chunks received on master; awaiting ingest worker.',
                'details_json' => [
                    'received_chunks' => (int) ($payload['received_chunks'] ?? 0),
                    'chunk_count'     => (int) ($payload['chunk_count'] ?? 0),
                ],
            ]);
        }
    } catch (Throwable) {
        // mirror must never break submit
    }
}
