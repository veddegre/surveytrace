#!/usr/bin/env php
<?php
/**
 * Manual operational history prune utility (dry-run by default).
 *
 * Usage:
 *   php scripts/prune_operational_history.php [--apply] [--db=/path/to/surveytrace.db]
 *     [--older-than-days=90] [--table=name] [--include-runs] [--vacuum] [--vacuum-advice]
 */
declare(strict_types=1);

const ST_PRUNE_ACTION = 'maintenance.prune_operational_history';
const ST_PRUNE_ACTOR = 'system_maintenance';
const ST_PRUNE_TABLES_DEFAULT = [
    'worker_job_events',
    'worker_job_attempts',
    'credential_check_artifacts',
    'credential_check_results',
    'reconciliation_runs',
];
const ST_PRUNE_TABLES_INCLUDE_RUNS = [
    'worker_job_events',
    'worker_job_attempts',
    'worker_jobs',
    'credential_check_artifacts',
    'credential_check_results',
    'credential_check_run_targets',
    'credential_check_runs',
    'reconciliation_runs',
];
const ST_PRUNE_TERMINAL_STATES = ['completed', 'failed', 'cancelled', 'expired'];

/**
 * @return array{
 *   apply:bool,
 *   db_path:string,
 *   older_days:int,
 *   table:string,
 *   include_runs:bool,
 *   vacuum:bool,
 *   vacuum_advice:bool
 * }
 */
function st_prune_parse_args(array $argv): array
{
    $out = [
        'apply' => false,
        'db_path' => dirname(__DIR__) . '/data/surveytrace.db',
        'older_days' => 90,
        'table' => '',
        'include_runs' => false,
        'vacuum' => false,
        'vacuum_advice' => false,
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
        if ($arg === '--include-runs') {
            $out['include_runs'] = true;
            continue;
        }
        if ($arg === '--vacuum') {
            $out['vacuum'] = true;
            continue;
        }
        if ($arg === '--vacuum-advice') {
            $out['vacuum_advice'] = true;
            continue;
        }
        if (str_starts_with($arg, '--db=')) {
            $out['db_path'] = (string) substr($arg, strlen('--db='));
            continue;
        }
        if (str_starts_with($arg, '--older-than-days=')) {
            $out['older_days'] = max(1, (int) substr($arg, strlen('--older-than-days=')));
            continue;
        }
        if (str_starts_with($arg, '--table=')) {
            $out['table'] = trim((string) substr($arg, strlen('--table=')));
            continue;
        }
        if ($arg === '--help' || $arg === '-h') {
            fwrite(STDOUT, "Usage: php scripts/prune_operational_history.php [--apply] [--db=/path/to/db] [--older-than-days=90] [--table=name] [--include-runs] [--vacuum] [--vacuum-advice]\n");
            exit(0);
        }
        fwrite(STDERR, "Unknown argument: {$arg}\n");
        exit(2);
    }

    return $out;
}

function st_prune_open_db(string $dbPath): PDO
{
    return new PDO('sqlite:' . $dbPath, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
}

function st_prune_has_table(PDO $pdo, string $name): bool
{
    $st = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1");
    $st->execute([$name]);
    $v = $st->fetchColumn();

    return $v !== false && $v !== null;
}

/**
 * @return list<string>
 */
function st_prune_selected_tables(string $table, bool $includeRuns): array
{
    $allowed = $includeRuns ? ST_PRUNE_TABLES_INCLUDE_RUNS : ST_PRUNE_TABLES_DEFAULT;
    if ($table === '') {
        return $allowed;
    }
    if (! in_array($table, ST_PRUNE_TABLES_INCLUDE_RUNS, true)) {
        fwrite(STDERR, "Invalid --table value: {$table}\n");
        exit(2);
    }

    return [$table];
}

/**
 * @param list<int> $ids
 */
function st_prune_count_in_ids(PDO $pdo, string $sqlPrefix, array $ids): int
{
    if ($ids === []) {
        return 0;
    }
    $ph = implode(',', array_fill(0, count($ids), '?'));
    $st = $pdo->prepare($sqlPrefix . " ({$ph})");
    $st->execute($ids);

    return (int) $st->fetchColumn();
}

/**
 * @param list<int> $ids
 */
function st_prune_delete_in_ids(PDO $pdo, string $sqlPrefix, array $ids): int
{
    if ($ids === []) {
        return 0;
    }
    $ph = implode(',', array_fill(0, count($ids), '?'));
    $st = $pdo->prepare($sqlPrefix . " ({$ph})");
    $st->execute($ids);

    return (int) $st->rowCount();
}

/**
 * @return list<int>
 */
function st_prune_old_terminal_run_ids(PDO $pdo, string $cutoff): array
{
    $st = $pdo->prepare(
        "SELECT id
         FROM credential_check_runs
         WHERE status IN ('completed','failed','cancelled','expired')
           AND COALESCE(finished_at, started_at, '1970-01-01 00:00:00') < ?"
    );
    $st->execute([$cutoff]);

    return array_map(static fn($r) => (int) ($r['id'] ?? 0), $st->fetchAll(PDO::FETCH_ASSOC));
}

/**
 * @return list<int>
 */
function st_prune_old_terminal_worker_job_ids(PDO $pdo, string $cutoff): array
{
    $st = $pdo->prepare(
        "SELECT id
         FROM worker_jobs
         WHERE status IN ('completed','failed','cancelled','expired')
           AND COALESCE(finished_at, updated_at, created_at, '1970-01-01 00:00:00') < ?"
    );
    $st->execute([$cutoff]);

    return array_map(static fn($r) => (int) ($r['id'] ?? 0), $st->fetchAll(PDO::FETCH_ASSOC));
}

/**
 * @return array{candidate:int,deleted:int,skipped:?string}
 */
function st_prune_one(PDO $pdo, string $table, string $cutoff, bool $apply, bool $includeRuns, array $ctx): array
{
    if (! st_prune_has_table($pdo, $table)) {
        return ['candidate' => 0, 'deleted' => 0, 'skipped' => 'table_missing'];
    }

    switch ($table) {
        case 'worker_job_events':
            if ($includeRuns && isset($ctx['old_worker_job_ids']) && is_array($ctx['old_worker_job_ids'])) {
                $ids = $ctx['old_worker_job_ids'];
                $candidate = st_prune_count_in_ids($pdo, 'SELECT COUNT(*) FROM worker_job_events WHERE job_id IN', $ids);
                $deleted = 0;
                if ($apply && $candidate > 0) {
                    $deleted = st_prune_delete_in_ids($pdo, 'DELETE FROM worker_job_events WHERE job_id IN', $ids);
                }

                return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];
            }
            $st = $pdo->prepare(
                "SELECT COUNT(*)
                 FROM worker_job_events e
                 LEFT JOIN worker_jobs j ON j.id = e.job_id
                 WHERE e.created_at < ?
                   AND (j.id IS NULL OR j.status IN ('completed','failed','cancelled','expired'))"
            );
            $st->execute([$cutoff]);
            $candidate = (int) $st->fetchColumn();
            $deleted = 0;
            if ($apply && $candidate > 0) {
                $del = $pdo->prepare(
                    "DELETE FROM worker_job_events
                     WHERE id IN (
                       SELECT e.id
                       FROM worker_job_events e
                       LEFT JOIN worker_jobs j ON j.id = e.job_id
                       WHERE e.created_at < ?
                         AND (j.id IS NULL OR j.status IN ('completed','failed','cancelled','expired'))
                     )"
                );
                $del->execute([$cutoff]);
                $deleted = (int) $del->rowCount();
            }

            return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];

        case 'worker_job_attempts':
            if ($includeRuns && isset($ctx['old_worker_job_ids']) && is_array($ctx['old_worker_job_ids'])) {
                $ids = $ctx['old_worker_job_ids'];
                $candidate = st_prune_count_in_ids($pdo, 'SELECT COUNT(*) FROM worker_job_attempts WHERE job_id IN', $ids);
                $deleted = 0;
                if ($apply && $candidate > 0) {
                    $deleted = st_prune_delete_in_ids($pdo, 'DELETE FROM worker_job_attempts WHERE job_id IN', $ids);
                }

                return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];
            }
            $st = $pdo->prepare(
                "SELECT COUNT(*)
                 FROM worker_job_attempts a
                 LEFT JOIN worker_jobs j ON j.id = a.job_id
                 WHERE COALESCE(a.finished_at, a.started_at, '1970-01-01 00:00:00') < ?
                   AND (j.id IS NULL OR j.status IN ('completed','failed','cancelled','expired'))"
            );
            $st->execute([$cutoff]);
            $candidate = (int) $st->fetchColumn();
            $deleted = 0;
            if ($apply && $candidate > 0) {
                $del = $pdo->prepare(
                    "DELETE FROM worker_job_attempts
                     WHERE id IN (
                       SELECT a.id
                       FROM worker_job_attempts a
                       LEFT JOIN worker_jobs j ON j.id = a.job_id
                       WHERE COALESCE(a.finished_at, a.started_at, '1970-01-01 00:00:00') < ?
                         AND (j.id IS NULL OR j.status IN ('completed','failed','cancelled','expired'))
                     )"
                );
                $del->execute([$cutoff]);
                $deleted = (int) $del->rowCount();
            }

            return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];

        case 'credential_check_artifacts':
            if ($includeRuns && isset($ctx['old_run_ids']) && is_array($ctx['old_run_ids'])) {
                $ids = $ctx['old_run_ids'];
                $candidate = 0;
                if ($ids !== []) {
                    $ph = implode(',', array_fill(0, count($ids), '?'));
                    $stc = $pdo->prepare(
                        "SELECT COUNT(*)
                         FROM credential_check_artifacts
                         WHERE result_id IN (
                           SELECT id FROM credential_check_results WHERE run_id IN ({$ph})
                         )"
                    );
                    $stc->execute($ids);
                    $candidate = (int) $stc->fetchColumn();
                }
                $deleted = 0;
                if ($apply && $candidate > 0) {
                    $ph = implode(',', array_fill(0, count($ids), '?'));
                    $std = $pdo->prepare(
                        "DELETE FROM credential_check_artifacts
                         WHERE result_id IN (
                           SELECT id FROM credential_check_results WHERE run_id IN ({$ph})
                         )"
                    );
                    $std->execute($ids);
                    $deleted = (int) $std->rowCount();
                }

                return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];
            }
            $st = $pdo->prepare(
                "SELECT COUNT(*)
                 FROM credential_check_artifacts a
                 LEFT JOIN credential_check_results r ON r.id = a.result_id
                 LEFT JOIN credential_check_runs run ON run.id = r.run_id
                 WHERE a.created_at < ?
                   AND (
                     r.id IS NULL
                     OR run.id IS NULL
                     OR run.status IN ('completed','failed','cancelled','expired')
                   )"
            );
            $st->execute([$cutoff]);
            $candidate = (int) $st->fetchColumn();
            $deleted = 0;
            if ($apply && $candidate > 0) {
                $del = $pdo->prepare(
                    "DELETE FROM credential_check_artifacts
                     WHERE id IN (
                       SELECT a.id
                       FROM credential_check_artifacts a
                       LEFT JOIN credential_check_results r ON r.id = a.result_id
                       LEFT JOIN credential_check_runs run ON run.id = r.run_id
                       WHERE a.created_at < ?
                         AND (
                           r.id IS NULL
                           OR run.id IS NULL
                           OR run.status IN ('completed','failed','cancelled','expired')
                         )
                     )"
                );
                $del->execute([$cutoff]);
                $deleted = (int) $del->rowCount();
            }

            return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];

        case 'credential_check_results':
            if ($includeRuns && isset($ctx['old_run_ids']) && is_array($ctx['old_run_ids'])) {
                $ids = $ctx['old_run_ids'];
                $candidate = st_prune_count_in_ids($pdo, 'SELECT COUNT(*) FROM credential_check_results WHERE run_id IN', $ids);
                $deleted = 0;
                if ($apply && $candidate > 0) {
                    $deleted = st_prune_delete_in_ids($pdo, 'DELETE FROM credential_check_results WHERE run_id IN', $ids);
                }

                return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];
            }
            $st = $pdo->prepare(
                "SELECT COUNT(*)
                 FROM credential_check_results r
                 LEFT JOIN credential_check_runs run ON run.id = r.run_id
                 WHERE r.created_at < ?
                   AND (
                     run.id IS NULL
                     OR run.status IN ('completed','failed','cancelled','expired')
                   )"
            );
            $st->execute([$cutoff]);
            $candidate = (int) $st->fetchColumn();
            $deleted = 0;
            if ($apply && $candidate > 0) {
                $del = $pdo->prepare(
                    "DELETE FROM credential_check_results
                     WHERE id IN (
                       SELECT r.id
                       FROM credential_check_results r
                       LEFT JOIN credential_check_runs run ON run.id = r.run_id
                       WHERE r.created_at < ?
                         AND (
                           run.id IS NULL
                           OR run.status IN ('completed','failed','cancelled','expired')
                         )
                     )"
                );
                $del->execute([$cutoff]);
                $deleted = (int) $del->rowCount();
            }

            return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];

        case 'reconciliation_runs':
            $st = $pdo->prepare(
                "SELECT COUNT(*) FROM reconciliation_runs
                 WHERE COALESCE(finished_at, started_at, '1970-01-01 00:00:00') < ?"
            );
            $st->execute([$cutoff]);
            $candidate = (int) $st->fetchColumn();
            $deleted = 0;
            if ($apply && $candidate > 0) {
                $del = $pdo->prepare(
                    "DELETE FROM reconciliation_runs
                     WHERE COALESCE(finished_at, started_at, '1970-01-01 00:00:00') < ?"
                );
                $del->execute([$cutoff]);
                $deleted = (int) $del->rowCount();
            }

            return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];

        case 'credential_check_run_targets':
            if (! $includeRuns) {
                return ['candidate' => 0, 'deleted' => 0, 'skipped' => 'requires_include_runs'];
            }
            $ids = isset($ctx['old_run_ids']) && is_array($ctx['old_run_ids']) ? $ctx['old_run_ids'] : [];
            $candidate = st_prune_count_in_ids($pdo, 'SELECT COUNT(*) FROM credential_check_run_targets WHERE run_id IN', $ids);
            $deleted = 0;
            if ($apply && $candidate > 0) {
                $deleted = st_prune_delete_in_ids($pdo, 'DELETE FROM credential_check_run_targets WHERE run_id IN', $ids);
            }

            return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];

        case 'credential_check_runs':
            if (! $includeRuns) {
                return ['candidate' => 0, 'deleted' => 0, 'skipped' => 'requires_include_runs'];
            }
            $ids = isset($ctx['old_run_ids']) && is_array($ctx['old_run_ids']) ? $ctx['old_run_ids'] : [];
            $candidate = count($ids);
            $deleted = 0;
            if ($apply && $candidate > 0) {
                $deleted = st_prune_delete_in_ids($pdo, 'DELETE FROM credential_check_runs WHERE id IN', $ids);
            }

            return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];

        case 'worker_jobs':
            if (! $includeRuns) {
                return ['candidate' => 0, 'deleted' => 0, 'skipped' => 'requires_include_runs'];
            }
            $ids = isset($ctx['old_worker_job_ids']) && is_array($ctx['old_worker_job_ids']) ? $ctx['old_worker_job_ids'] : [];
            $candidate = count($ids);
            $deleted = 0;
            if ($apply && $candidate > 0) {
                $deleted = st_prune_delete_in_ids($pdo, 'DELETE FROM worker_jobs WHERE id IN', $ids);
            }

            return ['candidate' => $candidate, 'deleted' => $deleted, 'skipped' => null];
    }

    return ['candidate' => 0, 'deleted' => 0, 'skipped' => 'unhandled_table'];
}

function st_prune_audit_row(PDO $pdo, array $details): void
{
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS user_audit_log (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id    INTEGER,
            actor_username   TEXT,
            target_user_id   INTEGER,
            target_username  TEXT,
            action           TEXT NOT NULL,
            details_json     TEXT,
            source_ip        TEXT,
            created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );
    $enc = json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $st = $pdo->prepare(
        "INSERT INTO user_audit_log
         (actor_user_id, actor_username, target_user_id, target_username, action, details_json, source_ip)
         VALUES (NULL, ?, NULL, NULL, ?, ?, '127.0.0.1')"
    );
    $st->execute([ST_PRUNE_ACTOR, ST_PRUNE_ACTION, $enc !== false ? $enc : null]);
}

$opt = st_prune_parse_args($argv);
$tables = st_prune_selected_tables($opt['table'], $opt['include_runs']);
$cutoffTs = time() - ($opt['older_days'] * 86400);
$cutoff = gmdate('Y-m-d H:i:s', $cutoffTs);

try {
    $pdo = st_prune_open_db($opt['db_path']);
    $pdo->exec('PRAGMA busy_timeout = 60000');
} catch (Throwable) {
    fwrite(STDERR, "FAIL: unable to open database.\n");
    exit(1);
}

$ctx = [];
if ($opt['include_runs']) {
    if (in_array('credential_check_runs', ST_PRUNE_TABLES_INCLUDE_RUNS, true) && st_prune_has_table($pdo, 'credential_check_runs')) {
        $ctx['old_run_ids'] = st_prune_old_terminal_run_ids($pdo, $cutoff);
    } else {
        $ctx['old_run_ids'] = [];
    }
    if (in_array('worker_jobs', ST_PRUNE_TABLES_INCLUDE_RUNS, true) && st_prune_has_table($pdo, 'worker_jobs')) {
        $ctx['old_worker_job_ids'] = st_prune_old_terminal_worker_job_ids($pdo, $cutoff);
    } else {
        $ctx['old_worker_job_ids'] = [];
    }
}

$resultRows = [];
$deletedCounts = [];
$candidateCounts = [];
$order = [
    'worker_job_events',
    'worker_job_attempts',
    'credential_check_artifacts',
    'credential_check_results',
    'credential_check_run_targets',
    'credential_check_runs',
    'worker_jobs',
    'reconciliation_runs',
];
$selectedOrdered = array_values(array_filter($order, static fn($t) => in_array($t, $tables, true)));

if ($opt['apply']) {
    $pdo->beginTransaction();
}
try {
    foreach ($selectedOrdered as $table) {
        $r = st_prune_one($pdo, $table, $cutoff, $opt['apply'], $opt['include_runs'], $ctx);
        $resultRows[] = [
            'table' => $table,
            'cutoff_utc' => $cutoff,
            'candidate_rows' => $r['candidate'],
            'deleted_rows' => $r['deleted'],
            'skipped_reason' => $r['skipped'],
        ];
        $deletedCounts[$table] = (int) $r['deleted'];
        $candidateCounts[$table] = (int) $r['candidate'];
    }
    if ($opt['apply']) {
        st_prune_audit_row($pdo, [
            'cutoff_utc' => $cutoff,
            'older_than_days' => $opt['older_days'],
            'tables' => $selectedOrdered,
            'candidate_counts' => $candidateCounts,
            'deleted_counts' => $deletedCounts,
            'include_runs' => $opt['include_runs'],
            'vacuum_requested' => $opt['vacuum'],
        ]);
        $pdo->commit();
    }
} catch (Throwable $e) {
    if ($opt['apply'] && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    $dbg = getenv('ST_PRUNE_DEBUG');
    if (is_string($dbg) && $dbg === '1') {
        fwrite(STDERR, "FAIL: prune execution failed safely: " . $e->getMessage() . "\n");
    } else {
        fwrite(STDERR, "FAIL: prune execution failed safely.\n");
    }
    exit(1);
}

$vacuumResult = 'not_requested';
if ($opt['vacuum']) {
    if (! $opt['apply']) {
        $vacuumResult = 'requires_apply';
    } else {
        try {
            $pdo->exec('VACUUM');
            $vacuumResult = 'done';
        } catch (Throwable) {
            $vacuumResult = 'failed';
        }
    }
}

fwrite(STDOUT, json_encode([
    'ok' => true,
    'mode' => $opt['apply'] ? 'apply' : 'dry_run',
    'db_path' => $opt['db_path'],
    'older_than_days' => $opt['older_days'],
    'include_runs' => $opt['include_runs'],
    'tables' => $resultRows,
    'vacuum' => [
        'requested' => $opt['vacuum'],
        'result' => $vacuumResult,
        'advice' => $opt['vacuum_advice'] ? 'vacuum can reclaim file space but may take a write lock; run during maintenance windows.' : null,
    ],
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n");

exit(0);
