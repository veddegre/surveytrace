#!/usr/bin/env php
<?php
/**
 * Prune credentialed-check runtime rows (results, artifacts, run targets, runs, related worker rows).
 *
 * Default: dry-run. Does not touch user_audit_log except to append one maintenance row on --apply.
 *
 * Policy:
 * - Never deletes non-terminal worker_jobs or credential_check_runs.
 * - Preserves the N most recent credential_check_runs by id (see --keep-runs).
 * - Only deletes terminal runs finished (or last activity) before cutoff = now - days.
 *
 * Usage:
 *   php scripts/prune_credential_runtime_history.php [--apply] [--db=PATH] [--days=90] [--keep-runs=50]
 */
declare(strict_types=1);

const ST_CRED_PRUNE_ACTOR = 'system_maintenance';
const ST_CRED_PRUNE_ACTION = 'maintenance.prune_credential_runtime_history';

/**
 * @return array{apply:bool,db_path:string,days:int,keep_runs:int}
 */
function st_cred_prune_parse(array $argv): array
{
    $o = ['apply' => false, 'db_path' => dirname(__DIR__) . '/data/surveytrace.db', 'days' => 90, 'keep_runs' => 50];
    foreach (array_slice($argv, 1) as $a) {
        if ($a === '--apply') {
            $o['apply'] = true;
            continue;
        }
        if ($a === '--dry-run') {
            $o['apply'] = false;
            continue;
        }
        if (str_starts_with($a, '--db=')) {
            $o['db_path'] = (string) substr($a, 5);
            continue;
        }
        if (str_starts_with($a, '--days=')) {
            $o['days'] = max(1, (int) substr($a, 7));
            continue;
        }
        if (str_starts_with($a, '--keep-runs=')) {
            $o['keep_runs'] = max(1, (int) substr($a, 12));
            continue;
        }
        if ($a === '-h' || $a === '--help') {
            fwrite(STDOUT, "Usage: php scripts/prune_credential_runtime_history.php [--apply] [--db=...] [--days=90] [--keep-runs=50]\n");
            exit(0);
        }
        fwrite(STDERR, "Unknown arg: {$a}\n");
        exit(2);
    }

    return $o;
}

function st_cred_prune_has(PDO $pdo, string $t): bool
{
    $st = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1");
    $st->execute([$t]);
    $v = $st->fetchColumn();

    return $v !== false && $v !== null;
}

/** @return list<int> */
function st_cred_prune_protected_run_ids(PDO $pdo, int $keep): array
{
    if (! st_cred_prune_has($pdo, 'credential_check_runs')) {
        return [];
    }
    $st = $pdo->prepare('SELECT id FROM credential_check_runs ORDER BY id DESC LIMIT ?');
    $st->bindValue(1, $keep, PDO::PARAM_INT);
    $st->execute();

    return array_map(static fn ($r) => (int) ($r['id'] ?? 0), $st->fetchAll(PDO::FETCH_ASSOC));
}

/**
 * @param list<int> $protected
 *
 * @return list<int>
 */
function st_cred_prune_candidate_run_ids(PDO $pdo, string $cutoff, array $protected): array
{
    $st = $pdo->prepare(
        "SELECT id FROM credential_check_runs
         WHERE status IN ('completed','failed','cancelled','expired')
           AND COALESCE(finished_at, started_at, '1970-01-01') < ?
         ORDER BY id ASC"
    );
    $st->execute([$cutoff]);
    $all = array_map(static fn ($r) => (int) ($r['id'] ?? 0), $st->fetchAll(PDO::FETCH_ASSOC));
    $prot = array_fill_keys($protected, true);
    $out = [];
    foreach ($all as $id) {
        if ($id > 0 && ! isset($prot[$id])) {
            $out[] = $id;
        }
    }

    return $out;
}

/**
 * @param list<int> $runIds
 *
 * @return list<int>
 */
function st_cred_prune_worker_job_ids_for_runs(PDO $pdo, array $runIds): array
{
    if ($runIds === [] || ! st_cred_prune_has($pdo, 'credential_check_runs')) {
        return [];
    }
    $ph = implode(',', array_fill(0, count($runIds), '?'));
    $st = $pdo->prepare("SELECT DISTINCT worker_job_id FROM credential_check_runs WHERE id IN ({$ph}) AND worker_job_id IS NOT NULL");
    $st->execute($runIds);
    $ids = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $j = (int) ($r['worker_job_id'] ?? 0);
        if ($j > 0) {
            $ids[] = $j;
        }
    }

    return array_values(array_unique($ids));
}

/**
 * @param list<int> $ids
 */
function st_cred_prune_delete_events_attempts(PDO $pdo, array $jobIds, bool $apply): array
{
    $delE = 0;
    $delA = 0;
    if ($jobIds === []) {
        return [$delE, $delA];
    }
    $ph = implode(',', array_fill(0, count($jobIds), '?'));
    $stc = $pdo->prepare("SELECT COUNT(*) FROM worker_job_events WHERE job_id IN ({$ph})");
    $stc->execute($jobIds);
    $candE = (int) $stc->fetchColumn();
    $stc2 = $pdo->prepare("SELECT COUNT(*) FROM worker_job_attempts WHERE job_id IN ({$ph})");
    $stc2->execute($jobIds);
    $candA = (int) $stc2->fetchColumn();
    if ($apply) {
        $pdo->prepare("DELETE FROM worker_job_events WHERE job_id IN ({$ph})")->execute($jobIds);
        $delE = $candE;
        $pdo->prepare("DELETE FROM worker_job_attempts WHERE job_id IN ({$ph})")->execute($jobIds);
        $delA = $candA;
    }

    return [$candE, $candA]; // candidates when apply=false; deleted rows when apply=true
}

$opt = st_cred_prune_parse($argv);
$cutoffTs = time() - ($opt['days'] * 86400);
$cutoff = gmdate('Y-m-d H:i:s', $cutoffTs);

try {
    $pdo = new PDO('sqlite:' . $opt['db_path'], null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA busy_timeout = 60000');
} catch (Throwable) {
    fwrite(STDERR, "FAIL: cannot open database\n");
    exit(1);
}

$protected = st_cred_prune_protected_run_ids($pdo, $opt['keep_runs']);
$candidates = st_cred_prune_candidate_run_ids($pdo, $cutoff, $protected);
$jobIds = st_cred_prune_worker_job_ids_for_runs($pdo, $candidates);

$counts = [
    'cutoff_utc' => $cutoff,
    'keep_run_ids' => $opt['keep_runs'],
    'protected_run_count' => count($protected),
    'candidate_run_ids' => count($candidates),
    'candidate_worker_job_ids' => count($jobIds),
];

$art = 0;
$res = 0;
$tgt = 0;
$runs = 0;
$jobs = 0;
if ($candidates !== []) {
    $ph = implode(',', array_fill(0, count($candidates), '?'));
    $st = $pdo->prepare(
        "SELECT COUNT(*) FROM credential_check_artifacts WHERE result_id IN (
           SELECT id FROM credential_check_results WHERE run_id IN ({$ph})
         )"
    );
    $st->execute($candidates);
    $art = (int) $st->fetchColumn();
    $st2 = $pdo->prepare("SELECT COUNT(*) FROM credential_check_results WHERE run_id IN ({$ph})");
    $st2->execute($candidates);
    $res = (int) $st2->fetchColumn();
    $st3 = $pdo->prepare("SELECT COUNT(*) FROM credential_check_run_targets WHERE run_id IN ({$ph})");
    $st3->execute($candidates);
    $tgt = (int) $st3->fetchColumn();
    $runs = count($candidates);
}

$terminalJobs = [];
foreach ($jobIds as $jid) {
    $r = $pdo->prepare('SELECT status FROM worker_jobs WHERE id = ? LIMIT 1');
    $r->execute([$jid]);
    $stt = (string) ($r->fetchColumn() ?: '');
    if (in_array($stt, ['completed', 'failed', 'cancelled', 'expired'], true)) {
        $terminalJobs[] = $jid;
    }
}
$jobs = count($terminalJobs);

[$evC, $atC] = st_cred_prune_delete_events_attempts($pdo, $terminalJobs, false);
$counts['worker_job_events'] = $evC;
$counts['worker_job_attempts'] = $atC;
$counts['credential_check_artifacts'] = $art;
$counts['credential_check_results'] = $res;
$counts['credential_check_run_targets'] = $tgt;
$counts['credential_check_runs'] = $runs;
$counts['worker_jobs_terminal'] = $jobs;

fwrite(STDOUT, json_encode(['dry_run' => ! $opt['apply'], 'plan' => $counts], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n");

if (! $opt['apply'] || $candidates === []) {
    exit(0);
}

$pdo->beginTransaction();
try {
    [$evC, $atC] = st_cred_prune_delete_events_attempts($pdo, $terminalJobs, true);
    $ph = implode(',', array_fill(0, count($candidates), '?'));
    $pdo->prepare(
        "DELETE FROM credential_check_artifacts WHERE result_id IN (
           SELECT id FROM credential_check_results WHERE run_id IN ({$ph})
         )"
    )->execute($candidates);
    $pdo->prepare("DELETE FROM credential_check_results WHERE run_id IN ({$ph})")->execute($candidates);
    $pdo->prepare("DELETE FROM credential_check_run_targets WHERE run_id IN ({$ph})")->execute($candidates);
    $pdo->prepare("DELETE FROM credential_check_runs WHERE id IN ({$ph})")->execute($candidates);
    if ($terminalJobs !== []) {
        $phj = implode(',', array_fill(0, count($terminalJobs), '?'));
        $pdo->prepare("DELETE FROM worker_jobs WHERE id IN ({$phj})")->execute($terminalJobs);
    }
    if (st_cred_prune_has($pdo, 'user_audit_log')) {
        $det = json_encode(
            [
                'mode' => ST_CRED_PRUNE_ACTION,
                'runs_deleted' => count($candidates),
                'days' => $opt['days'],
                'keep_runs' => $opt['keep_runs'],
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
        $pdo->prepare(
            "INSERT INTO user_audit_log
             (actor_user_id, actor_username, target_user_id, target_username, action, details_json, source_ip)
             VALUES (NULL, ?, NULL, NULL, ?, ?, '127.0.0.1')"
        )->execute([ST_CRED_PRUNE_ACTOR, ST_CRED_PRUNE_ACTION, $det !== false ? $det : null]);
    }
    $pdo->commit();
} catch (Throwable $e) {
    $pdo->rollBack();
    fwrite(STDERR, 'FAIL: ' . $e->getMessage() . "\n");
    exit(1);
}

fwrite(STDOUT, json_encode(['applied' => true, 'deleted_runs' => count($candidates)], JSON_UNESCAPED_SLASHES) . "\n");
exit(0);
