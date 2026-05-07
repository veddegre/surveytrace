#!/usr/bin/env php
<?php
/**
 * Smoke: Credentialed Checks placeholder-mode run (no production DB).
 *
 * Usage:
 *   php scripts/smoke_credential_checks_placeholder.php /path/to/temp.db
 *
 * Expects the DB file to exist and already contain a full schema (e.g. from
 * `sqlite3 "$DB" ".read sql/schema.sql"`). Seeds rows, calls st_cc_run_launch(),
 * runs daemon/credential_check_worker.py --once with SURVEYTRACE_DB_PATH, then asserts.
 *
 * Exits non-zero on failure. Prints PASS/FAIL summary to stderr.
 *
 * Not covered: `st_audit_log` (needs app `db.php` stack), HTTP APIs,
 * `worker_job_events` rows (success path still creates `worker_job_attempts`).
 *
 * After the happy path, exercises **cancel before lease**: second launch then
 * `st_cc_run_cancel()`, asserts run/worker_job/target terminal state, then runs
 * the worker `--once` again (no crash with only terminal jobs).
 */

declare(strict_types=1);

if ($argc < 2) {
    fwrite(STDERR, "usage: php scripts/smoke_credential_checks_placeholder.php /path/to/temp.db\n");
    exit(2);
}

$dbPath = $argv[1];
if ($dbPath === '' || ! is_file($dbPath)) {
    fwrite(STDERR, "FAIL: database file not found: {$dbPath}\n");
    exit(1);
}

$root = dirname(__DIR__);

require_once $root . '/api/lib_credentialed_checks.php';
require_once $root . '/api/lib_credential_check_ops.php';

function smoke_fail(string $msg, int $code = 1): void
{
    fwrite(STDERR, 'FAIL: ' . $msg . "\n");
    exit($code);
}

function smoke_count(PDO $pdo, string $sql): int
{
    $st = $pdo->query($sql);
    if ($st === false) {
        return -1;
    }

    return (int) $st->fetchColumn();
}

function smoke_run_worker_once(string $root, string $dbPath, string $py): void
{
    $workerScript = $root . '/daemon/credential_check_worker.py';
    if (! is_file($workerScript)) {
        smoke_fail('missing daemon/credential_check_worker.py');
    }
    $env = $_ENV;
    $env['SURVEYTRACE_DB_PATH'] = realpath($dbPath) ?: $dbPath;
    $env['SURVEYTRACE_INSTALL_DIR'] = $root;
    $env['SURVEYTRACE_CRED_CHECK_NODE_KEY'] = 'smoke_cred_placeholder';
    $env['SURVEYTRACE_CRED_CHECK_PLACEHOLDER_ONLY'] = '1';

    $cmd = [$py, $workerScript, '--once'];
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $spec, $pipes, $root . '/daemon', $env);
    if (! is_resource($proc)) {
        smoke_fail('proc_open worker failed');
    }
    if (isset($pipes[0])) {
        fclose($pipes[0]);
    }
    $stdout = isset($pipes[1]) ? stream_get_contents($pipes[1]) : '';
    $stderr = isset($pipes[2]) ? stream_get_contents($pipes[2]) : '';
    if (isset($pipes[1])) {
        fclose($pipes[1]);
    }
    if (isset($pipes[2])) {
        fclose($pipes[2]);
    }
    $rc = proc_close($proc);
    if ($rc !== 0) {
        smoke_fail('worker exit ' . $rc . ' stderr=' . trim((string) $stderr) . ' stdout=' . trim((string) $stdout));
    }
}

try {
    $pdo = new PDO('sqlite:' . $dbPath, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA foreign_keys = ON');
} catch (Throwable $e) {
    smoke_fail('open sqlite: ' . $e->getMessage());
}

$migrations = [
    'migration_worker_execution_substrate_v1'         => '1',
    'migration_credentialed_checks_v1'              => '1',
    'migration_worker_jobs_collector_mirror_unique_v1' => '1',
];
foreach ($migrations as $k => $v) {
    $pdo->prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)')->execute([$k, $v]);
}

if (! st_worker_tables_ready($pdo) || ! st_cc_ops_tables_ready($pdo)) {
    smoke_fail('substrate or cred-check tables not ready (missing migrations/tables?)');
}

st_cred_seed_builtin_plugins($pdo);

$nObs0 = smoke_count($pdo, 'SELECT COUNT(*) FROM asset_observations');
$nFind0 = smoke_count($pdo, 'SELECT COUNT(*) FROM findings');

$pdo->exec("INSERT INTO assets (ip, hostname, lifecycle_status) VALUES ('10.254.98.1', 'smoke-cred-placeholder', 'active')");
$assetId = (int) $pdo->lastInsertId();
if ($assetId < 1) {
    smoke_fail('asset insert');
}

$pdo->prepare(
    'INSERT INTO credential_profiles (name, transport, principal_json, enabled, deleted_at)
     VALUES (?, ?, ?, 1, NULL)'
)->execute(['smoke-profile', 'ssh', '{"username":"smoke-readonly"}']);

$profileId = (int) $pdo->lastInsertId();
if ($profileId < 1) {
    smoke_fail('profile insert');
}

$jobIn = [
    'name'                  => 'smoke-cred-job',
    'description'           => 'fixture',
    'credential_profile_id' => $profileId,
    'target_mode'           => 'assets',
    'target_json'           => ['asset_ids' => [$assetId]],
    'plugin_selection_json' => [
        ['plugin_key' => 'ssh.linux.os_release', 'version' => '1.0.0'],
    ],
    'policy_json'           => ['max_concurrency' => 1, 'timeout_ms' => 15000],
    'enabled'               => true,
];

[$jobId, $jErr] = st_cc_job_create($pdo, $jobIn, null);
if ($jobId < 1) {
    smoke_fail('job create: ' . ($jErr ?? 'unknown'));
}

[$ok, $lErr, $run,] = st_cc_run_launch($pdo, $jobId, 'smoke', false);
if (! $ok || ! is_array($run)) {
    smoke_fail('launch: ' . ($lErr ?? 'unknown'));
}

$runId = (int) ($run['id'] ?? 0);
$wjid = (int) ($run['worker_job_id'] ?? 0);
if ($runId < 1 || $wjid < 1) {
    smoke_fail('run or worker_job_id missing after launch');
}

$tgt = smoke_count($pdo, 'SELECT COUNT(*) FROM credential_check_run_targets WHERE run_id = ' . $runId);
if ($tgt !== 1) {
    smoke_fail("expected 1 run target, got {$tgt}");
}

$wj = smoke_count($pdo, "SELECT COUNT(*) FROM worker_jobs WHERE id = {$wjid} AND job_type = 'credentialed_check'");
if ($wj !== 1) {
    smoke_fail('worker_jobs row missing or wrong job_type');
}

$py = '';
if (isset($_ENV['PYTHON']) && is_string($_ENV['PYTHON']) && $_ENV['PYTHON'] !== '') {
    $py = $_ENV['PYTHON'];
} else {
    $which = shell_exec('command -v python3 2>/dev/null');
    $py = $which !== null ? trim($which) : '';
}
if ($py === '' || ! is_executable($py)) {
    smoke_fail('python3 not found (set PYTHON=/path/to/python3 if needed)');
}

smoke_run_worker_once($root, $dbPath, $py);

$st = $pdo->query('SELECT status FROM credential_check_runs WHERE id = ' . $runId)->fetchColumn();
if ((string) $st !== 'completed') {
    smoke_fail("run status expected completed, got " . var_export($st, true));
}

$ts = $pdo->query('SELECT status, error_code FROM credential_check_run_targets WHERE run_id = ' . $runId)->fetch(PDO::FETCH_ASSOC);
if (! is_array($ts) || ($ts['status'] ?? '') !== 'skipped' || ($ts['error_code'] ?? '') !== 'not_implemented') {
    smoke_fail('target not skipped/not_implemented: ' . json_encode($ts));
}

$wjst = $pdo->query('SELECT status FROM worker_jobs WHERE id = ' . $wjid)->fetchColumn();
if ((string) $wjst !== 'completed') {
    smoke_fail('worker_jobs not completed: ' . var_export($wjst, true));
}

$att = smoke_count($pdo, 'SELECT COUNT(*) FROM worker_job_attempts WHERE job_id = ' . $wjid);
if ($att < 1) {
    smoke_fail('expected at least one worker_job_attempt');
}

[$ok2, $lErr2, $run2,] = st_cc_run_launch($pdo, $jobId, 'smoke', false);
if (! $ok2 || ! is_array($run2)) {
    smoke_fail('second launch: ' . ($lErr2 ?? 'unknown'));
}
$run2Id = (int) ($run2['id'] ?? 0);
$wj2id = (int) ($run2['worker_job_id'] ?? 0);
if ($run2Id < 1 || $wj2id < 1) {
    smoke_fail('second run or worker_job_id missing');
}
if ($run2Id === $runId) {
    smoke_fail('second launch should create a new run row');
}

[$cok, $cerr] = st_cc_run_cancel($pdo, $run2Id, 'smoke');
if (! $cok) {
    smoke_fail('cancel run2: ' . ($cerr ?? 'unknown'));
}

$st2 = $pdo->query('SELECT status FROM credential_check_runs WHERE id = ' . $run2Id)->fetchColumn();
if ((string) $st2 !== 'cancelled') {
    smoke_fail('run2 expected cancelled, got ' . var_export($st2, true));
}
$wj2st = $pdo->query('SELECT status FROM worker_jobs WHERE id = ' . $wj2id)->fetchColumn();
if ((string) $wj2st !== 'cancelled') {
    smoke_fail('worker_jobs run2 expected cancelled, got ' . var_export($wj2st, true));
}
$ts2 = $pdo->query('SELECT status, error_code FROM credential_check_run_targets WHERE run_id = ' . $run2Id)->fetch(PDO::FETCH_ASSOC);
if (! is_array($ts2) || ($ts2['status'] ?? '') !== 'skipped' || ($ts2['error_code'] ?? '') !== 'user_cancelled') {
    smoke_fail('run2 target not skipped/user_cancelled: ' . json_encode($ts2));
}

smoke_run_worker_once($root, $dbPath, $py);

$st1again = $pdo->query('SELECT status FROM credential_check_runs WHERE id = ' . $runId)->fetchColumn();
if ((string) $st1again !== 'completed') {
    smoke_fail('first run should stay completed after cancel+worker, got ' . var_export($st1again, true));
}

if (smoke_count($pdo, 'SELECT COUNT(*) FROM credential_check_results') !== 0) {
    smoke_fail('credential_check_results should stay empty for placeholder');
}
if (smoke_count($pdo, 'SELECT COUNT(*) FROM credential_check_artifacts') !== 0) {
    smoke_fail('credential_check_artifacts should stay empty for placeholder');
}

if (smoke_count($pdo, 'SELECT COUNT(*) FROM asset_observations') !== $nObs0) {
    smoke_fail('asset_observations row count changed (placeholder must not write observations)');
}
if (smoke_count($pdo, 'SELECT COUNT(*) FROM findings') !== $nFind0) {
    smoke_fail('findings row count changed');
}

fwrite(STDERR, "PASS smoke_credential_checks_placeholder (run_id={$runId} worker_job_id={$wjid} cancelled_run_id={$run2Id})\n");
exit(0);
