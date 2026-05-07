#!/usr/bin/env php
<?php
declare(strict_types=1);

function pfail(string $msg): void
{
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

function run_cli(array $cmd, ?array $env = null): array
{
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $spec, $pipes, dirname(__DIR__), $env);
    if (! is_resource($proc)) {
        pfail('proc_open failed');
    }
    fclose($pipes[0]);
    $out = (string) stream_get_contents($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $rc = proc_close($proc);

    return [$rc, $out, $err];
}

function jget(array $payload, string $table, string $key): int
{
    $rows = $payload['tables'] ?? [];
    if (! is_array($rows)) {
        return -1;
    }
    foreach ($rows as $r) {
        if (is_array($r) && (($r['table'] ?? '') === $table)) {
            return (int) ($r[$key] ?? -1);
        }
    }

    return -1;
}

$tmpDir = sys_get_temp_dir() . '/st_prune_' . bin2hex(random_bytes(4));
if (! mkdir($tmpDir, 0700, true) && ! is_dir($tmpDir)) {
    pfail('tmp dir create failed');
}
$db = $tmpDir . '/test.db';
$schema = dirname(__DIR__) . '/sql/schema.sql';
$sql = @file_get_contents($schema);
if (! is_string($sql) || $sql === '') {
    pfail('schema read failed');
}

try {
    $pdo = new PDO('sqlite:' . $db, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec($sql);
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
} catch (Throwable $e) {
    pfail('db bootstrap failed: ' . $e->getMessage());
}

$pdo->exec("INSERT INTO worker_jobs (job_type, status, created_at, updated_at, finished_at) VALUES
('credentialed_check','completed', datetime('now','-150 days'), datetime('now','-150 days'), datetime('now','-150 days')),
('credentialed_check','running', datetime('now','-150 days'), datetime('now','-1 day'), NULL)");
$jobOld = (int) $pdo->lastInsertId() - 1;
$jobActive = (int) $pdo->lastInsertId();

$pdo->exec("INSERT INTO worker_job_attempts (job_id, attempt_no, status, started_at, finished_at) VALUES
({$jobOld},1,'failed',datetime('now','-140 days'),datetime('now','-140 days')),
({$jobActive},1,'running',datetime('now','-1 day'),NULL)");
$pdo->exec("INSERT INTO worker_job_events (job_id, event_type, level, created_at) VALUES
({$jobOld},'done','info',datetime('now','-140 days')),
({$jobActive},'tick','info',datetime('now','-1 day'))");

$pdo->exec("INSERT INTO credential_check_runs (status, started_at, finished_at) VALUES
('completed', datetime('now','-140 days'), datetime('now','-140 days')),
('running', datetime('now','-1 day'), NULL)");
$runOld = (int) $pdo->lastInsertId() - 1;
$runActive = (int) $pdo->lastInsertId();

$pdo->exec("INSERT INTO credential_check_run_targets (run_id, asset_id, status, started_at, finished_at) VALUES
({$runOld},1,'completed',datetime('now','-140 days'),datetime('now','-140 days')),
({$runActive},1,'running',datetime('now','-1 day'),NULL)");
$targetOld = (int) $pdo->lastInsertId() - 1;
$targetActive = (int) $pdo->lastInsertId();

$pdo->exec("INSERT INTO credential_check_results (run_id, target_id, asset_id, plugin_key, plugin_version, status, created_at) VALUES
({$runOld},{$targetOld},1,'ssh.linux.os_release','1.0.0','failed',datetime('now','-140 days')),
({$runActive},{$targetActive},1,'ssh.linux.os_release','1.0.0','success',datetime('now','-1 day'))");
$resultOld = (int) $pdo->lastInsertId() - 1;
$resultActive = (int) $pdo->lastInsertId();

$pdo->exec("INSERT INTO credential_check_artifacts (result_id, kind, storage_path, size_bytes, created_at) VALUES
({$resultOld},'stdout','/tmp/a',100,datetime('now','-140 days')),
({$resultActive},'stdout','/tmp/b',100,datetime('now','-1 day'))");

$pdo->exec("INSERT INTO reconciliation_runs (entity_type, entity_id, slice_key, status, started_at, finished_at) VALUES
('asset',1,'os_platform','ok',datetime('now','-140 days'),datetime('now','-140 days')),
('asset',1,'os_platform','ok',datetime('now','-1 day'),datetime('now','-1 day'))");

$script = dirname(__DIR__) . '/scripts/prune_operational_history.php';

[$rcDry, $outDry, $errDry] = run_cli([PHP_BINARY, $script, '--db=' . $db, '--older-than-days=90']);
if ($rcDry !== 0) {
    pfail('dry-run failed: ' . trim($errDry));
}
$dry = json_decode($outDry, true);
if (! is_array($dry)) {
    pfail('dry-run json parse failed');
}
if (jget($dry, 'worker_job_events', 'candidate_rows') < 1) {
    pfail('dry-run expected worker_job_events candidates');
}
if ((int) $pdo->query('SELECT COUNT(*) FROM worker_job_events')->fetchColumn() !== 2) {
    pfail('dry-run deleted rows unexpectedly');
}

[$rcApply, $outApply, $errApply] = run_cli([PHP_BINARY, $script, '--db=' . $db, '--older-than-days=90', '--apply']);
if ($rcApply !== 0) {
    pfail('apply failed: ' . trim($errApply));
}
$apply = json_decode($outApply, true);
if (! is_array($apply)) {
    pfail('apply json parse failed');
}
if ((int) $pdo->query('SELECT COUNT(*) FROM worker_job_events')->fetchColumn() !== 1) {
    pfail('apply should prune old worker_job_events only');
}
if ((int) $pdo->query("SELECT COUNT(*) FROM credential_check_runs WHERE status='running'")->fetchColumn() !== 1) {
    pfail('active run should be preserved');
}
if ((int) $pdo->query("SELECT COUNT(*) FROM worker_jobs WHERE status='running'")->fetchColumn() !== 1) {
    pfail('active worker job should be preserved');
}

[$rcInclude, $outInclude, $errInclude] = run_cli([PHP_BINARY, $script, '--db=' . $db, '--older-than-days=90', '--apply', '--include-runs']);
if ($rcInclude !== 0) {
    pfail('include-runs apply failed: ' . trim($errInclude));
}
$inc = json_decode($outInclude, true);
if (! is_array($inc)) {
    pfail('include-runs json parse failed');
}

if ((int) $pdo->query("SELECT COUNT(*) FROM credential_check_runs WHERE id={$runOld}")->fetchColumn() !== 0) {
    pfail('old terminal run should be deleted with include-runs');
}
if ((int) $pdo->query("SELECT COUNT(*) FROM credential_check_runs WHERE id={$runActive}")->fetchColumn() !== 1) {
    pfail('active run should be preserved with include-runs');
}
if ((int) $pdo->query("SELECT COUNT(*) FROM credential_check_artifacts WHERE result_id={$resultOld}")->fetchColumn() !== 0) {
    pfail('old artifacts should be deleted with include-runs');
}
if ((int) $pdo->query("SELECT COUNT(*) FROM worker_jobs WHERE id={$jobOld}")->fetchColumn() !== 0) {
    pfail('old terminal worker job should be deleted with include-runs');
}
if ((int) $pdo->query("SELECT COUNT(*) FROM worker_jobs WHERE id={$jobActive}")->fetchColumn() !== 1) {
    pfail('active worker job should be preserved with include-runs');
}

$audit = (int) $pdo->query("SELECT COUNT(*) FROM user_audit_log WHERE action='maintenance.prune_operational_history'")->fetchColumn();
if ($audit < 2) {
    pfail('expected maintenance audit rows for apply runs');
}

[$rcBad, , $errBad] = run_cli([PHP_BINARY, $script, '--db=' . $db, '--table=assets']);
if ($rcBad === 0 || ! str_contains($errBad, 'Invalid --table')) {
    pfail('invalid table should be rejected safely');
}

fwrite(STDERR, "OK st_operational_prune_selftest\n");
exit(0);
