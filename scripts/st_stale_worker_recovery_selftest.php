#!/usr/bin/env php
<?php
declare(strict_types=1);

function rfail(string $msg): void
{
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

function rrun(array $cmd): array
{
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $spec, $pipes, dirname(__DIR__), null);
    if (! is_resource($proc)) {
        rfail('proc_open failed');
    }
    fclose($pipes[0]);
    $out = (string) stream_get_contents($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $rc = proc_close($proc);

    return [$rc, $out, $err];
}

$tmpDir = sys_get_temp_dir() . '/st_recover_' . bin2hex(random_bytes(4));
if (! mkdir($tmpDir, 0700, true) && ! is_dir($tmpDir)) {
    rfail('tmp dir create failed');
}
$db = $tmpDir . '/test.db';
$schema = dirname(__DIR__) . '/sql/schema.sql';
$sql = @file_get_contents($schema);
if (! is_string($sql) || $sql === '') {
    rfail('schema read failed');
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
    // heartbeats table may exist via schema, keep additive.
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS worker_heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id INTEGER NOT NULL,
            worker_key TEXT,
            worker_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'healthy',
            heartbeat_at DATETIME NOT NULL DEFAULT (datetime('now')),
            details_json TEXT
        )"
    );
} catch (Throwable $e) {
    rfail('db bootstrap failed: ' . $e->getMessage());
}

// stale credentialed_check running job
$pdo->exec("INSERT INTO worker_jobs (job_type,status,lease_node_id,lease_expires_at,created_at,updated_at,entity_type,entity_id)
VALUES ('credentialed_check','running',1,datetime('now','-120 minutes'),datetime('now','-120 minutes'),datetime('now','-120 minutes'),'credential_check_run',1)");
$jobStale = (int) $pdo->lastInsertId();
$pdo->exec("INSERT INTO worker_job_attempts (job_id,attempt_no,status,started_at) VALUES ({$jobStale},1,'running',datetime('now','-120 minutes'))");

// queued cancel requested
$pdo->exec("INSERT INTO worker_jobs (job_type,status,cancel_requested_at,created_at,updated_at,entity_type,entity_id)
VALUES ('credentialed_check','queued',datetime('now','-120 minutes'),datetime('now','-120 minutes'),datetime('now','-120 minutes'),'credential_check_run',2)");
$jobQueuedCancel = (int) $pdo->lastInsertId();

// recent active should stay
$pdo->exec("INSERT INTO worker_jobs (job_type,status,created_at,updated_at,entity_type,entity_id)
VALUES ('credentialed_check','running',datetime('now','-5 minutes'),datetime('now','-5 minutes'),'credential_check_run',3)");
$jobRecent = (int) $pdo->lastInsertId();

// Expired lease but recently bumped updated_at — must still be stale (lease vs wall clock, not age cutoff)
$pdo->exec("INSERT INTO worker_jobs (job_type,status,lease_node_id,lease_expires_at,created_at,updated_at,entity_type,entity_id)
VALUES ('credentialed_check','leased',1,datetime('now','-10 minutes'),datetime('now','-2 hours'),datetime('now','-2 minutes'),'credential_check_run',44)");
$jobLeaseStaleRecentTouch = (int) $pdo->lastInsertId();

// completed should stay untouched
$pdo->exec("INSERT INTO worker_jobs (job_type,status,finished_at,created_at,updated_at,entity_type,entity_id)
VALUES ('credentialed_check','completed',datetime('now','-5 minutes'),datetime('now','-5 minutes'),datetime('now','-5 minutes'),'credential_check_run',4)");
$jobCompleted = (int) $pdo->lastInsertId();

// collector_ingest stale should be ignored by default job-type filter
$pdo->exec("INSERT INTO worker_jobs (job_type,status,lease_expires_at,created_at,updated_at,entity_type,entity_id)
VALUES ('collector_ingest','running',datetime('now','-120 minutes'),datetime('now','-120 minutes'),datetime('now','-120 minutes'),'collector_submission',55)");
$jobCollector = (int) $pdo->lastInsertId();

// linked runs
$pdo->exec("INSERT INTO credential_check_runs (id,worker_job_id,status,started_at) VALUES
(1,{$jobStale},'running',datetime('now','-120 minutes')),
(2,{$jobQueuedCancel},'queued',datetime('now','-120 minutes')),
(3,{$jobRecent},'running',datetime('now','-5 minutes')),
(4,{$jobLeaseStaleRecentTouch},'running',datetime('now','-30 minutes'))");
$pdo->exec("INSERT INTO credential_check_run_targets (run_id,asset_id,status,started_at) VALUES
(1,1,'running',datetime('now','-120 minutes')),
(2,1,'pending',datetime('now','-120 minutes')),
(3,1,'running',datetime('now','-5 minutes')),
(4,1,'running',datetime('now','-30 minutes'))");

$script = dirname(__DIR__) . '/scripts/recover_stale_worker_jobs.php';

$pre = (int) $pdo->query(
    "SELECT COUNT(*) FROM worker_jobs
     WHERE status IN ('leased','running','retrying')
       AND job_type='credentialed_check'
       AND (
         (lease_expires_at IS NOT NULL AND lease_expires_at <> '' AND lease_expires_at < datetime('now'))
         OR COALESCE(updated_at,created_at,'1970-01-01 00:00:00') < datetime('now','-60 minutes')
       )"
)->fetchColumn();
if ($pre < 2) {
    $dbg = $pdo->query("SELECT id,job_type,status,lease_expires_at,created_at,updated_at FROM worker_jobs ORDER BY id ASC")->fetchAll(PDO::FETCH_ASSOC);
    rfail('fixture did not create stale candidate: ' . json_encode($dbg));
}

[$rcDry, $outDry, $errDry] = rrun([PHP_BINARY, $script, '--db=' . $db, '--older-than-minutes=60', '--run-sync']);
if ($rcDry !== 0) {
    rfail('dry-run failed: ' . trim($errDry));
}
$dry = json_decode($outDry, true);
if (! is_array($dry)) {
    rfail('dry-run parse failed');
}
if ((int) (($dry['candidates']['stale_jobs'] ?? 0)) < 2) {
    rfail('expected stale job candidate; payload=' . $outDry);
}
if ((int) $pdo->query("SELECT COUNT(*) FROM worker_jobs WHERE status='failed'")->fetchColumn() !== 0) {
    rfail('dry-run should not modify rows');
}

[$rcApply, $outApply, $errApply] = rrun([PHP_BINARY, $script, '--db=' . $db, '--older-than-minutes=60', '--apply', '--run-sync']);
if ($rcApply !== 0) {
    rfail('apply failed: ' . trim($errApply));
}
$ap = json_decode($outApply, true);
if (! is_array($ap)) {
    rfail('apply parse failed');
}

$staleNow = (string) $pdo->query("SELECT status FROM worker_jobs WHERE id={$jobStale}")->fetchColumn();
if ($staleNow !== 'failed') {
    rfail('stale running job should be failed');
}
$queuedNow = (string) $pdo->query("SELECT status FROM worker_jobs WHERE id={$jobQueuedCancel}")->fetchColumn();
if ($queuedNow !== 'cancelled') {
    rfail('queued cancel-requested job should be cancelled');
}
$leaseTouchNow = (string) $pdo->query("SELECT status FROM worker_jobs WHERE id={$jobLeaseStaleRecentTouch}")->fetchColumn();
if ($leaseTouchNow !== 'failed') {
    rfail('leased job with expired lease (recent updated_at) should be failed');
}
$recentNow = (string) $pdo->query("SELECT status FROM worker_jobs WHERE id={$jobRecent}")->fetchColumn();
if ($recentNow !== 'running') {
    rfail('recent active job should remain running');
}
$completedNow = (string) $pdo->query("SELECT status FROM worker_jobs WHERE id={$jobCompleted}")->fetchColumn();
if ($completedNow !== 'completed') {
    rfail('completed job should remain completed');
}
$collectorNow = (string) $pdo->query("SELECT status FROM worker_jobs WHERE id={$jobCollector}")->fetchColumn();
if ($collectorNow !== 'running') {
    rfail('collector_ingest should be ignored by default');
}

$attemptState = (string) $pdo->query("SELECT status FROM worker_job_attempts WHERE job_id={$jobStale}")->fetchColumn();
if ($attemptState !== 'failed') {
    rfail('stale running attempt should be finalized failed');
}

$run1 = (string) $pdo->query("SELECT status FROM credential_check_runs WHERE id=1")->fetchColumn();
if ($run1 !== 'failed') {
    rfail('run sync should fail run linked to failed worker job');
}
$run2 = (string) $pdo->query("SELECT status FROM credential_check_runs WHERE id=2")->fetchColumn();
if ($run2 !== 'cancelled') {
    rfail('run sync should cancel run linked to cancelled worker job');
}
$run3 = (string) $pdo->query("SELECT status FROM credential_check_runs WHERE id=3")->fetchColumn();
if ($run3 !== 'running') {
    rfail('recent active run should remain running');
}
$run4 = (string) $pdo->query("SELECT status FROM credential_check_runs WHERE id=4")->fetchColumn();
if ($run4 !== 'failed') {
    rfail('run sync should fail run linked to lease-stale worker job');
}

$auditCount = (int) $pdo->query("SELECT COUNT(*) FROM user_audit_log WHERE action='maintenance.recover_stale_worker_jobs'")->fetchColumn();
if ($auditCount < 1) {
    rfail('expected aggregate maintenance recovery audit row');
}

fwrite(STDERR, "OK st_stale_worker_recovery_selftest\n");
exit(0);
