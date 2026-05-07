#!/usr/bin/env php
<?php
declare(strict_types=1);

function cifail(string $msg): void
{
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

/**
 * @return array{0:int,1:string,2:string}
 */
function cirun(array $cmd, ?string $cwd = null, array $env = []): array
{
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $spec, $pipes, $cwd ?? dirname(__DIR__), $env !== [] ? $env : null);
    if (! is_resource($proc)) {
        cifail('proc_open failed');
    }
    fclose($pipes[0]);
    $out = (string) stream_get_contents($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $rc = proc_close($proc);
    return [$rc, $out, $err];
}

$tmp = sys_get_temp_dir() . '/st_ciw_' . bin2hex(random_bytes(4));
$install = $tmp . '/install';
$data = $install . '/data';
$ingestDir = $data . '/collector_ingest';
if (! mkdir($ingestDir, 0770, true) && ! is_dir($ingestDir)) {
    cifail('tmp dir create failed');
}
$db = $data . '/surveytrace.db';
$schema = @file_get_contents(dirname(__DIR__) . '/sql/schema.sql');
if (! is_string($schema) || $schema === '') {
    cifail('schema read failed');
}

try {
    $pdo = new PDO('sqlite:' . $db, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec($schema);
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS collector_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            collector_id INTEGER NOT NULL,
            job_id INTEGER NOT NULL,
            submission_id TEXT NOT NULL,
            chunk_count INTEGER NOT NULL DEFAULT 1,
            received_chunks INTEGER NOT NULL DEFAULT 0,
            processed_chunks INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'receiving',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(collector_id, job_id, submission_id)
        )"
    );
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS collector_ingest_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            collector_id INTEGER NOT NULL,
            job_id INTEGER NOT NULL,
            submission_id TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            chunk_count INTEGER NOT NULL,
            content_sha256 TEXT NOT NULL,
            local_relpath TEXT NOT NULL,
            artifact_uri TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at DATETIME,
            error_msg TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            processed_at DATETIME,
            processing_started_at DATETIME,
            UNIQUE(collector_id, job_id, submission_id, chunk_index)
        )"
    );
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_collector_ingest_pending ON collector_ingest_queue(status, next_attempt_at, created_at)");
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS collector_job_leases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL UNIQUE,
            collector_id INTEGER NOT NULL,
            lease_token TEXT NOT NULL,
            leased_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            lease_expires_at DATETIME NOT NULL,
            last_heartbeat_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS collector_ingest_exec_ai_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at DATETIME,
            error_msg TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            processing_started_at DATETIME,
            UNIQUE(job_id)
        )"
    );
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('migration_worker_execution_substrate_v1', '1')");
    $pdo->exec(
        "INSERT INTO scan_jobs (id, target_cidr, status, created_at, started_at, collector_id)
         VALUES (1, '192.0.2.0/24', 'running', datetime('now'), datetime('now'), 1)"
    );
    $pdo->exec(
        "INSERT INTO collector_submissions (collector_id, job_id, submission_id, chunk_count, received_chunks, processed_chunks, status)
         VALUES (1, 1, 'sub-a', 1, 1, 0, 'receiving')"
    );
} catch (Throwable $e) {
    cifail('db bootstrap failed: ' . $e->getMessage());
}

$payload = [
    'scan_job' => ['status' => 'done', 'hosts_found' => 0, 'hosts_scanned' => 0, 'summary_json' => '{}'],
    'assets' => [],
    'findings' => [],
    'scan_log' => [],
    'port_history' => [],
];
$relValid = '2026/05/07/sub-a-chunk0.json';
$absValid = $ingestDir . '/' . $relValid;
if (! mkdir(dirname($absValid), 0770, true) && ! is_dir(dirname($absValid))) {
    cifail('valid artifact dir create failed');
}
if (@file_put_contents($absValid, json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) === false) {
    cifail('valid artifact write failed');
}

try {
    $pdo->prepare(
        "INSERT INTO collector_ingest_queue
         (collector_id, job_id, submission_id, chunk_index, chunk_count, content_sha256, local_relpath, artifact_uri, status, next_attempt_at)
         VALUES (1,1,'sub-a',0,1,?,?,'file://x','pending',NULL)"
    )->execute([hash('sha256', 'x'), $relValid]);
} catch (Throwable $e) {
    cifail('insert valid queue row failed: ' . $e->getMessage());
}

$env = [
    'SURVEYTRACE_INSTALL_DIR' => $install,
    'SURVEYTRACE_DB_PATH' => $db,
];
$worker = dirname(__DIR__) . '/daemon/collector_ingest_worker.py';
[$rc1, $out1, $err1] = cirun(['python3', $worker, '--once'], dirname(__DIR__), $env);
if ($rc1 !== 0) {
    cifail('worker once(valid) failed rc=' . $rc1 . ' err=' . trim($err1) . ' out=' . trim($out1));
}
$s1 = (string) $pdo->query("SELECT status FROM collector_ingest_queue WHERE submission_id='sub-a' AND chunk_index=0")->fetchColumn();
if ($s1 !== 'applied') {
    cifail('valid pending row not applied');
}

// Future next_attempt row should remain pending/ineligible.
$pdo->exec(
    "INSERT INTO collector_submissions (collector_id, job_id, submission_id, chunk_count, received_chunks, processed_chunks, status)
     VALUES (1,1,'sub-future',1,1,0,'receiving')"
);
$pdo->prepare(
    "INSERT INTO collector_ingest_queue
     (collector_id, job_id, submission_id, chunk_index, chunk_count, content_sha256, local_relpath, artifact_uri, status, next_attempt_at)
     VALUES (1,1,'sub-future',0,1,?,?,'file://x','pending',datetime('now','+1 hour'))"
)->execute([hash('sha256', 'y'), $relValid]);
[$rc2] = cirun(['python3', $worker, '--once'], dirname(__DIR__), $env);
if ($rc2 !== 0) {
    cifail('worker once(future) failed');
}
$s2 = (string) $pdo->query("SELECT status FROM collector_ingest_queue WHERE submission_id='sub-future'")->fetchColumn();
if ($s2 !== 'pending') {
    cifail('future next_attempt row should remain pending');
}

// Missing artifact should fail/retry visibly (status failed with attempts incremented).
$pdo->exec(
    "INSERT INTO collector_submissions (collector_id, job_id, submission_id, chunk_count, received_chunks, processed_chunks, status)
     VALUES (1,1,'sub-missing',1,1,0,'receiving')"
);
$pdo->prepare(
    "INSERT INTO collector_ingest_queue
     (collector_id, job_id, submission_id, chunk_index, chunk_count, content_sha256, local_relpath, artifact_uri, status, next_attempt_at)
     VALUES (1,1,'sub-missing',0,1,?,'does/not/exist.json','file://x','pending',NULL)"
)->execute([hash('sha256', 'z')]);
[$rc3] = cirun(['python3', $worker, '--once'], dirname(__DIR__), $env);
if ($rc3 !== 0) {
    cifail('worker once(missing artifact) failed');
}
$r3 = $pdo->query("SELECT status, attempts, error_msg FROM collector_ingest_queue WHERE submission_id='sub-missing'")->fetch(PDO::FETCH_ASSOC);
if (! is_array($r3) || (string) ($r3['status'] ?? '') !== 'failed' || (int) ($r3['attempts'] ?? 0) < 1) {
    cifail('missing artifact row did not transition to failed retry state');
}

// Malformed row (empty relpath) should fail/retry.
$pdo->exec(
    "INSERT INTO collector_submissions (collector_id, job_id, submission_id, chunk_count, received_chunks, processed_chunks, status)
     VALUES (1,1,'sub-malformed',1,1,0,'receiving')"
);
$pdo->prepare(
    "INSERT INTO collector_ingest_queue
     (collector_id, job_id, submission_id, chunk_index, chunk_count, content_sha256, local_relpath, artifact_uri, status, next_attempt_at)
     VALUES (1,1,'sub-malformed',0,1,?,'','file://x','pending',NULL)"
)->execute([hash('sha256', 'm')]);
[$rc4] = cirun(['python3', $worker, '--once'], dirname(__DIR__), $env);
if ($rc4 !== 0) {
    cifail('worker once(malformed row) failed');
}
$r4 = $pdo->query("SELECT status, attempts FROM collector_ingest_queue WHERE submission_id='sub-malformed'")->fetch(PDO::FETCH_ASSOC);
if (! is_array($r4) || (string) ($r4['status'] ?? '') !== 'failed' || (int) ($r4['attempts'] ?? 0) < 1) {
    cifail('malformed row did not transition to failed retry state');
}

fwrite(STDERR, "OK st_collector_ingest_worker_hardening_selftest\n");
exit(0);
