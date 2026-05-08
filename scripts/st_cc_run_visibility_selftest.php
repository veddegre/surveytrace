<?php
/**
 * CLI: credentialed run timeline (bounded + allowlisted), plugin summary, and list SQL fields.
 *
 *   php scripts/st_cc_run_visibility_selftest.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_credential_check_ops.php';
require_once dirname(__DIR__) . '/api/lib_worker_jobs.php';

$pdo = new PDO('sqlite::memory:', null, null, [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
$pdo->exec('PRAGMA foreign_keys = OFF');

$pdo->exec(
    'CREATE TABLE config (
        key TEXT PRIMARY KEY,
        value TEXT
    )'
);
$pdo->exec("INSERT INTO config (key, value) VALUES ('migration_worker_execution_substrate_v1', '1')");

$pdo->exec(
    "CREATE TABLE worker_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued'
    )"
);
$pdo->exec("INSERT INTO worker_jobs (id, job_type, status) VALUES (1, 'credentialed_check', 'completed')");

$pdo->exec(
    "CREATE TABLE worker_job_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        attempt_id INTEGER,
        event_type TEXT NOT NULL,
        level TEXT NOT NULL DEFAULT 'info',
        message TEXT,
        details_json TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )"
);

$pdo->exec(
    "CREATE TABLE user_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER,
        actor_username TEXT,
        target_user_id INTEGER,
        target_username TEXT,
        action TEXT NOT NULL,
        details_json TEXT,
        source_ip TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )"
);

$insA = $pdo->prepare(
    'INSERT INTO user_audit_log (action, actor_username, details_json, created_at) VALUES (?, ?, ?, ?)'
);
$insW = $pdo->prepare(
    'INSERT INTO worker_job_events (job_id, attempt_id, event_type, level, message, details_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)'
);

$base = '2020-01-01 00:00:';
for ($i = 0; $i < 52; ++$i) {
    $t = $base . str_pad((string) (10 + $i), 2, '0', STR_PAD_LEFT);
    $insA->execute([
        'credential_check.target_started',
        'system',
        json_encode(['run_id' => 7, 'target_row_id' => $i, 'asset_id' => 100 + $i], JSON_THROW_ON_ERROR),
        $t,
    ]);
}
$insA->execute([
    'credential_check.run_started',
    'alice',
    json_encode(['run_id' => 7, 'job_id' => 3, 'worker_job_id' => 1, 'password' => 'nope'], JSON_THROW_ON_ERROR),
    '2020-01-01 00:00:05',
]);
$insW->execute([1, 1, 'cancel_requested', 'info', 'Cancellation requested', json_encode(['actor' => 'alice'], JSON_THROW_ON_ERROR), '2020-01-01 00:00:06']);
$insW->execute([1, 1, 'cred_check_run_executing', 'info', 'Run marked running', json_encode(['credential_check_run_id' => 7, 'extra' => ['x' => 1]]), '2020-01-01 00:00:07']);

$tl = st_cc_run_timeline_public($pdo, 7, 1);
if (count($tl['events']) !== 50) {
    fwrite(STDERR, 'FAIL: expected 50 capped events, got ' . count($tl['events']) . "\n");
    exit(1);
}
if (! $tl['truncated'] || $tl['total_before_cap'] <= 50) {
    fwrite(STDERR, "FAIL: expected truncation with total_before_cap > 50\n");
    exit(1);
}

$joined = json_encode($tl['events'], JSON_THROW_ON_ERROR);
if (stripos($joined, 'password') !== false || stripos($joined, 'nope') !== false) {
    fwrite(STDERR, "FAIL: timeline leaked disallowed audit field\n");
    exit(1);
}
if (stripos($joined, '"extra"') !== false) {
    fwrite(STDERR, "FAIL: timeline leaked nested worker details\n");
    exit(1);
}

$sum = st_cc_plugin_selection_summary(json_encode([
    ['plugin_key' => 'ssh.linux.os_release', 'version' => '1.0.0'],
    ['plugin_key' => 'ssh.linux.package_inventory', 'version' => '1.0.0'],
    ['plugin_key' => 'snmpv3.device_identity', 'version' => '1.0.0'],
    ['plugin_key' => 'x.y', 'version' => '1'],
    ['plugin_key' => 'a.b', 'version' => '2'],
], JSON_THROW_ON_ERROR));
if (strpos($sum, '+') === false) {
    fwrite(STDERR, "FAIL: plugin_summary expected overflow hint, got {$sum}\n");
    exit(1);
}

echo "OK st_cc_run_visibility_selftest\n";
