<?php
/**
 * CLI: credentialed job schedule — cron normalization, next_run, launch_source, audits (light).
 *
 *   php scripts/st_credential_schedule_selftest.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_credential_schedule.php';
require_once dirname(__DIR__) . '/api/lib_credential_check_ops.php';

$fail = static function (string $m): void {
    fwrite(STDERR, 'FAIL: ' . $m . "\n");
    exit(1);
};

$p = st_cc_schedule_parse_cron('@hourly');
if ($p === null || $p[0] !== '0' || $p[1] !== '*') {
    $fail('@hourly preset');
}
if (st_cc_schedule_validate_cron('bad cron') === null) {
    $fail('invalid cron should be rejected');
}
if (st_cc_schedule_validate_timezone('Not/A/Zone') === null) {
    $fail('invalid timezone should be rejected');
}

$after = new \DateTimeImmutable('2024-06-01 12:00:00', new \DateTimeZone('UTC'));
$n1 = st_cc_schedule_next_run_sqlite('0 * * * *', 'UTC', $after);
$n2 = st_cc_schedule_next_run_sqlite('0 * * * *', 'UTC', new \DateTimeImmutable($n1, new \DateTimeZone('UTC')));
if ($n2 <= $n1) {
    $fail('next_run_at should advance for hourly');
}

$pdo = new PDO('sqlite::memory:', null, null, [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
$pdo->exec('PRAGMA foreign_keys = OFF');
$pdo->exec('CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)');
$pdo->exec("INSERT INTO config (key, value) VALUES ('migration_worker_execution_substrate_v1', '1')");
$pdo->exec(
    'CREATE TABLE user_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER,
        actor_username TEXT,
        action TEXT NOT NULL,
        details_json TEXT,
        source_ip TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
    )'
);
$pdo->exec(
    'CREATE TABLE credential_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        transport TEXT NOT NULL,
        principal_json TEXT,
        secret_ciphertext TEXT,
        scope_json TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        deleted_at TEXT,
        last_test_at TEXT,
        last_test_status TEXT,
        last_test_error_code TEXT,
        last_test_duration_ms INTEGER,
        created_by INTEGER,
        created_at TEXT NOT NULL DEFAULT (datetime(\'now\')),
        updated_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
    )'
);
$pdo->exec("INSERT INTO credential_profiles (id, name, transport, enabled) VALUES (1, 'p', 'ssh', 1)");
$pdo->exec(
    'CREATE TABLE credential_check_plugins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plugin_key TEXT NOT NULL,
        version TEXT NOT NULL,
        transport TEXT NOT NULL,
        manifest_json TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT \'stable\',
        created_at TEXT NOT NULL DEFAULT (datetime(\'now\')),
        updated_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
    )'
);
$pdo->exec(
    "INSERT INTO credential_check_plugins (plugin_key, version, transport, manifest_json, state)
     VALUES ('ssh.linux.os_release','1.0.0','ssh','{}','stable')"
);
$pdo->exec(
    'CREATE TABLE assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scope_id INTEGER,
        ip TEXT,
        hostname TEXT,
        lifecycle_status TEXT,
        retired_at TEXT
    )'
);
$pdo->exec("INSERT INTO assets (id, ip, hostname, lifecycle_status) VALUES (10, '10.0.0.1', 'h1', 'active')");
$pdo->exec(
    'CREATE TABLE scan_scopes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)'
);
$pdo->exec("INSERT INTO scan_scopes (id, name) VALUES (1, 's1')");
$pdo->exec(
    'CREATE TABLE credential_check_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        credential_profile_id INTEGER NOT NULL,
        target_mode TEXT NOT NULL,
        target_json TEXT,
        plugin_selection_json TEXT,
        policy_json TEXT,
        schedule_cron TEXT,
        schedule_enabled INTEGER NOT NULL DEFAULT 0,
        schedule_timezone TEXT NOT NULL DEFAULT \'UTC\',
        schedule_last_run_at TEXT,
        schedule_next_run_at TEXT,
        schedule_last_error TEXT,
        max_concurrency INTEGER NOT NULL DEFAULT 1,
        run_timeout_sec INTEGER NOT NULL DEFAULT 3600,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_by INTEGER,
        created_at TEXT NOT NULL DEFAULT (datetime(\'now\')),
        updated_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
    )'
);
$pdo->exec(
    'CREATE TABLE credential_check_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER,
        worker_job_id INTEGER,
        started_at TEXT NOT NULL DEFAULT (datetime(\'now\')),
        finished_at TEXT,
        status TEXT NOT NULL DEFAULT \'queued\',
        initiated_by TEXT,
        launch_source TEXT NOT NULL DEFAULT \'manual\',
        summary_json TEXT
    )'
);
$pdo->exec(
    'CREATE TABLE credential_check_run_targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        asset_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT \'pending\',
        error_code TEXT,
        error_message_safe TEXT,
        started_at TEXT,
        finished_at TEXT
    )'
);
$pdo->exec(
    'CREATE TABLE worker_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_type TEXT NOT NULL,
        entity_type TEXT,
        entity_id INTEGER,
        status TEXT NOT NULL DEFAULT \'queued\',
        priority INTEGER DEFAULT 0,
        max_attempts INTEGER DEFAULT 3,
        payload_json TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime(\'now\')),
        updated_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
    )'
);

$tj = json_encode(['asset_ids' => [10]], JSON_THROW_ON_ERROR);
$pl = json_encode([['plugin_key' => 'ssh.linux.os_release', 'version' => '1.0.0']], JSON_THROW_ON_ERROR);
$pdo->prepare(
    'INSERT INTO credential_check_jobs (name, credential_profile_id, target_mode, target_json, plugin_selection_json, policy_json,
        schedule_cron, schedule_enabled, schedule_timezone, schedule_next_run_at, max_concurrency, enabled)
     VALUES (\'j1\', 1, \'assets\', ?, ?, \'{}\', \'0 * * * *\', 1, \'UTC\', datetime(\'now\',\'-1 hour\'), 1, 1)'
)->execute([$tj, $pl]);

$jobId = (int) $pdo->query('SELECT id FROM credential_check_jobs LIMIT 1')->fetchColumn();
if ($jobId < 1) {
    $fail('seed job');
}

$st0 = st_cc_schedule_process_tick($pdo, 10);
if ((int) ($st0['due_selected'] ?? 0) < 1) {
    $fail('tick should select due job (stats=' . json_encode($st0) . ')');
}
if ((int) ($st0['launched'] ?? 0) < 1) {
    $fail('tick should launch (stats=' . json_encode($st0) . ')');
}
$rowR = $pdo->query('SELECT id, launch_source, initiated_by FROM credential_check_runs ORDER BY id DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
$ls = is_array($rowR) ? (string) ($rowR['launch_source'] ?? '') : '';
if ($ls !== 'scheduled') {
    $fail('expected launch_source scheduled, got ' . $ls . ' row=' . json_encode($rowR ?: []));
}
$ac = (int) $pdo->query("SELECT COUNT(*) FROM credential_check_runs WHERE job_id = {$jobId} AND status IN ('queued','resolving_targets','ready','running')")->fetchColumn();
if ($ac !== 1) {
    $fail('expected one active run');
}
// Second tick: job due again but active run -> skip path
$pdo->exec('UPDATE credential_check_jobs SET schedule_next_run_at = datetime(\'now\',\'-5 minutes\') WHERE id = ' . (int) $jobId);
$stats2 = st_cc_schedule_process_tick($pdo, 10);
if ((int) ($stats2['launched'] ?? 0) !== 0) {
    $fail('second tick should not launch duplicate while active');
}
if ((int) ($stats2['skipped'] ?? 0) < 1) {
    $fail('expected skip when max concurrency reached');
}

$aud = (int) $pdo->query("SELECT COUNT(*) FROM user_audit_log WHERE action = 'credential_check.run_scheduled_launch'")->fetchColumn();
if ($aud < 1) {
    $fail('expected run_scheduled_launch audit');
}

$pdo->exec("UPDATE credential_check_runs SET status = 'completed', finished_at = datetime('now') WHERE job_id = " . (int) $jobId);
[$okM,, $runM,] = st_cc_run_launch($pdo, $jobId, 'tester', false, 'manual', true);
if (! $okM || ! is_array($runM)) {
    $fail('manual launch should succeed when no active runs');
}
$ls2 = $pdo->query('SELECT launch_source FROM credential_check_runs WHERE id = ' . (int) ($runM['id'] ?? 0))->fetchColumn();
if ($ls2 !== 'manual') {
    $fail('manual launch_source');
}

fwrite(STDOUT, "PASS: st_credential_schedule_selftest\n");
exit(0);
