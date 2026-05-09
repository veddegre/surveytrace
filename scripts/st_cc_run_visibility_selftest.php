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
        status TEXT NOT NULL DEFAULT 'queued',
        entity_type TEXT,
        entity_id INTEGER
    )"
);
$pdo->exec("INSERT INTO worker_jobs (id, job_type, status, entity_type, entity_id) VALUES (1, 'credentialed_check', 'completed', 'credential_check_run', 7)");

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

if (st_cc_timeline_redact_sensitive_string('x password=secret', 99) !== '[redacted]') {
    fwrite(STDERR, "FAIL: redact password pattern\n");
    exit(1);
}
$pemCode = json_encode(['run_id' => 7, 'code' => "-----BEGIN RSA PRIVATE KEY-----\nABC"], JSON_THROW_ON_ERROR);
$pubPem = st_cc_timeline_audit_details_public($pemCode);
if (($pubPem['code'] ?? '') !== '[redacted]') {
    fwrite(STDERR, 'FAIL: audit code field should redact PEM-like value, got ' . json_encode($pubPem) . "\n");
    exit(1);
}

$longPlugs = [];
for ($i = 0; $i < 30; ++$i) {
    $longPlugs[] = ['plugin_key' => 'ssh.linux.p_' . str_repeat('x', 40), 'version' => '1.0.0'];
}
$sumLong = st_cc_plugin_selection_summary(json_encode($longPlugs, JSON_THROW_ON_ERROR));
if (strlen($sumLong) > 280) {
    fwrite(STDERR, 'FAIL: plugin_summary length cap, len=' . strlen($sumLong) . "\n");
    exit(1);
}

$pdo->exec('DELETE FROM user_audit_log');
$pdo->exec('DELETE FROM worker_job_events');
$insW->execute([1, 1, 'e1', 'info', 'first', null, '2021-06-01 12:00:00']);
$insW->execute([1, 1, 'e2', 'info', 'second', null, '2021-06-01 12:00:00']);
$tl2 = st_cc_run_timeline_public($pdo, 7, 1);
$labs = array_map(static fn (array $e): string => (string) ($e['label'] ?? ''), $tl2['events']);
if ($labs !== ['first', 'second']) {
    fwrite(STDERR, 'FAIL: stable chronological order for same-timestamp worker events, got ' . json_encode($labs) . "\n");
    exit(1);
}

if (st_cc_run_outcome_from_result_counts(0, 0, 3) !== 'failed') {
    fwrite(STDERR, "FAIL: outcome all failed\n");
    exit(1);
}
if (st_cc_run_outcome_from_result_counts(1, 0, 1) !== 'partial') {
    fwrite(STDERR, "FAIL: outcome mixed success+failed\n");
    exit(1);
}
if (st_cc_run_outcome_from_result_counts(2, 1, 0) !== 'success') {
    fwrite(STDERR, "FAIL: outcome no failed rows\n");
    exit(1);
}
if (st_cc_run_outcome_from_result_counts(0, 2, 1) !== 'partial') {
    fwrite(STDERR, "FAIL: outcome partial+failed\n");
    exit(1);
}
$hFail = st_cc_run_headline_public('failed', 'failed', 0, 0, 8);
if (strpos($hFail, 'all plugin') === false) {
    fwrite(STDERR, 'FAIL: headline all-plugin fail, got ' . $hFail . "\n");
    exit(1);
}
$hPart = st_cc_run_headline_public('completed', 'partial', 1, 0, 1);
if (strpos($hPart, 'failures') === false) {
    fwrite(STDERR, 'FAIL: headline partial, got ' . $hPart . "\n");
    exit(1);
}
$hLegacy = st_cc_run_headline_public('completed', 'failed', 0, 0, 4);
if (strpos($hLegacy, 'all plugin') === false) {
    fwrite(STDERR, 'FAIL: headline legacy completed+failed plugins, got ' . $hLegacy . "\n");
    exit(1);
}

$plugAudit = json_encode(
    [
        'run_id'         => 7,
        'target_row_id'  => 2,
        'asset_id'       => 9,
        'plugin_ok'      => 0,
        'plugin_failed'  => 2,
        'plugin_partial' => 0,
        'outcome'        => 'failed',
        'stderr'         => 'secret token=abc',
    ],
    JSON_THROW_ON_ERROR
);
$pubPlug = st_cc_timeline_audit_details_public($plugAudit);
if (($pubPlug['plugin_failed'] ?? null) !== 2) {
    fwrite(STDERR, 'FAIL: timeline should expose plugin_failed count, got ' . json_encode($pubPlug) . "\n");
    exit(1);
}
if (isset($pubPlug['stderr'])) {
    fwrite(STDERR, "FAIL: timeline must not pass through raw stderr key\n");
    exit(1);
}

$sumPub = st_cc_run_summary_for_display(json_encode([
    'slice'               => 9,
    'executor'            => 'credential_check_worker',
    'placeholder_only'    => false,
    'plugins_placeholder' => [],
    'targets_total'       => 2,
    'run_outcome'         => 'success',
    'result_success_count'=> 5,
], JSON_THROW_ON_ERROR));
if (isset($sumPub['slice']) || isset($sumPub['executor'])) {
    fwrite(STDERR, 'FAIL: summary_public should omit slice/executor, got ' . json_encode($sumPub) . "\n");
    exit(1);
}
if (isset($sumPub['placeholder_only']) || isset($sumPub['plugins_placeholder'])) {
    fwrite(STDERR, "FAIL: summary_public should omit empty placeholder fields\n");
    exit(1);
}
if ((int) ($sumPub['targets_total'] ?? 0) !== 2) {
    fwrite(STDERR, "FAIL: summary_public targets_total\n");
    exit(1);
}

$sumPh = st_cc_run_summary_for_display(json_encode([
    'placeholder_only'    => true,
    'plugins_placeholder' => ['x@1'],
    'run_outcome'         => 'partial',
], JSON_THROW_ON_ERROR));
if (($sumPh['placeholder_only'] ?? null) !== true || ! isset($sumPh['plugins_placeholder'])) {
    fwrite(STDERR, 'FAIL: summary_public should keep truthy placeholder signals, got ' . json_encode($sumPh) . "\n");
    exit(1);
}

$pdoObs = new PDO('sqlite::memory:', null, null, [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
$pdoObs->exec('PRAGMA foreign_keys = OFF');
$pdoObs->exec('CREATE TABLE asset_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    observation_type TEXT NOT NULL,
    source_id INTEGER NOT NULL,
    source_object_ref TEXT NOT NULL DEFAULT \'\',
    observed_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
)');
$insO = $pdoObs->prepare('INSERT INTO asset_observations (asset_id, observation_type, source_id, source_object_ref, observed_at) VALUES (?,?,?,?,?)');
$insO->execute([1, 'os_version_observed', 9, 'run:77:t1', '2024-01-01 00:00:00']);
$insO->execute([1, 'package_inventory_observed', 9, 'run:77:t2', '2024-01-01 00:00:01']);
for ($i = 0; $i < 12; ++$i) {
    $insO->execute([1, 'software_observed', 9, 'run:77:sw:' . $i, '2024-01-02 00:00:' . str_pad((string) $i, 2, '0', STR_PAD_LEFT)]);
}
$osum = st_cc_run_observations_public_summary($pdoObs, 9, 77);
if ((int) ($osum['counts_by_type']['software_observed'] ?? 0) !== 12) {
    fwrite(STDERR, 'FAIL: software_observed count, got ' . json_encode($osum['counts_by_type']) . "\n");
    exit(1);
}
if ((int) ($osum['counts_by_type']['os_version_observed'] ?? 0) !== 1) {
    fwrite(STDERR, "FAIL: os_version_observed count\n");
    exit(1);
}
if (count($osum['software_observed_samples']) !== 5) {
    fwrite(STDERR, 'FAIL: expected 5 software samples, got ' . count($osum['software_observed_samples']) . "\n");
    exit(1);
}

echo "OK st_cc_run_visibility_selftest\n";
