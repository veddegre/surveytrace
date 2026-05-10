#!/usr/bin/env php
<?php
/**
 * Selftest: scheduler status JSON parsing, health warnings, and scheduler_daemon --check-db-open on temp DB.
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_scheduler_health.php';

function st_sh_fail(string $m): void
{
    fwrite(STDERR, "FAIL: {$m}\n");
    exit(1);
}

// --- st_health_scheduler_runtime: stale heartbeat should warn ---
$tmp = sys_get_temp_dir() . '/st_sched_h_' . bin2hex(random_bytes(4));
@mkdir($tmp, 0700, true);
$statusPath = $tmp . '/scheduler_status.json';
$old = gmdate('Y-m-dT', time() - 400) . '00:00Z';
$doc = [
    'pid' => 1,
    'last_start_utc' => $old,
    'last_loop_success_utc' => $old,
    'last_db_open_success_utc' => $old,
    'last_schedule_scan_attempt_utc' => $old,
    'last_credential_schedule_tick_utc' => '',
    'db_open_consecutive_failures' => 2,
    'db_open_first_failure_utc' => $old,
    'last_db_open_error' => 'unable to open database file',
    'updated_at' => $old,
];
file_put_contents($statusPath, json_encode($doc, JSON_UNESCAPED_SLASHES));
$rt = st_health_scheduler_runtime($tmp);
if (empty($rt['warnings'])) {
    st_sh_fail('expected warnings for stale scheduler status');
}
if ($rt['db_open_consecutive_failures'] !== 2) {
    st_sh_fail('db_open_consecutive_failures not propagated');
}

// --- schedule tick warnings when schedules enabled ---
$sched = ['enabled_active' => 1, 'table_ok' => true];
$rt2 = ['last_schedule_scan_attempt_utc' => '', 'warnings' => []];
$w = st_health_scheduler_schedule_tick_warnings($sched, $rt2);
if ($w === []) {
    st_sh_fail('expected schedule tick warning when enabled but no attempt timestamp');
}

// --- Python --check-db-open on minimal install tree ---
$root = $tmp . '/install';
$data = $root . '/data';
$daemon = $root . '/daemon';
@mkdir($data, 0770, true);
@mkdir($daemon, 0755, true);
$schema = @file_get_contents(dirname(__DIR__) . '/sql/schema.sql');
if (! is_string($schema) || $schema === '') {
    st_sh_fail('schema read failed');
}
try {
    $pdo = new PDO('sqlite:' . $data . '/surveytrace.db', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    $pdo->exec($schema);
    $pdo = null;
} catch (Throwable $e) {
    st_sh_fail('temp db: ' . $e->getMessage());
}
copy(dirname(__DIR__) . '/daemon/scheduler_daemon.py', $daemon . '/scheduler_daemon.py');
foreach (['sqlite_pragmas.py', 'surveytrace_paths.py'] as $bn) {
    $src = dirname(__DIR__) . '/daemon/' . $bn;
    if (! is_file($src)) {
        st_sh_fail('missing ' . $bn);
    }
    copy($src, $daemon . '/' . $bn);
}
$venvBin = $root . '/venv/bin';
@mkdir($venvBin, 0755, true);
$pyReal = PHP_OS_FAMILY === 'Darwin' ? '/usr/bin/python3' : '/usr/bin/python3';
if (! is_executable($pyReal)) {
    $pyReal = trim((string) shell_exec('command -v python3 2>/dev/null'));
}
if ($pyReal === '' || ! is_executable($pyReal)) {
    fwrite(STDERR, "SKIP: no system python3 for scheduler_daemon --check-db-open integration\n");
    echo "OK (PHP checks only)\n";
    exit(0);
}
symlink($pyReal, $venvBin . '/python3');

$cmd = [$venvBin . '/python3', $daemon . '/scheduler_daemon.py', '--check-db-open'];
$spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
$prevInstall = getenv('SURVEYTRACE_INSTALL_DIR');
putenv('SURVEYTRACE_INSTALL_DIR=' . $root);
$proc = proc_open($cmd, $spec, $pipes, $root, null);
if (! is_resource($proc)) {
    if ($prevInstall === false) {
        putenv('SURVEYTRACE_INSTALL_DIR');
    } else {
        putenv('SURVEYTRACE_INSTALL_DIR=' . (string) $prevInstall);
    }
    st_sh_fail('proc_open scheduler --check-db-open');
}
fclose($pipes[0]);
$err = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
$rc = proc_close($proc);
if ($prevInstall === false) {
    putenv('SURVEYTRACE_INSTALL_DIR');
} else {
    putenv('SURVEYTRACE_INSTALL_DIR=' . (string) $prevInstall);
}
if ($rc !== 0) {
    st_sh_fail('scheduler_daemon --check-db-open expected 0, got ' . $rc . ' stderr=' . substr((string) $err, 0, 500));
}

echo "OK\n";
exit(0);
