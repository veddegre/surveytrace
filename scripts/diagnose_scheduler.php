#!/usr/bin/env php
<?php
/**
 * Read-only SurveyTrace scheduler diagnostics (no secrets).
 *
 * Usage:
 *   php scripts/diagnose_scheduler.php [--data-dir=/opt/surveytrace/data]
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_scheduler_health.php';

function st_sched_diag_usage(): void
{
    fwrite(STDOUT, "Usage: php scripts/diagnose_scheduler.php [--data-dir=/opt/surveytrace/data]\n");
}

$dataDir = dirname(__DIR__) . '/data';
foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--help' || $arg === '-h') {
        st_sched_diag_usage();
        exit(0);
    }
    if (str_starts_with($arg, '--data-dir=')) {
        $dataDir = (string) substr($arg, strlen('--data-dir='));
        continue;
    }
    fwrite(STDERR, "Unknown argument: {$arg}\n");
    st_sched_diag_usage();
    exit(2);
}

$dataDir = rtrim($dataDir, '/');
$installDir = dirname($dataDir);

$out = [
    'data_dir' => $dataDir,
    'install_dir' => $installDir,
    'surveytrace_scheduler_active' => null,
    'scheduler_status' => st_health_scheduler_runtime($dataDir),
    'db_open_check' => [
        'ran' => false,
        'exit_code' => null,
        'detail' => '',
    ],
    'due_scan_schedules' => [],
    'last_scheduled_scan_job' => null,
    'credential_jobs_due_sample' => [],
];

if (PHP_OS_FAMILY !== 'Windows' && function_exists('shell_exec')) {
    $df = @ini_get('disable_functions');
    $dfList = $df ? array_map('trim', explode(',', $df)) : [];
    if (! in_array('shell_exec', $dfList, true)) {
        $raw = @shell_exec('systemctl is-active surveytrace-scheduler.service 2>/dev/null');
        $out['surveytrace_scheduler_active'] = is_string($raw) ? trim($raw) : null;
    }
}

$py = $installDir . '/venv/bin/python3';
$schedPy = $installDir . '/daemon/scheduler_daemon.py';
if (is_executable($py) && is_file($schedPy)) {
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $prevInstall = getenv('SURVEYTRACE_INSTALL_DIR');
    putenv('SURVEYTRACE_INSTALL_DIR=' . $installDir);
    $proc = proc_open(
        [$py, $schedPy, '--check-db-open'],
        $spec,
        $pipes,
        $installDir,
        null,
    );
    if (is_resource($proc)) {
        fclose($pipes[0]);
        $stdout = (string) stream_get_contents($pipes[1]);
        $stderr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $rc = proc_close($proc);
        $out['db_open_check'] = [
            'ran' => true,
            'exit_code' => $rc,
            'detail' => $rc === 0 ? 'OK' : 'FAILED',
            'stderr_tail' => strlen($stderr) > 400 ? substr($stderr, 0, 400) . '…' : $stderr,
            'stdout_tail' => strlen($stdout) > 200 ? substr($stdout, 0, 200) . '…' : $stdout,
        ];
    }
    if ($prevInstall === false) {
        putenv('SURVEYTRACE_INSTALL_DIR');
    } else {
        putenv('SURVEYTRACE_INSTALL_DIR=' . (string) $prevInstall);
    }
} else {
    $out['db_open_check']['detail'] = 'venv python or scheduler_daemon.py not found at expected install paths';
}

$dbPath = $dataDir . '/surveytrace.db';
if (is_file($dbPath) && is_readable($dbPath)) {
    try {
        $pdo = new PDO('sqlite:' . $dbPath, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $pdo->exec('PRAGMA busy_timeout = 15000');
        $now = $pdo->query("SELECT datetime('now') AS n")->fetch()['n'] ?? '';
        $t = $pdo->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_schedules' LIMIT 1")->fetchColumn();
        if ($t) {
            $st = $pdo->prepare(
                "SELECT id, name, enabled, paused, cron_expr, next_run, missed_run_policy
                 FROM scan_schedules
                 WHERE enabled = 1 AND COALESCE(paused,0)=0 AND next_run IS NOT NULL AND next_run <= ?
                 ORDER BY next_run ASC LIMIT 20"
            );
            $st->execute([$now]);
            $out['due_scan_schedules'] = $st->fetchAll() ?: [];
        }
        $st2 = $pdo->query(
            "SELECT id, schedule_id, label, status, created_at, started_at
             FROM scan_jobs WHERE schedule_id IS NOT NULL AND schedule_id > 0
             ORDER BY id DESC LIMIT 1"
        );
        if ($st2) {
            $row = $st2->fetch();
            $out['last_scheduled_scan_job'] = is_array($row) ? $row : null;
        }
        $t3 = $pdo->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='credential_check_jobs' LIMIT 1")->fetchColumn();
        if ($t3) {
            try {
                $st3 = $pdo->query(
                    "SELECT id, name, schedule_enabled, schedule_next_run_at, schedule_cron
                     FROM credential_check_jobs
                     WHERE COALESCE(enabled,0)=1
                       AND COALESCE(schedule_enabled,0)=1
                       AND schedule_next_run_at IS NOT NULL
                       AND datetime(schedule_next_run_at) <= datetime('now')
                     ORDER BY schedule_next_run_at ASC LIMIT 10"
                );
                if ($st3) {
                    $out['credential_jobs_due_sample'] = $st3->fetchAll() ?: [];
                }
            } catch (Throwable $e2) {
                $out['credential_jobs_due_note'] = 'credential_check_jobs schedule columns unavailable: ' . $e2->getMessage();
            }
        }
    } catch (Throwable $e) {
        $out['database_query_error'] = $e->getMessage();
    }
}

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
exit(0);
