#!/usr/bin/env php
<?php
/**
 * SurveyTrace — operational integrity diagnostics (JSON output).
 *
 * Collects latest integrity results, stale components, scheduler/worker state,
 * vulnerability state, DB health indicators, and warning rollup.
 *
 * Usage:
 *   php scripts/diagnose_operational_integrity.php [--db=PATH]
 *
 * @see docs/wiki/troubleshooting.md
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$dbPath = null;

foreach (array_slice($argv, 1) as $a) {
    if (str_starts_with($a, '--db=')) {
        $dbPath = substr($a, 5);
    } elseif ($a === '-h' || $a === '--help') {
        fwrite(STDOUT, "Usage: php scripts/diagnose_operational_integrity.php [--db=PATH]\n");
        exit(0);
    }
}

if ($dbPath === null) {
    $candidates = [
        $root . '/data/surveytrace.db',
        '/opt/surveytrace/data/surveytrace.db',
    ];
    foreach ($candidates as $c) {
        if (is_file($c)) {
            $dbPath = $c;
            break;
        }
    }
}

$diag = [
    'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
    'db_path'      => $dbPath,
    'db_exists'    => $dbPath !== null && is_file($dbPath),
    'db_health'    => null,
    'scheduler_state' => null,
    'worker_state'    => null,
    'vulnerability_state' => null,
    'stale_components'    => [],
    'warning_rollup'      => [],
];

if (!$diag['db_exists']) {
    $diag['warning_rollup'][] = 'Database not found; diagnostics limited.';
    fwrite(STDOUT, json_encode($diag, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    exit(0);
}

try {
    $pdo = new PDO('sqlite:' . $dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->exec('PRAGMA query_only=1');
} catch (Throwable $e) {
    $diag['warning_rollup'][] = 'Failed to open database: ' . $e->getMessage();
    fwrite(STDOUT, json_encode($diag, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    exit(0);
}

// DB health
$dbHealth = [];
try {
    $ic = $pdo->query("PRAGMA integrity_check")->fetchColumn();
    $dbHealth['integrity_check'] = ($ic === 'ok') ? 'ok' : 'failed';
} catch (Throwable $e) {
    $dbHealth['integrity_check'] = 'error';
}
$walFile = $dbPath . '-wal';
$dbHealth['wal_exists'] = is_file($walFile);
$dbHealth['wal_size_mb'] = $dbHealth['wal_exists'] ? round(filesize($walFile) / 1048576, 2) : 0;
$dbHealth['db_size_mb'] = round(filesize($dbPath) / 1048576, 2);
$diag['db_health'] = $dbHealth;

// Scheduler state
try {
    $sched = [];
    $sched['total_jobs'] = (int) $pdo->query("SELECT COUNT(*) FROM worker_jobs")->fetchColumn();
    $sched['queued'] = (int) $pdo->query("SELECT COUNT(*) FROM worker_jobs WHERE status='queued'")->fetchColumn();
    $sched['leased'] = (int) $pdo->query("SELECT COUNT(*) FROM worker_jobs WHERE status='leased'")->fetchColumn();
    $sched['completed'] = (int) $pdo->query("SELECT COUNT(*) FROM worker_jobs WHERE status='completed'")->fetchColumn();
    $sched['failed'] = (int) $pdo->query("SELECT COUNT(*) FROM worker_jobs WHERE status='failed'")->fetchColumn();
    $sched['stale_leases'] = (int) $pdo->query(
        "SELECT COUNT(*) FROM worker_jobs WHERE status='leased' AND datetime(leased_at) < datetime('now','-2 hour')"
    )->fetchColumn();
    $sched['old_queued_7d'] = (int) $pdo->query(
        "SELECT COUNT(*) FROM worker_jobs WHERE status='queued' AND datetime(created_at) < datetime('now','-7 day')"
    )->fetchColumn();
    $diag['scheduler_state'] = $sched;
    if ($sched['stale_leases'] > 0) {
        $diag['stale_components'][] = 'worker_leases';
        $diag['warning_rollup'][] = "Stale worker leases: {$sched['stale_leases']}";
    }
    if ($sched['old_queued_7d'] > 0) {
        $diag['stale_components'][] = 'queued_jobs';
        $diag['warning_rollup'][] = "Old queued jobs (>7d): {$sched['old_queued_7d']}";
    }
} catch (Throwable $e) {
    $diag['scheduler_state'] = ['error' => $e->getMessage()];
}

// Worker state (most recent jobs)
try {
    $worker = [];
    $recent = $pdo->query(
        "SELECT id, job_type, status, created_at, finished_at FROM worker_jobs ORDER BY id DESC LIMIT 10"
    )->fetchAll(PDO::FETCH_ASSOC);
    $worker['recent_jobs'] = $recent;
    $diag['worker_state'] = $worker;
} catch (Throwable $e) {
    $diag['worker_state'] = ['error' => $e->getMessage()];
}

// Vulnerability state
try {
    $vuln = [];
    $vuln['advisory_count'] = (int) $pdo->query("SELECT COUNT(*) FROM vulnerability_advisories")->fetchColumn();
    $vuln['package_rule_count'] = (int) $pdo->query("SELECT COUNT(*) FROM vulnerability_advisory_packages")->fetchColumn();
    $vuln['affected_count'] = (int) $pdo->query(
        "SELECT COUNT(*) FROM asset_vulnerabilities WHERE status='affected'"
    )->fetchColumn();
    $vuln['fixed_count'] = (int) $pdo->query(
        "SELECT COUNT(*) FROM asset_vulnerabilities WHERE status='fixed'"
    )->fetchColumn();
    $vuln['last_correlation_at'] = $pdo->query(
        "SELECT MAX(finished_at) FROM vulnerability_correlation_runs WHERE status='completed'"
    )->fetchColumn() ?: null;
    $vuln['last_advisory_import_at'] = $pdo->query(
        "SELECT MAX(created_at) FROM vulnerability_advisories"
    )->fetchColumn() ?: null;
    $vuln['stale_correlation'] = false;
    if ($vuln['last_correlation_at']) {
        $days = (int) $pdo->query(
            "SELECT CAST(julianday(datetime('now')) - julianday('" . $vuln['last_correlation_at'] . "') AS INTEGER)"
        )->fetchColumn();
        if ($days > 7) {
            $vuln['stale_correlation'] = true;
            $diag['stale_components'][] = 'correlation';
            $diag['warning_rollup'][] = "Correlation stale ({$days}d since last run)";
        }
    }
    $diag['vulnerability_state'] = $vuln;
} catch (Throwable $e) {
    $diag['vulnerability_state'] = ['error' => $e->getMessage()];
}

fwrite(STDOUT, json_encode($diag, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
exit(0);
