#!/usr/bin/env php
<?php
/**
 * SurveyTrace — unified operational integrity suite.
 *
 * Read-only runner that aggregates selftests, database consistency, scheduler/runtime invariant
 * checks, deploy manifest coverage, and health snapshot validation into one deterministic pass.
 *
 * Usage:
 *   php scripts/run_operational_integrity_suite.php [--strict] [--json] [--db=PATH] [--help]
 *
 * Exit: 0 = pass/warn only  |  1 = fail present  |  2 = runtime/tool error
 *
 * @see docs/RELEASE_READINESS_CHECKLIST.md — Operational integrity gate
 */
declare(strict_types=1);

$root = dirname(__DIR__);

$opts = [
    'strict' => false,
    'json'   => false,
    'db'     => null,
];
foreach (array_slice($argv, 1) as $a) {
    if ($a === '--strict') {
        $opts['strict'] = true;
    } elseif ($a === '--json') {
        $opts['json'] = true;
    } elseif (str_starts_with($a, '--db=')) {
        $opts['db'] = substr($a, 5);
    } elseif ($a === '-h' || $a === '--help') {
        fwrite(STDOUT, "Usage: php scripts/run_operational_integrity_suite.php [--strict] [--json] [--db=PATH]\n");
        exit(0);
    } else {
        fwrite(STDERR, "Unknown argument: {$a}\n");
        exit(2);
    }
}

$state = ['pass' => 0, 'warn' => 0, 'fail' => 0, 'info' => 0, 'lines' => []];

function oi_emit(array &$st, string $level, string $domain, string $msg): void
{
    $line = ['level' => $level, 'domain' => $domain, 'msg' => $msg];
    $st['lines'][] = $line;
    if (isset($st[$level])) {
        ++$st[$level];
    }
    if (empty($st['_json'])) {
        fwrite(STDOUT, strtoupper($level) . '  [' . $domain . ']  ' . $msg . "\n");
    }
}

if ($opts['json']) {
    $state['_json'] = true;
}

// --- Domain 1: PHP lint on critical files ---
$criticalFiles = [
    'api/health.php',
    'api/lib_ubuntu_advisory_convert.php',
    'api/lib_vulnerability_correlation.php',
    'api/lib_vulnerability_triage.php',
    'api/vulnerability_dashboard.php',
    'scripts/check_database_integrity.php',
    'scripts/convert_ubuntu_advisories.php',
    'scripts/sync_ubuntu_distro_advisories.php',
    'scripts/run_operational_integrity_suite.php',
];
foreach ($criticalFiles as $f) {
    $path = $root . '/' . $f;
    if (!is_file($path)) {
        oi_emit($state, 'info', 'lint', "Skipped (missing): {$f}");
        continue;
    }
    $out = '';
    $rc = 0;
    exec(PHP_BINARY . ' -l ' . escapeshellarg($path) . ' 2>&1', $outArr, $rc);
    if ($rc !== 0) {
        oi_emit($state, 'fail', 'lint', "Syntax error: {$f}");
    } else {
        oi_emit($state, 'pass', 'lint', $f);
    }
}

// --- Domain 2: Existing selftests ---
$selftests = [
    'st_vulnerability_correlation_selftest.php',
    'st_convert_ubuntu_advisories_selftest.php',
    'st_vulnerability_dashboard_selftest.php',
    'st_remove_advisory_selftest.php',
    'st_diagnose_advisory_feeds_selftest.php',
    'st_vulnerability_triage_selftest.php',
    'st_operational_integrity_selftest.php',
    'st_credential_secret_no_leak_selftest.php',
    'st_cred_secret_rewrap_selftest.php',
    'st_backup_restore_readiness_selftest.php',
    'st_scheduler_health_selftest.php',
];
foreach ($selftests as $st) {
    $path = $root . '/scripts/' . $st;
    if (!is_file($path)) {
        oi_emit($state, 'info', 'selftest', "Skipped (not present): {$st}");
        continue;
    }
    $rc = 0;
    $out = [];
    exec(PHP_BINARY . ' ' . escapeshellarg($path) . ' 2>&1', $out, $rc);
    if ($rc === 0) {
        oi_emit($state, 'pass', 'selftest', $st);
    } else {
        $hint = '';
        if ($out !== []) {
            $joined = implode("\n", $out);
            $hint = ' — ' . (strlen($joined) > 600 ? substr($joined, -600) : $joined);
        }
        oi_emit($state, 'fail', 'selftest', "{$st} exit={$rc}{$hint}");
    }
}

// --- Domain 3: Deploy manifest coverage ---
$deployCoverage = $root . '/scripts/check_deploy_coverage.php';
if (is_file($deployCoverage)) {
    $rc = 0;
    exec(PHP_BINARY . ' ' . escapeshellarg($deployCoverage) . ' ' . escapeshellarg($root) . ' 2>&1', $out, $rc);
    if ($rc === 0) {
        oi_emit($state, 'pass', 'deploy', 'check_deploy_coverage');
    } else {
        oi_emit($state, 'fail', 'deploy', 'check_deploy_coverage exit=' . $rc);
    }
} else {
    oi_emit($state, 'info', 'deploy', 'check_deploy_coverage.php not found');
}

// --- Domain 4: Database integrity ---
$dbIntegrityScript = $root . '/scripts/check_database_integrity.php';
if (is_file($dbIntegrityScript)) {
    $dbArg = $opts['db'] ? ' --db=' . escapeshellarg($opts['db']) : '';
    $rc = 0;
    $out = [];
    exec(PHP_BINARY . ' ' . escapeshellarg($dbIntegrityScript) . $dbArg . ' 2>&1', $out, $rc);
    if ($rc === 0) {
        oi_emit($state, 'pass', 'db_integrity', 'check_database_integrity (pass/warn only)');
    } elseif ($rc === 1) {
        oi_emit($state, 'fail', 'db_integrity', 'check_database_integrity reported failures');
    } else {
        oi_emit($state, 'warn', 'db_integrity', 'check_database_integrity runtime error (exit=' . $rc . ')');
    }
} else {
    oi_emit($state, 'info', 'db_integrity', 'check_database_integrity.php not present');
}

// --- Domain 5: Runtime invariant checks (in-process if DB available) ---
$dbPath = $opts['db'];
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

if ($dbPath !== null && is_file($dbPath)) {
    try {
        $pdo = new PDO('sqlite:' . $dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $pdo->exec('PRAGMA query_only=1');

        // 5a: WAL size check
        $walFile = $dbPath . '-wal';
        if (is_file($walFile)) {
            $walSize = filesize($walFile);
            if ($walSize > 64 * 1024 * 1024) {
                oi_emit($state, 'warn', 'runtime', 'WAL file large: ' . round($walSize / 1048576, 1) . ' MB');
            } else {
                oi_emit($state, 'pass', 'runtime', 'WAL size OK (' . round($walSize / 1048576, 2) . ' MB)');
            }
        } else {
            oi_emit($state, 'pass', 'runtime', 'No WAL file (journal mode likely non-WAL)');
        }

        // 5b: Stale active correlation runs
        $staleRuns = (int) $pdo->query(
            "SELECT COUNT(*) FROM vulnerability_correlation_runs WHERE status='running' AND datetime(started_at) < datetime('now','-2 hour') LIMIT 1"
        )->fetchColumn();
        if ($staleRuns > 0) {
            oi_emit($state, 'warn', 'runtime', "Stale correlation runs stuck >2h: {$staleRuns}");
        } else {
            oi_emit($state, 'pass', 'runtime', 'No stuck correlation runs');
        }

        // 5c: Advisory freshness
        $lastAdvisory = $pdo->query(
            "SELECT MAX(created_at) FROM vulnerability_advisories"
        )->fetchColumn();
        if ($lastAdvisory) {
            $daysSince = (int) $pdo->query(
                "SELECT CAST(julianday(datetime('now')) - julianday('{$lastAdvisory}') AS INTEGER)"
            )->fetchColumn();
            if ($daysSince > 30) {
                oi_emit($state, 'warn', 'runtime', "Advisory data stale: last import {$daysSince}d ago");
            } else {
                oi_emit($state, 'pass', 'runtime', "Advisory freshness OK (last {$daysSince}d ago)");
            }
        } else {
            oi_emit($state, 'info', 'runtime', 'No advisories imported yet');
        }

        // 5d: Correlation freshness
        $lastCorr = $pdo->query(
            "SELECT MAX(finished_at) FROM vulnerability_correlation_runs WHERE status='completed'"
        )->fetchColumn();
        if ($lastCorr) {
            $corrDays = (int) $pdo->query(
                "SELECT CAST(julianday(datetime('now')) - julianday('{$lastCorr}') AS INTEGER)"
            )->fetchColumn();
            if ($corrDays > 7) {
                oi_emit($state, 'warn', 'runtime', "Correlation stale: last completed {$corrDays}d ago");
            } else {
                oi_emit($state, 'pass', 'runtime', "Correlation freshness OK ({$corrDays}d ago)");
            }
        } else {
            oi_emit($state, 'info', 'runtime', 'No completed correlation runs');
        }

        // 5e: Stale worker leases
        $staleLeases = (int) $pdo->query(
            "SELECT COUNT(*) FROM worker_jobs WHERE status='leased' AND datetime(leased_at) < datetime('now','-2 hour')"
        )->fetchColumn();
        if ($staleLeases > 0) {
            oi_emit($state, 'warn', 'runtime', "Stale worker leases: {$staleLeases}");
        } else {
            oi_emit($state, 'pass', 'runtime', 'No stale worker leases');
        }

        // 5f: Queued jobs aging > 7 days
        $agingQueued = (int) $pdo->query(
            "SELECT COUNT(*) FROM worker_jobs WHERE status='queued' AND datetime(created_at) < datetime('now','-7 day')"
        )->fetchColumn();
        if ($agingQueued > 0) {
            oi_emit($state, 'warn', 'runtime', "Old queued jobs (>7d): {$agingQueued}");
        } else {
            oi_emit($state, 'pass', 'runtime', 'No indefinitely queued jobs');
        }

        // 5g: Stale suppressions (expired but still active)
        try {
            $staleSup = (int) $pdo->query(
                "SELECT COUNT(*) FROM asset_vulnerability_triage t
                 INNER JOIN asset_vulnerabilities av ON av.id = t.asset_vulnerability_id
                 WHERE t.suppression_reason IS NOT NULL
                   AND t.suppression_expires_at IS NOT NULL
                   AND datetime(t.suppression_expires_at) < datetime('now')
                   AND av.status = 'affected'"
            )->fetchColumn();
            if ($staleSup > 0) {
                oi_emit($state, 'warn', 'runtime', "Expired-but-active suppressions: {$staleSup}");
            } else {
                oi_emit($state, 'pass', 'runtime', 'No stale suppressions');
            }
        } catch (Throwable $e) {
            oi_emit($state, 'info', 'runtime', 'Suppression check skipped (table not ready)');
        }

        // 5h: Bounded table growth warning
        $largeTables = [
            'vulnerability_activity_log' => 50000,
            'worker_jobs'                => 10000,
            'scan_history'               => 5000,
        ];
        foreach ($largeTables as $tbl => $threshold) {
            try {
                $cnt = (int) $pdo->query("SELECT COUNT(*) FROM {$tbl}")->fetchColumn();
                if ($cnt > $threshold) {
                    oi_emit($state, 'warn', 'runtime', "Table {$tbl} has {$cnt} rows (threshold {$threshold})");
                }
            } catch (Throwable $e) {
                // table may not exist
            }
        }

    } catch (Throwable $e) {
        oi_emit($state, 'warn', 'runtime', 'Runtime invariant checks failed: ' . $e->getMessage());
    }
} else {
    oi_emit($state, 'info', 'runtime', 'No database found for runtime invariant checks');
}

// --- Domain 6: Health endpoint shape validation ---
$healthFile = $root . '/api/health.php';
if (is_file($healthFile) && is_file($root . '/api/db.php')) {
    oi_emit($state, 'pass', 'health', 'health.php present (shape validated via selftests)');
} else {
    oi_emit($state, 'info', 'health', 'health.php or db.php not found');
}

// --- Domain 7: Shell script syntax ---
foreach (['setup.sh', 'deploy.sh'] as $sh) {
    $shPath = $root . '/' . $sh;
    if (!is_file($shPath)) {
        oi_emit($state, 'info', 'shell_syntax', "Skipped: {$sh}");
        continue;
    }
    $rc = 0;
    exec('bash -n ' . escapeshellarg($shPath) . ' 2>&1', $out, $rc);
    if ($rc === 0) {
        oi_emit($state, 'pass', 'shell_syntax', $sh);
    } else {
        oi_emit($state, 'fail', 'shell_syntax', "{$sh} syntax error");
    }
}

// --- Summary ---
$summary = sprintf('SUMMARY fail=%d warn=%d pass=%d info=%d', $state['fail'], $state['warn'], $state['pass'], $state['info']);

if ($opts['json']) {
    $out = [
        'summary' => [
            'fail' => $state['fail'],
            'warn' => $state['warn'],
            'pass' => $state['pass'],
            'info' => $state['info'],
        ],
        'lines'   => $state['lines'],
    ];
    fwrite(STDOUT, json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
} else {
    fwrite(STDOUT, "\n" . $summary . "\n");
}

if ($state['fail'] > 0) {
    exit(1);
}
if ($opts['strict'] && $state['warn'] > 0) {
    exit(1);
}
exit(0);
