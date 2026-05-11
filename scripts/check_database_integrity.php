#!/usr/bin/env php
<?php
/**
 * SurveyTrace — bounded, read-only SQLite database integrity checker.
 *
 * No mutations. Outputs PASS/WARN/FAIL lines with a final SUMMARY.
 *
 * Usage:
 *   php scripts/check_database_integrity.php [--db=/path/to/surveytrace.db] [--json] [--strict]
 *
 * Exit: 0 = PASS/WARN only (strict: WARN also fails). 1 = FAIL present. 2 = tool/runtime error.
 */
declare(strict_types=1);

/**
 * @return array{db_path:string, json:bool, strict:bool}
 */
function st_dbi_parse_argv(array $argv): array
{
    $out = [
        'db_path' => dirname(__DIR__) . '/data/surveytrace.db',
        'json'    => false,
        'strict'  => false,
    ];
    foreach (array_slice($argv, 1) as $a) {
        if ($a === '--json') {
            $out['json'] = true;
            continue;
        }
        if ($a === '--strict') {
            $out['strict'] = true;
            continue;
        }
        if (str_starts_with($a, '--db=')) {
            $out['db_path'] = substr($a, strlen('--db='));
            continue;
        }
        if ($a === '--help' || $a === '-h') {
            fwrite(STDOUT, "Usage: php scripts/check_database_integrity.php [--db=PATH] [--json] [--strict]\n");
            exit(0);
        }
        fwrite(STDERR, "Unknown argument: {$a}\n");
        exit(2);
    }
    return $out;
}

/**
 * @param array{pass:int,warn:int,fail:int,lines:list<array{level:string,msg:string}>} $st
 */
function st_dbi_emit(array &$st, string $level, string $msg): void
{
    $lvl = strtoupper($level);
    if (!in_array($lvl, ['PASS', 'WARN', 'FAIL', 'INFO'], true)) {
        $lvl = 'WARN';
    }
    if (empty($st['_json'])) {
        fwrite(STDOUT, str_pad($lvl, 4) . "  {$msg}\n");
    }
    $st['lines'][] = ['level' => strtolower($lvl), 'msg' => $msg];
    match ($lvl) {
        'PASS' => ++$st['pass'],
        'WARN' => ++$st['warn'],
        'FAIL' => ++$st['fail'],
        default => null,
    };
}

function st_dbi_has_table(PDO $pdo, string $name): bool
{
    $s = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1");
    $s->execute([$name]);
    return $s->fetchColumn() !== false;
}

/**
 * Run all checks against the given database.
 *
 * @return array{pass:int,warn:int,fail:int,lines:list<array{level:string,msg:string}>}
 */
function st_dbi_run(string $dbPath, bool $jsonMode): array
{
    $st = ['pass' => 0, 'warn' => 0, 'fail' => 0, 'lines' => [], '_json' => $jsonMode];

    if (!is_file($dbPath) || !is_readable($dbPath)) {
        st_dbi_emit($st, 'fail', 'Database file not found or not readable: ' . $dbPath);
        return $st;
    }

    try {
        $pdo = new PDO('sqlite:' . $dbPath, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $pdo->exec('PRAGMA busy_timeout = 30000');
        $pdo->exec('PRAGMA query_only = 1');
    } catch (Throwable $e) {
        st_dbi_emit($st, 'fail', 'Cannot open database: ' . $e->getMessage());
        return $st;
    }

    // 1. PRAGMA integrity_check
    try {
        $rows = $pdo->query('PRAGMA integrity_check(20)')->fetchAll(PDO::FETCH_COLUMN, 0);
        if ($rows === ['ok']) {
            st_dbi_emit($st, 'pass', 'PRAGMA integrity_check: ok');
        } else {
            $detail = implode('; ', array_slice($rows ?: [], 0, 5));
            st_dbi_emit($st, 'fail', 'PRAGMA integrity_check failed: ' . $detail);
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'fail', 'PRAGMA integrity_check error: ' . $e->getMessage());
    }

    // 2. Orphan asset_vulnerabilities (advisory_id → vulnerability_advisories)
    try {
        if (st_dbi_has_table($pdo, 'asset_vulnerabilities') && st_dbi_has_table($pdo, 'vulnerability_advisories')) {
            $n = (int) $pdo->query(
                "SELECT COUNT(*) FROM (
                    SELECT av.id FROM asset_vulnerabilities av
                    LEFT JOIN vulnerability_advisories va ON va.id = av.advisory_id
                    WHERE va.id IS NULL
                    LIMIT 100
                )"
            )->fetchColumn();
            if ($n > 0) {
                st_dbi_emit($st, 'warn', 'Orphan asset_vulnerabilities rows (advisory_id not in vulnerability_advisories): ' . $n . ($n >= 100 ? '+' : ''));
            } else {
                st_dbi_emit($st, 'pass', 'No orphan asset_vulnerabilities (advisory_id FK)');
            }
        } else {
            st_dbi_emit($st, 'info', 'Skipped orphan asset_vulnerabilities check (table missing)');
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'warn', 'Orphan asset_vulnerabilities check error: ' . $e->getMessage());
    }

    // 3. Orphan triage rows (asset_vulnerability_id → asset_vulnerabilities)
    try {
        if (st_dbi_has_table($pdo, 'asset_vulnerability_triage') && st_dbi_has_table($pdo, 'asset_vulnerabilities')) {
            $n = (int) $pdo->query(
                "SELECT COUNT(*) FROM (
                    SELECT t.id FROM asset_vulnerability_triage t
                    LEFT JOIN asset_vulnerabilities av ON av.id = t.asset_vulnerability_id
                    WHERE av.id IS NULL
                    LIMIT 100
                )"
            )->fetchColumn();
            if ($n > 0) {
                st_dbi_emit($st, 'warn', 'Orphan triage rows (asset_vulnerability_id not in asset_vulnerabilities): ' . $n . ($n >= 100 ? '+' : ''));
            } else {
                st_dbi_emit($st, 'pass', 'No orphan triage rows');
            }
        } else {
            st_dbi_emit($st, 'info', 'Skipped orphan triage check (table missing)');
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'warn', 'Orphan triage check error: ' . $e->getMessage());
    }

    // 4. Duplicate advisory keys
    try {
        if (st_dbi_has_table($pdo, 'vulnerability_advisories')) {
            $dupes = $pdo->query(
                "SELECT advisory_key, COUNT(*) AS cnt
                 FROM vulnerability_advisories
                 GROUP BY advisory_key
                 HAVING COUNT(*) > 1
                 LIMIT 50"
            )->fetchAll();
            if (count($dupes) > 0) {
                $sample = array_map(fn(array $r) => $r['advisory_key'] . '(x' . $r['cnt'] . ')', array_slice($dupes, 0, 5));
                st_dbi_emit($st, 'fail', 'Duplicate advisory_key in vulnerability_advisories: ' . count($dupes) . ' keys — ' . implode(', ', $sample));
            } else {
                st_dbi_emit($st, 'pass', 'No duplicate advisory_key values');
            }
        } else {
            st_dbi_emit($st, 'info', 'Skipped duplicate advisory_key check (table missing)');
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'warn', 'Duplicate advisory_key check error: ' . $e->getMessage());
    }

    // 5. Stale worker leases (leased > 2 hours ago)
    try {
        if (st_dbi_has_table($pdo, 'worker_jobs')) {
            $n = (int) $pdo->query(
                "SELECT COUNT(*) FROM (
                    SELECT id FROM worker_jobs
                    WHERE status = 'leased'
                      AND leased_at < datetime('now', '-2 hours')
                    LIMIT 100
                )"
            )->fetchColumn();
            if ($n > 0) {
                st_dbi_emit($st, 'warn', 'Stale worker leases (leased >2h ago): ' . $n . ($n >= 100 ? '+' : ''));
            } else {
                st_dbi_emit($st, 'pass', 'No stale worker leases');
            }
        } else {
            st_dbi_emit($st, 'info', 'Skipped stale worker lease check (table missing)');
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'warn', 'Stale worker lease check error: ' . $e->getMessage());
    }

    // 6. Stale queued jobs (queued > 7 days ago)
    try {
        if (st_dbi_has_table($pdo, 'worker_jobs')) {
            $n = (int) $pdo->query(
                "SELECT COUNT(*) FROM (
                    SELECT id FROM worker_jobs
                    WHERE status = 'queued'
                      AND created_at < datetime('now', '-7 days')
                    LIMIT 100
                )"
            )->fetchColumn();
            if ($n > 0) {
                st_dbi_emit($st, 'warn', 'Stale queued jobs (queued >7d ago): ' . $n . ($n >= 100 ? '+' : ''));
            } else {
                st_dbi_emit($st, 'pass', 'No stale queued jobs');
            }
        } else {
            st_dbi_emit($st, 'info', 'Skipped stale queued jobs check (table missing)');
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'warn', 'Stale queued jobs check error: ' . $e->getMessage());
    }

    // 7. Invalid asset_vulnerabilities.status values
    try {
        if (st_dbi_has_table($pdo, 'asset_vulnerabilities')) {
            $bad = $pdo->query(
                "SELECT DISTINCT status FROM (
                    SELECT status FROM asset_vulnerabilities
                    WHERE status NOT IN ('affected','fixed','ignored')
                    LIMIT 50
                )"
            )->fetchAll(PDO::FETCH_COLUMN, 0);
            if (count($bad) > 0) {
                st_dbi_emit($st, 'fail', 'Invalid asset_vulnerabilities.status values: ' . implode(', ', array_map(fn($v) => var_export($v, true), $bad)));
            } else {
                st_dbi_emit($st, 'pass', 'All asset_vulnerabilities.status values valid');
            }
        } else {
            st_dbi_emit($st, 'info', 'Skipped status validation (table missing)');
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'warn', 'Status validation error: ' . $e->getMessage());
    }

    // 8. Invalid priority_source values
    try {
        if (st_dbi_has_table($pdo, 'asset_vulnerability_triage')) {
            $bad = $pdo->query(
                "SELECT DISTINCT priority_source FROM (
                    SELECT priority_source FROM asset_vulnerability_triage
                    WHERE priority_source NOT IN ('model','analyst_override')
                    LIMIT 50
                )"
            )->fetchAll(PDO::FETCH_COLUMN, 0);
            if (count($bad) > 0) {
                st_dbi_emit($st, 'warn', 'Invalid priority_source values: ' . implode(', ', array_map(fn($v) => var_export($v, true), $bad)));
            } else {
                st_dbi_emit($st, 'pass', 'All priority_source values valid');
            }
        } else {
            st_dbi_emit($st, 'info', 'Skipped priority_source validation (table missing)');
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'warn', 'priority_source validation error: ' . $e->getMessage());
    }

    // 9. Malformed explain_json
    try {
        if (st_dbi_has_table($pdo, 'asset_vulnerabilities')) {
            $rows = $pdo->query(
                "SELECT id, explain_json FROM asset_vulnerabilities
                 WHERE explain_json IS NOT NULL AND explain_json != ''
                 LIMIT 50"
            )->fetchAll();
            $malformed = 0;
            foreach ($rows as $row) {
                if (!is_string($row['explain_json'])) {
                    continue;
                }
                json_decode($row['explain_json']);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    ++$malformed;
                }
            }
            if ($malformed > 0) {
                st_dbi_emit($st, 'warn', 'Malformed explain_json in asset_vulnerabilities: ' . $malformed . ' rows (sampled first 50 non-empty)');
            } else {
                st_dbi_emit($st, 'pass', 'No malformed explain_json detected (sampled first 50)');
            }
        } else {
            st_dbi_emit($st, 'info', 'Skipped explain_json check (table missing)');
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'warn', 'explain_json check error: ' . $e->getMessage());
    }

    // 10. Broken advisory→package relationships
    try {
        if (st_dbi_has_table($pdo, 'vulnerability_advisory_packages') && st_dbi_has_table($pdo, 'vulnerability_advisories')) {
            $n = (int) $pdo->query(
                "SELECT COUNT(*) FROM (
                    SELECT p.id FROM vulnerability_advisory_packages p
                    LEFT JOIN vulnerability_advisories va ON va.id = p.advisory_id
                    WHERE va.id IS NULL
                    LIMIT 100
                )"
            )->fetchColumn();
            if ($n > 0) {
                st_dbi_emit($st, 'fail', 'Broken advisory→package FK (advisory_id not in vulnerability_advisories): ' . $n . ($n >= 100 ? '+' : ''));
            } else {
                st_dbi_emit($st, 'pass', 'No broken advisory→package relationships');
            }
        } else {
            st_dbi_emit($st, 'info', 'Skipped advisory→package FK check (table missing)');
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'warn', 'Advisory→package FK check error: ' . $e->getMessage());
    }

    // 11. Expired active suppressions (sweep hasn't run)
    try {
        if (st_dbi_has_table($pdo, 'asset_vulnerability_triage') && st_dbi_has_table($pdo, 'asset_vulnerabilities')) {
            $n = (int) $pdo->query(
                "SELECT COUNT(*) FROM (
                    SELECT t.id
                    FROM asset_vulnerability_triage t
                    JOIN asset_vulnerabilities av ON av.id = t.asset_vulnerability_id
                    WHERE t.suppression_reason IS NOT NULL
                      AND t.suppression_expires_at IS NOT NULL
                      AND datetime(t.suppression_expires_at) < datetime('now')
                      AND av.status = 'affected'
                    LIMIT 100
                )"
            )->fetchColumn();
            if ($n > 0) {
                st_dbi_emit($st, 'warn', 'Expired active suppressions still joined to affected rows: ' . $n . ($n >= 100 ? '+' : '') . ' (suppression sweep may not have run)');
            } else {
                st_dbi_emit($st, 'pass', 'No expired active suppressions on affected rows');
            }
        } else {
            st_dbi_emit($st, 'info', 'Skipped expired suppression check (table missing)');
        }
    } catch (Throwable $e) {
        st_dbi_emit($st, 'warn', 'Expired suppression check error: ' . $e->getMessage());
    }

    // 12. WAL file size
    $walPath = $dbPath . '-wal';
    if (is_file($walPath)) {
        $walBytes = (int) filesize($walPath);
        $walMB = round($walBytes / 1024 / 1024, 1);
        if ($walBytes > 64 * 1024 * 1024) {
            st_dbi_emit($st, 'warn', 'WAL file is large: ' . $walMB . ' MiB (>64 MiB) — consider PRAGMA wal_checkpoint');
        } else {
            st_dbi_emit($st, 'pass', 'WAL file size OK (' . $walMB . ' MiB)');
        }
    } else {
        st_dbi_emit($st, 'pass', 'No WAL file present (journal_mode is likely not WAL, or DB is clean)');
    }

    return $st;
}

try {
    $opts = st_dbi_parse_argv($argv);
    $st = st_dbi_run($opts['db_path'], $opts['json']);

    $summary = 'SUMMARY: fail=' . $st['fail'] . ' warn=' . $st['warn'] . ' pass=' . $st['pass'];
    if ($opts['json']) {
        fwrite(STDOUT, json_encode([
            'summary' => ['fail' => $st['fail'], 'warn' => $st['warn'], 'pass' => $st['pass']],
            'lines'   => $st['lines'],
        ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n");
    } else {
        fwrite(STDOUT, $summary . "\n");
    }

    if ($st['fail'] > 0) {
        exit(1);
    }
    if ($opts['strict'] && $st['warn'] > 0) {
        exit(1);
    }
    exit(0);
} catch (Throwable $e) {
    fwrite(STDERR, 'check_database_integrity: ' . $e->getMessage() . "\n");
    exit(2);
}
