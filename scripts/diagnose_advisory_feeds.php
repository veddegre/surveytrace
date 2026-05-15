<?php
/**
 * Read-only advisory feed operations aggregator (CLI).
 *
 * Summarizes NVD sync/bridge, vendor advisory imports, correlation runtime,
 * dashboard/triage posture, and test-advisory pollution — no network, imports,
 * deletes, or correlation execution.
 *
 * Usage:
 *   php scripts/diagnose_advisory_feeds.php [--db=PATH] [--install-root=/opt/surveytrace]
 *
 * @see docs/wiki/vulnerability-advisory-runbook.md
 */
declare(strict_types=1);

if (! defined('ST_DIAG_ADVISORY_FEEDS_NO_MAIN')) {
    require_once dirname(__DIR__) . '/api/db.php';
    require_once dirname(__DIR__) . '/api/lib_vulnerability_correlation.php';
    require_once dirname(__DIR__) . '/api/lib_vulnerability_triage.php';
}

/**
 * @return array{install_root: string, data_dir: string, surveytrace_db: string, nvd_db: string, feed_sync_result: string}
 */
function st_diag_af_resolve_paths(?string $installRoot, ?string $dbPath): array
{
    $root = $installRoot !== null && $installRoot !== ''
        ? rtrim($installRoot, '/')
        : dirname(__DIR__);
    $dataDir = $root . '/data';

    return [
        'install_root'      => $root,
        'data_dir'          => $dataDir,
        'surveytrace_db'    => ($dbPath !== null && $dbPath !== '') ? $dbPath : $dataDir . '/surveytrace.db',
        'nvd_db'            => $dataDir . '/nvd.db',
        'feed_sync_result'  => $dataDir . '/feed_sync_result.json',
    ];
}

/**
 * Read config from `config` or legacy `st_config` (first hit).
 */
function st_diag_af_config_get(PDO $pdo, string $key): ?string
{
    foreach (['config', 'st_config'] as $table) {
        try {
            $t = $pdo->query(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=" . $pdo->quote($table)
            )->fetchColumn();
            if (! $t) {
                continue;
            }
            $st = $pdo->prepare("SELECT value FROM {$table} WHERE key = ? LIMIT 1");
            $st->execute([$key]);
            $v = $st->fetchColumn();
            if ($v !== false && $v !== null && (string) $v !== '') {
                return (string) $v;
            }
        } catch (Throwable $e) {
            continue;
        }
    }

    return null;
}

/**
 * @return array<string, mixed>
 */
function st_diag_af_probe_nvd_db(string $path): array
{
    $out = [
        'path'              => $path,
        'exists'            => is_file($path),
        'readable'          => false,
        'size_bytes'        => null,
        'mtime_utc'         => null,
        'cve_count'         => null,
        'cpe_link_count'    => null,
        'sync_meta'         => [],
        'probe_error'       => null,
    ];
    if (! $out['exists']) {
        return $out;
    }
    $out['readable'] = is_readable($path);
    if (! $out['readable']) {
        $out['probe_error'] = 'not_readable';

        return $out;
    }
    $sz = @filesize($path);
    $out['size_bytes'] = $sz !== false ? (int) $sz : null;
    $mt = @filemtime($path);
    $out['mtime_utc'] = $mt !== false ? gmdate('Y-m-d\\TH:i:s\\Z', $mt) : null;

    try {
        $nvd = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
        $nvd->exec('PRAGMA query_only=1');
        $out['cve_count'] = (int) $nvd->query('SELECT COUNT(*) FROM cves')->fetchColumn();
        $hasCpe = $nvd->query(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cpe_cve' LIMIT 1"
        )->fetchColumn();
        if ($hasCpe) {
            $out['cpe_link_count'] = (int) $nvd->query('SELECT COUNT(*) FROM cpe_cve')->fetchColumn();
        }
        $hasMeta = $nvd->query(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_meta' LIMIT 1"
        )->fetchColumn();
        if ($hasMeta) {
            $rows = $nvd->query('SELECT key, value FROM sync_meta ORDER BY key ASC')->fetchAll(PDO::FETCH_ASSOC) ?: [];
            foreach ($rows as $r) {
                if (! is_array($r)) {
                    continue;
                }
                $out['sync_meta'][(string) ($r['key'] ?? '')] = $r['value'] ?? null;
            }
        }
    } catch (Throwable $e) {
        $out['probe_error'] = 'sqlite_probe_failed';
    }

    return $out;
}

/**
 * @return array<string, mixed>|null
 */
function st_diag_af_feed_sync_summary(string $path): ?array
{
    if (! is_file($path) || ! is_readable($path)) {
        return null;
    }
    $raw = @file_get_contents($path);
    if ($raw === false) {
        return ['parse_ok' => false, 'error' => 'read_failed'];
    }
    $j = json_decode($raw, true);
    if (! is_array($j)) {
        return ['parse_ok' => false, 'error' => 'invalid_json'];
    }
    $summary = [
        'parse_ok'    => true,
        'ok'          => isset($j['ok']) ? (bool) $j['ok'] : null,
        'cancelled'   => ! empty($j['cancelled']),
        'finished_at' => isset($j['finished_at']) ? (string) $j['finished_at'] : null,
        'nvd'         => null,
    ];
    $results = isset($j['results']) && is_array($j['results']) ? $j['results'] : [];
    foreach ($results as $row) {
        if (! is_array($row)) {
            continue;
        }
        $script = (string) ($row['script'] ?? '');
        if ($script !== 'sync_nvd.py') {
            continue;
        }
        $summary['nvd'] = [
            'ok'         => isset($row['ok']) ? (bool) $row['ok'] : null,
            'exit_code'  => isset($row['exit_code']) ? (int) $row['exit_code'] : null,
            'cancelled'  => ! empty($row['cancelled']),
            'output_len' => strlen((string) ($row['output'] ?? '')),
        ];
        break;
    }

    return $summary;
}

/**
 * Suggest a single safe operator next step (no side effects).
 *
 * @param array<string, mixed> $ctx
 */
function st_diag_af_suggest_next_action(array $ctx): string
{
    $testCve = (int) ($ctx['cve_test_count'] ?? 0);
    $testSample = (int) ($ctx['sample_source_count'] ?? 0);
    if ($testCve > 0 || $testSample > 0) {
        return 'remove_test_advisories';
    }

    $nvdExists = ! empty($ctx['nvd_db_exists']);
    if (! $nvdExists) {
        return 'run_nvd_sync';
    }

    $bridgeAt = $ctx['nvd_bridge_last_import_at'] ?? null;
    if ($bridgeAt === null || $bridgeAt === '') {
        return 'run_nvd_bridge';
    }

    $vendorRules = (int) ($ctx['vendor_distro_package_rule_count'] ?? 0);
    if ($vendorRules === 0) {
        return 'import_vendor_advisories';
    }

    $activeInv = (int) ($ctx['active_inventory_rows'] ?? 0);
    if ($activeInv === 0 && $vendorRules > 0) {
        return 'collect_credentialed_inventory';
    }

    $queued = (int) ($ctx['queued_correlation_jobs'] ?? 0);
    if ($queued > 0) {
        return 'run_correlation';
    }

    $lastCorr = $ctx['last_correlation_finished_at'] ?? null;
    if ($activeInv > 0 && $vendorRules > 0 && ($lastCorr === null || $lastCorr === '')) {
        return 'run_correlation';
    }

    if ($activeInv > 0 && $vendorRules > 0 && isset($ctx['correlation_stale_days']) && (float) $ctx['correlation_stale_days'] > 7.0) {
        return 'run_correlation';
    }

    return 'no_action';
}

/**
 * @return array<string, mixed>
 */
function st_diag_af_aggregate(PDO $pdo, array $paths): array
{
    $warnings = [];
    $generatedAt = gmdate('Y-m-d\\TH:i:s\\Z');

    $nvdLocal = st_diag_af_probe_nvd_db($paths['nvd_db']);
    $nvdLastSync = st_diag_af_config_get($pdo, 'nvd_last_sync');
    $feedSync = st_diag_af_feed_sync_summary($paths['feed_sync_result']);

    $nvdFeed = [
        'local_nvd_db'           => $nvdLocal,
        'surveytrace_nvd_last_sync' => $nvdLastSync,
        'last_feed_sync_result'  => $feedSync,
    ];
    if (! $nvdLocal['exists']) {
        $warnings[] = 'data/nvd.db is missing; run NVD feed sync (Settings → Sync NVD, or daemon/sync_nvd.py).';
    } elseif (! $nvdLocal['readable']) {
        $warnings[] = 'data/nvd.db exists but is not readable by this user.';
    }

    $corr = st_vuln_correlation_health_snapshot($pdo);
    foreach ($corr['warning_hints'] ?? [] as $hint) {
        $s = trim((string) $hint);
        if ($s !== '') {
            $warnings[] = $s;
        }
    }

    $bridgeAt = $corr['nvd_bridge_last_import_at'] ?? st_diag_af_config_get($pdo, 'nvd_bridge_last_modified_at');
    $nvdBridge = [
        'nvd_bridge_last_import_at'       => $bridgeAt,
        'nvd_metadata_only_advisory_count' => (int) ($corr['nvd_metadata_only_advisory_count'] ?? 0),
        'nvd_db_exists'                   => (bool) ($nvdLocal['exists'] && $nvdLocal['readable']),
        'bridge_never_ran'                => ($nvdLocal['exists'] && $nvdLocal['readable'] && ($bridgeAt === null || $bridgeAt === '')),
    ];
    if ($nvdBridge['bridge_never_ran']) {
        $warnings[] = 'NVD database (data/nvd.db) exists but NVD metadata bridge has not run. Run: php scripts/import_nvd_from_local_db.php --apply';
    }

    $advisorySummary = [
        'tables_ready'                         => (bool) ($corr['tables_ready'] ?? false),
        'advisory_count'                       => (int) ($corr['advisory_count'] ?? 0),
        'advisory_package_rules'               => (int) ($corr['advisory_package_rules'] ?? 0),
        'package_authority_counts'             => $corr['package_authority_counts'] ?? [],
        'advisory_sources_loaded'              => $corr['advisory_sources_loaded'] ?? [],
        'last_advisory_import_by_source'       => $corr['last_advisory_import_by_source'] ?? [],
        'advisory_package_rules_by_ecosystem_release' => $corr['advisory_package_rules_by_ecosystem_release'] ?? [],
        'stale_advisory_warning'               => (bool) ($corr['stale_advisory_warning'] ?? false),
    ];

    $rulesMissingFixed = null;
    if ($advisorySummary['tables_ready']) {
        try {
            $rulesMissingFixed = (int) $pdo->query(
                "SELECT COUNT(*) FROM vulnerability_advisory_packages p
                 INNER JOIN vulnerability_advisories a ON a.id = p.advisory_id
                 WHERE IFNULL(a.withdrawn, 0) = 0
                   AND IFNULL(a.package_authority, 'internal') IN ('vendor_distro', 'internal')
                   AND (p.fixed_version IS NULL OR trim(IFNULL(p.fixed_version, '')) = '')"
            )->fetchColumn();
            if ($rulesMissingFixed > 0) {
                $warnings[] = $rulesMissingFixed . ' vendor/internal package rule(s) lack fixed_version (correlation may be incomplete).';
            }
        } catch (Throwable $e) {
            $rulesMissingFixed = null;
        }
    }

    $vendorRules = [
        'vendor_distro_package_rule_count'   => (int) ($corr['vendor_distro_package_rule_count'] ?? 0),
        'ubuntu_vendor_package_rules'        => (int) ($corr['ubuntu_vendor_package_rules'] ?? 0),
        'internal_policy_package_rule_count' => (int) ($corr['internal_policy_package_rule_count'] ?? 0),
        'rules_missing_fixed_version'        => $rulesMissingFixed,
    ];

    $correlationRuntime = [
        'queued_correlation_jobs'      => (int) ($corr['queued_correlation_jobs'] ?? 0),
        'last_correlation_finished_at' => $corr['last_correlation_finished_at'] ?? null,
        'last_correlation_duration_ms' => $corr['last_correlation_duration_ms'] ?? null,
        'last_correlation_status'      => $corr['last_correlation_status'] ?? null,
        'correlation_runtime_warning'  => (bool) ($corr['correlation_runtime_warning'] ?? false),
        'affected_rows'                => (int) ($corr['affected_rows'] ?? 0),
        'distinct_vulnerable_assets'   => (int) ($corr['distinct_vulnerable_assets'] ?? 0),
    ];
    if ($correlationRuntime['queued_correlation_jobs'] > 0) {
        $warnings[] = $correlationRuntime['queued_correlation_jobs'] . ' vulnerability_correlation worker job(s) queued.';
    }

    $dashHealth = st_vuln_dashboard_health_snapshot($pdo);
    foreach ($dashHealth['warnings'] ?? [] as $w) {
        $s = trim((string) $w);
        if ($s !== '') {
            $warnings[] = $s;
        }
    }

    $triage = st_vt_health_snapshot($pdo);
    foreach ($triage['warning_hints'] ?? [] as $hint) {
        $s = trim((string) $hint);
        if ($s !== '') {
            $warnings[] = $s;
        }
    }

    $staleDashboard = [];
    try {
        if ($advisorySummary['tables_ready']) {
            $oldCount = (int) $pdo->query(
                "SELECT COUNT(*) FROM vulnerability_advisories WHERE IFNULL(withdrawn,0)=0
                 AND modified_at IS NOT NULL AND datetime(modified_at) < datetime('now', '-365 day')"
            )->fetchColumn();
            if ($oldCount > 0) {
                $staleDashboard[] = $oldCount . ' advisories have modified_at older than 365 days.';
            }
        }
    } catch (Throwable $e) {
        $staleDashboard[] = 'stale advisory age check failed';
    }

    $dashboardTriage = [
        'total_open_findings'        => (int) ($dashHealth['total_open_findings'] ?? 0),
        'critical_open_findings'     => (int) ($dashHealth['critical_open_findings'] ?? 0),
        'distinct_vulnerable_assets'   => (int) ($correlationRuntime['distinct_vulnerable_assets']),
        'counts_by_priority'         => $triage['counts_by_priority'] ?? [],
        'stale_findings_over_30d'  => (int) ($dashHealth['stale_findings_over_30d'] ?? 0),
        'stale_data_warnings'        => $staleDashboard,
        'suppressed_active'          => (int) ($dashHealth['suppressed_active'] ?? 0),
        'override_active'            => (int) ($dashHealth['override_active'] ?? 0),
    ];

    $testPollution = [
        'cve_test_count'       => 0,
        'sample_source_count'  => 0,
        'test_advisory_keys'   => [],
    ];
    if ($advisorySummary['tables_ready']) {
        try {
            $testPollution['cve_test_count'] = (int) $pdo->query(
                "SELECT COUNT(*) FROM vulnerability_advisories
                 WHERE IFNULL(withdrawn,0)=0 AND advisory_key LIKE 'CVE-TEST-%'"
            )->fetchColumn();
            $testPollution['sample_source_count'] = (int) $pdo->query(
                "SELECT COUNT(*) FROM vulnerability_advisories
                 WHERE IFNULL(withdrawn,0)=0 AND lower(trim(source)) = 'sample'"
            )->fetchColumn();
            $keys = $pdo->query(
                "SELECT advisory_key FROM vulnerability_advisories
                 WHERE IFNULL(withdrawn,0)=0
                   AND (advisory_key LIKE 'CVE-TEST-%' OR lower(trim(source)) = 'sample')
                 ORDER BY advisory_key ASC LIMIT 20"
            )->fetchAll(PDO::FETCH_COLUMN) ?: [];
            $testPollution['test_advisory_keys'] = array_values(array_map('strval', $keys));
        } catch (Throwable $e) {
            $warnings[] = 'Test advisory pollution check failed.';
        }
    }
    if ($testPollution['cve_test_count'] > 0 || $testPollution['sample_source_count'] > 0) {
        $warnings[] = 'Test/sample advisories present (CVE-TEST-* or source=sample); remove before production.';
    }

    $activeInventory = 0;
    try {
        $t = $pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='software_inventory_asset_state' LIMIT 1"
        )->fetchColumn();
        if ($t) {
            $activeInventory = (int) $pdo->query(
                'SELECT COUNT(*) FROM software_inventory_asset_state WHERE active = 1'
            )->fetchColumn();
        }
    } catch (Throwable $e) {
        $activeInventory = 0;
    }

    $correlationStaleDays = null;
    $lastFin = $correlationRuntime['last_correlation_finished_at'];
    if ($lastFin !== null && $lastFin !== '') {
        try {
            $age = $pdo->prepare("SELECT (julianday(datetime('now')) - julianday(?)) AS d");
            $age->execute([$lastFin]);
            $correlationStaleDays = (float) $age->fetchColumn();
            if ($correlationStaleDays > 7.0) {
                $warnings[] = 'Last correlation run was ' . round($correlationStaleDays, 1) . ' days ago.';
            }
        } catch (Throwable $e) {
            $correlationStaleDays = null;
        }
    } elseif ($advisorySummary['tables_ready'] && $vendorRules['vendor_distro_package_rule_count'] > 0) {
        $warnings[] = 'No completed correlation runs found.';
    }

    $nextAction = st_diag_af_suggest_next_action([
        'cve_test_count'                    => $testPollution['cve_test_count'],
        'sample_source_count'               => $testPollution['sample_source_count'],
        'nvd_db_exists'                     => $nvdBridge['nvd_db_exists'],
        'nvd_bridge_last_import_at'         => $bridgeAt,
        'vendor_distro_package_rule_count'  => $vendorRules['vendor_distro_package_rule_count'],
        'advisory_count'                    => $advisorySummary['advisory_count'],
        'active_inventory_rows'             => $activeInventory,
        'queued_correlation_jobs'           => $correlationRuntime['queued_correlation_jobs'],
        'last_correlation_finished_at'      => $lastFin,
        'correlation_stale_days'            => $correlationStaleDays,
    ]);

    return [
        'generated_at'          => $generatedAt,
        'install_root'          => $paths['install_root'],
        'surveytrace_db'        => $paths['surveytrace_db'],
        'surveytrace_db_exists' => is_file($paths['surveytrace_db']),
        'nvd_feed'              => $nvdFeed,
        'nvd_bridge'            => $nvdBridge,
        'advisory_summary'      => $advisorySummary,
        'vendor_rules'          => $vendorRules,
        'correlation_runtime'   => $correlationRuntime,
        'dashboard_triage'      => $dashboardTriage,
        'test_pollution'        => $testPollution,
        'active_inventory_rows' => $activeInventory,
        'warnings'              => array_values(array_unique($warnings)),
        'next_action'           => $nextAction,
        'summary'               => 'Advisory feed operations snapshot (read-only; no imports or correlation executed).',
    ];
}

/**
 * @param list<string> $argv
 */
function st_diag_advisory_feeds_main(array $argv): void
{
    $installRoot = null;
    $dbPath = null;
    foreach (array_slice($argv, 1) as $arg) {
        if (str_starts_with($arg, '--install-root=')) {
            $installRoot = substr($arg, 15);
            continue;
        }
        if (str_starts_with($arg, '--db=')) {
            $dbPath = substr($arg, 5);
            continue;
        }
        if ($arg === '-h' || $arg === '--help') {
            fwrite(STDOUT, "Usage: php scripts/diagnose_advisory_feeds.php [--db=PATH] [--install-root=/opt/surveytrace]\n");
            exit(0);
        }
        fwrite(STDERR, "Unknown argument: {$arg}\n");
        exit(2);
    }

    $paths = st_diag_af_resolve_paths($installRoot, $dbPath);
    $explicitDb = $dbPath !== null && $dbPath !== '';

    if ($explicitDb) {
        if (! is_file($paths['surveytrace_db'])) {
            fwrite(STDERR, "Database not found: {$paths['surveytrace_db']}\n");
            exit(1);
        }
        $pdo = new PDO('sqlite:' . $paths['surveytrace_db'], null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
    } elseif (is_file($paths['surveytrace_db'])) {
        $pdo = new PDO('sqlite:' . $paths['surveytrace_db'], null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
    } else {
        $pdo = st_db();
        $paths['surveytrace_db'] = $paths['data_dir'] . '/surveytrace.db';
    }

    $pdo->exec('PRAGMA foreign_keys=ON');
    try {
        $pdo->exec('PRAGMA query_only=1');
    } catch (Throwable $e) {
        // Older SQLite builds may not support query_only; continue read-only by convention.
    }

    $out = st_diag_af_aggregate($pdo, $paths);
    echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    exit(0);
}

if (! defined('ST_DIAG_ADVISORY_FEEDS_NO_MAIN')) {
    st_diag_advisory_feeds_main($argv);
}
