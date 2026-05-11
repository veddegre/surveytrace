<?php
/**
 * SurveyTrace — GET /api/health.php
 *
 * Read-only JSON for the System health tab: a quick operational picture (background services,
 * data directory space, app/NVD files, queue, feeds, and recent jobs). No configuration changes.
 * Low-level size/disk details live in st_health_* helpers.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/feed_sync_lib.php';
require_once __DIR__ . '/lib_scheduler_health.php';

st_auth();
if (st_config('security_health_requires_scan_editor', '0') === '1') {
    st_require_role(['scan_editor', 'admin']);
} else {
    st_require_role(['viewer', 'scan_editor', 'admin']);
}
st_method('GET');
st_release_session_lock();

/**
 * @return array{unit: string, state: string, detail: string}
 *   state: active | inactive | degraded | unknown
 */
function st_health_systemd_unit(string $unit): array {
    $out = [
        'unit' => $unit,
        'state' => 'unknown',
        'detail' => 'Not available (use Settings or SSH to verify services).',
    ];
    if (PHP_OS_FAMILY === 'Windows') {
        $out['detail'] = 'Not available on Windows.';
        return $out;
    }
    $df = @ini_get('disable_functions');
    $dfList = $df ? array_map('trim', explode(',', $df)) : [];
    if (in_array('shell_exec', $dfList, true) || !function_exists('shell_exec')) {
        return $out;
    }
    if (!preg_match('/^[a-zA-Z0-9@._-]+$/', $unit)) {
        $out['detail'] = 'Invalid unit name';
        return $out;
    }
    $raw = @shell_exec('systemctl is-active ' . escapeshellarg($unit) . ' 2>/dev/null');
    $s = is_string($raw) ? trim($raw) : '';
    if ($s === 'active') {
        $out['state'] = 'active';
        $out['detail'] = 'Running';
        return $out;
    }
    if ($s === 'inactive' || $s === 'failed') {
        $out['state'] = 'inactive';
        $out['detail'] = $s;
        return $out;
    }
    if ($s === 'activating' || $s === 'reloading') {
        $out['state'] = 'degraded';
        $out['detail'] = $s;
        return $out;
    }
    if ($s !== '') {
        $out['detail'] = $s;
    }
    return $out;
}

/**
 * Runtime signal emitted by daemon/collector_ingest_worker.py (status file in data/).
 *
 * @return array<string,mixed>
 */
function st_health_collector_ingest_runtime(string $dataDir): array {
    $out = [
        'status_file' => $dataDir . '/collector_ingest_status.json',
        'status_file_exists' => false,
        'state' => 'unknown',
        'updated_at' => '',
        'last_db_open_ok_at' => '',
        'last_loop_ok_at' => '',
        'last_claim_attempt_at' => '',
        'last_processed_at' => '',
        'last_db_open_error_at' => '',
        'db_open_error_count_consecutive' => 0,
        'db_open_error_total' => 0,
        'db_open_error_first_at' => '',
        'db_open_error_last_message' => '',
        'message' => '',
        'warnings' => [],
    ];
    $path = $out['status_file'];
    if (!is_file($path) || !is_readable($path)) {
        $out['warnings'][] = 'collector ingest runtime status file missing/unreadable.';
        return $out;
    }
    $raw = @file_get_contents($path);
    if (!is_string($raw) || trim($raw) === '') {
        $out['warnings'][] = 'collector ingest runtime status file is empty.';
        return $out;
    }
    $doc = json_decode($raw, true);
    if (!is_array($doc)) {
        $out['warnings'][] = 'collector ingest runtime status file is invalid JSON.';
        return $out;
    }
    $out['status_file_exists'] = true;
    foreach ([
        'state', 'updated_at', 'last_db_open_ok_at', 'last_loop_ok_at', 'last_claim_attempt_at',
        'last_processed_at', 'last_db_open_error_at', 'db_open_error_first_at',
        'db_open_error_last_message', 'message',
    ] as $k) {
        if (isset($doc[$k])) {
            $out[$k] = (string) $doc[$k];
        }
    }
    foreach (['db_open_error_count_consecutive', 'db_open_error_total'] as $k) {
        if (isset($doc[$k])) {
            $out[$k] = max(0, (int) $doc[$k]);
        }
    }
    $now = time();
    $updatedTs = strtotime((string) $out['updated_at']);
    $loopOkTs = strtotime((string) $out['last_loop_ok_at']);
    $dbOkTs = strtotime((string) $out['last_db_open_ok_at']);
    $dbErrTs = strtotime((string) $out['last_db_open_error_at']);
    if ($updatedTs !== false && ($now - $updatedTs) > 300) {
        $out['warnings'][] = 'collector ingest heartbeat stale (>5 minutes).';
    }
    if ($dbErrTs !== false && ($now - $dbErrTs) <= 600 && $out['db_open_error_count_consecutive'] > 0) {
        $out['warnings'][] = 'collector ingest observed recent SQLite open failures.';
    }
    if ($loopOkTs !== false && ($now - $loopOkTs) > 300) {
        $out['warnings'][] = 'collector ingest loop success timestamp stale (>5 minutes).';
    }
    if ($dbOkTs !== false && ($now - $dbOkTs) > 300) {
        $out['warnings'][] = 'collector ingest DB-open success timestamp stale (>5 minutes).';
    }
    return $out;
}

/**
 * Human size without (int) casts — they overflow for multi-GB on 32-bit PHP and
 * can corrupt filesize/stat results that wrap past 2^31.
 *
 * @param int|float|null $bytes
 */
function st_health_fmt_bytes($bytes): ?string {
    if ($bytes === null) {
        return null;
    }
    $x = (float) $bytes;
    if ($x < 0.0 || $x > 1.0e21) {
        return null;
    }
    if ($x < 1024) {
        return (string) (int) max(0, $x) . ' B';
    }
    $units = ['KB', 'MB', 'GB', 'TB', 'PB'];
    $exp = (int) floor(log($x, 1024));
    if ($exp < 1) {
        $exp = 1;
    }
    $ui = min($exp - 1, count($units) - 1);
    $v = $x / (1024 ** $exp);
    return round($v, $ui > 0 ? 1 : 0) . ' ' . $units[$ui];
}

/** Free space on the filesystem that contains this path. Uses float, never (int) cast. */
function st_health_disk_free_bytes(string $path): ?float {
    $p = $path;
    if (is_file($p)) {
        $p = dirname($p);
    } elseif (!is_dir($p)) {
        $p = dirname($p);
    }
    $rp = @realpath($p);
    if ($rp !== false) {
        $p = $rp;
    }
    if (!is_dir($p) || $p === '') {
        return null;
    }
    $v = @disk_free_space($p);
    if ($v === false) {
        return null;
    }
    $f = (float) $v;
    return $f >= 0.0 ? $f : null;
}

/**
 * File length as float. Avoids 32-bit filesize/ stat wrap. Falls back to fseek+ftell.
 */
function st_health_file_bytes(string $path): ?float {
    if (!is_file($path) || !is_readable($path)) {
        return null;
    }
    clearstatcache(true, $path);
    $fs = @filesize($path);
    if ($fs !== false) {
        // 32-bit PHP can return a negative int for large files; treat as unreliable.
        if (is_int($fs) && $fs < 0) {
            $fs = null;
        } else {
            return (float) $fs;
        }
    }
    $fh = @fopen($path, 'rb');
    if ($fh === false) {
        return null;
    }
    if (fseek($fh, 0, SEEK_END) !== 0) {
        fclose($fh);
        return null;
    }
    $pos = @ftell($fh);
    fclose($fh);
    if ($pos === false) {
        return null;
    }
    if (is_int($pos) && $pos < 0) {
        return null;
    }
    return (float) $pos;
}

/**
 * Prefer shell stat when it matches PHP; if stat is vastly larger than what PHP can read, trust PHP
 * (bind mounts, web SAPI path resolution, or bad metadata vs the openable file).
 *
 * @return array{0: ?float, 1: string}  [bytes, size_source: stat|filesize|fseek|none]
 */
function st_health_file_size_preferred(string $path): array {
    $st = st_health_stat_file_bytes($path);
    $ph = st_health_file_bytes($path);
    if ($st === null) {
        if ($ph === null) {
            return [null, 'none'];
        }
        return [$ph, 'filesize'];
    }
    if ($ph === null) {
        return [$st, 'stat'];
    }
    $stF = (float) $st;
    $phF = (float) $ph;
    if ($phF > 0.0 && $stF / $phF > 10.0 && $stF > 1024.0 * 1024.0 * 1024.0) {
        return [$ph, 'filesize'];
    }
    return [$st, 'stat'];
}

function st_health_shell_ok(): bool {
    if (PHP_OS_FAMILY === 'Windows') {
        return false;
    }
    $df = @ini_get('disable_functions');
    $list = $df ? array_map('trim', explode(',', $df)) : [];
    return !in_array('shell_exec', $list, true) && function_exists('shell_exec');
}

function st_health_cmd_available(string $cmd): bool {
    if (!st_health_shell_ok()) {
        return false;
    }
    $raw = @shell_exec('command -v ' . escapeshellarg($cmd) . ' 2>/dev/null');
    return is_string($raw) && trim($raw) !== '';
}

/**
 * “Available” column in 1K units from a df line. Strips thousands separators (locale) so
 * 15,903,544 and 15903544 both work.
 */
function st_health_df_avail_k_from_word(string $word): ?string {
    $n = str_replace([',', "'", '’', "\xC2\xA0"], '', trim($word));
    if ($n === '' || !ctype_digit($n)) {
        return null;
    }
    return $n;
}

/**
 * @return ?float  free bytes, or null
 */
function st_health_parse_df_koutput(string $out): ?float {
    $lines = array_values(
        array_filter(
            array_map('trim', preg_split("/\R/", trim($out))),
            static function ($l) {
                return $l !== '';
            }
        )
    );
    for ($i = count($lines) - 1; $i >= 0; $i--) {
        if (preg_match('/^filesystem/i', $lines[$i])) {
            continue;
        }
        $parts = preg_split('/\s+/', $lines[$i], -1, PREG_SPLIT_NO_EMPTY);
        if (count($parts) < 4) {
            continue;
        }
        $k = st_health_df_avail_k_from_word($parts[3]);
        if ($k === null) {
            continue;
        }
        return (float) $k * 1024.0;
    }
    return null;
}

/**
 * Free space (bytes) for the filesystem that contains $path, from `df -kP` “Available” × 1024.
 * Uses `LC_ALL=C` so numbers are not locale-formatted (commas break simple parsers).
 * Uses `awk` for field 4 when possible so the column is unambiguous. Falls back to PHP
 * line parsing of the same output with separator stripping.
 */
function st_health_df_free_bytes(string $path): ?float {
    if (!st_health_shell_ok()) {
        return null;
    }
    $test = is_dir($path) ? $path : dirname($path);
    $rp = @realpath($test);
    if ($rp === false) {
        return null;
    }
    $ep = escapeshellarg($rp);

    $tries = [
        "LC_ALL=C PATH=/bin:/usr/bin df -kP " . $ep . " 2>/dev/null | tail -n 1 | awk '{print \$4}'",
        "env -i LC_ALL=C PATH=/bin:/usr/bin df -kP " . $ep . " 2>/dev/null | tail -n 1 | awk '{print \$4}'",
        "LC_ALL=C /usr/bin/df -kP " . $ep . " 2>/dev/null | /usr/bin/tail -n 1 | /usr/bin/awk '{print \$4}'",
    ];
    foreach ($tries as $inner) {
        $o = @shell_exec('sh -c ' . escapeshellarg($inner));
        if (!is_string($o)) {
            continue;
        }
        $w = trim($o);
        if ($w === '') {
            continue;
        }
        $k = st_health_df_avail_k_from_word($w);
        if ($k !== null) {
            $b = (float) $k * 1024.0;
            if ($b >= 0.0) {
                return $b;
            }
        }
    }

    $dfTries = [
        'LC_ALL=C PATH=/bin:/usr/bin df -kP ' . $ep . ' 2>/dev/null',
        'env -i LC_ALL=C PATH=/bin:/usr/bin df -kP ' . $ep . ' 2>/dev/null',
        'LC_ALL=C /usr/bin/df -kP ' . $ep . ' 2>/dev/null',
        'LC_ALL=C /bin/df -kP ' . $ep . ' 2>/dev/null',
        'LC_ALL=C df -kP ' . $ep . ' 2>/dev/null',
    ];
    foreach ($dfTries as $cmd) {
        $out = @shell_exec($cmd);
        if (is_string($out) && trim($out) !== '') {
            $a = st_health_parse_df_koutput($out);
            if ($a !== null && $a >= 0.0) {
                return $a;
            }
        }
    }
    return null;
}

/** File size via POSIX stat (matches `ls` / `stat` on the host). */
function st_health_stat_file_bytes(string $path): ?float {
    if (!st_health_shell_ok() || !is_file($path)) {
        return null;
    }
    $rp = @realpath($path);
    if ($rp === false) {
        return null;
    }
    if (PHP_OS_FAMILY === 'Darwin') {
        $out = @shell_exec('stat -f %z ' . escapeshellarg($rp) . ' 2>/dev/null');
    } else {
        $out = @shell_exec('stat -c %s ' . escapeshellarg($rp) . ' 2>/dev/null');
    }
    if (!is_string($out)) {
        return null;
    }
    $s = trim($out);
    if ($s === '' || !ctype_digit($s)) {
        return null;
    }
    return (float) $s;
}

/**
 * Read-only operational maintenance snapshot for admin visibility.
 *
 * Counts only; no maintenance actions triggered here.
 *
 * @return array<string,mixed>
 */
function st_health_maintenance_snapshot(PDO $db): array {
    $out = [
        'tables_ready' => false,
        'secret_rewrap_candidates' => null,
        'operational_row_counts' => [
            'credential_check_results' => 0,
            'credential_check_artifacts' => 0,
            'worker_job_events' => 0,
            'worker_job_attempts' => 0,
            'reconciliation_runs' => 0,
        ],
        'stale_worker_job_candidates' => 0,
        'stale_running_attempt_candidates' => 0,
        'old_terminal_worker_jobs' => 0,
        'old_terminal_credential_runs' => 0,
        'warning_hints' => [],
        'summary' => 'Operational maintenance snapshot unavailable.',
    ];
    $hasWorker = false;
    $hasCred = false;
    $hasRecon = false;
    try {
        $hasWorker = $db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_jobs' LIMIT 1")->fetchColumn() !== false;
        $hasCred = $db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='credential_profiles' LIMIT 1")->fetchColumn() !== false;
        $hasRecon = $db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='reconciliation_runs' LIMIT 1")->fetchColumn() !== false;
    } catch (Throwable) {
        return $out;
    }
    $out['tables_ready'] = $hasWorker || $hasCred || $hasRecon;
    if (! $out['tables_ready']) {
        return $out;
    }

    try {
        if ($hasCred) {
            // Cheap string-based legacy-envelope heuristic (safe on old SQLite builds).
            $out['secret_rewrap_candidates'] = (int) $db->query(
                "SELECT COUNT(*)
                 FROM credential_profiles
                 WHERE deleted_at IS NULL
                   AND length(trim(COALESCE(secret_ciphertext,''))) > 0
                   AND (
                        (secret_ciphertext LIKE '%\"alg\":\"sodium_secretbox\"%' AND secret_ciphertext NOT LIKE '%\"ctxh\"%')
                        OR secret_ciphertext LIKE '%\"v\":0%'
                   )"
            )->fetchColumn();
        }

        if ($db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='credential_check_results' LIMIT 1")->fetchColumn() !== false) {
            $out['operational_row_counts']['credential_check_results'] = (int) $db->query("SELECT COUNT(*) FROM credential_check_results")->fetchColumn();
        }
        if ($db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='credential_check_artifacts' LIMIT 1")->fetchColumn() !== false) {
            $out['operational_row_counts']['credential_check_artifacts'] = (int) $db->query("SELECT COUNT(*) FROM credential_check_artifacts")->fetchColumn();
        }
        if ($db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_job_events' LIMIT 1")->fetchColumn() !== false) {
            $out['operational_row_counts']['worker_job_events'] = (int) $db->query("SELECT COUNT(*) FROM worker_job_events")->fetchColumn();
        }
        if ($db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_job_attempts' LIMIT 1")->fetchColumn() !== false) {
            $out['operational_row_counts']['worker_job_attempts'] = (int) $db->query("SELECT COUNT(*) FROM worker_job_attempts")->fetchColumn();
        }
        if ($hasRecon) {
            $out['operational_row_counts']['reconciliation_runs'] = (int) $db->query("SELECT COUNT(*) FROM reconciliation_runs")->fetchColumn();
        }

        if ($hasWorker) {
            $out['stale_worker_job_candidates'] = (int) $db->query(
                "SELECT COUNT(*)
                 FROM worker_jobs
                 WHERE status IN ('leased','running','retrying')
                   AND (
                     (lease_expires_at IS NOT NULL AND lease_expires_at <> '' AND lease_expires_at < datetime('now'))
                     OR COALESCE(updated_at, created_at, '1970-01-01 00:00:00') < datetime('now','-60 minutes')
                   )"
            )->fetchColumn();
            $out['stale_running_attempt_candidates'] = (int) $db->query(
                "SELECT COUNT(*)
                 FROM worker_job_attempts a
                 LEFT JOIN worker_jobs w ON w.id = a.job_id
                 WHERE a.status = 'running'
                   AND COALESCE(a.started_at, '1970-01-01 00:00:00') < datetime('now','-60 minutes')
                   AND (
                     w.id IS NULL
                     OR w.status IN ('leased','running','retrying','failed','cancelled','expired','completed')
                   )"
            )->fetchColumn();
            $out['old_terminal_worker_jobs'] = (int) $db->query(
                "SELECT COUNT(*) FROM worker_jobs
                 WHERE status IN ('completed','failed','cancelled','expired')
                   AND COALESCE(finished_at, updated_at, created_at, '1970-01-01 00:00:00') < datetime('now','-90 days')"
            )->fetchColumn();
        }

        if ($db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='credential_check_runs' LIMIT 1")->fetchColumn() !== false) {
            $out['old_terminal_credential_runs'] = (int) $db->query(
                "SELECT COUNT(*) FROM credential_check_runs
                 WHERE status IN ('completed','failed','cancelled','expired')
                   AND COALESCE(finished_at, started_at, '1970-01-01 00:00:00') < datetime('now','-90 days')"
            )->fetchColumn();
        }
    } catch (Throwable) {
        $out['summary'] = 'Operational maintenance snapshot unavailable.';
        return $out;
    }

    $c = $out['operational_row_counts'];
    $sumRows = ((int) $c['credential_check_results']) + ((int) $c['credential_check_artifacts'])
        + ((int) $c['worker_job_events']) + ((int) $c['worker_job_attempts']) + ((int) $c['reconciliation_runs']);
    $out['summary'] = 'Maintenance counts loaded: ' . $sumRows . ' tracked row(s) across retention-sensitive tables.';

    if (($out['secret_rewrap_candidates'] ?? 0) > 0) {
        $out['warning_hints'][] = (string) $out['secret_rewrap_candidates'] . ' credential profile secret envelope(s) appear to need manual rewrap.';
    }
    if ($out['stale_worker_job_candidates'] > 0) {
        $out['warning_hints'][] = (string) $out['stale_worker_job_candidates'] . ' stale worker job candidate(s) detected.';
    }
    if ($out['stale_running_attempt_candidates'] > 0) {
        $out['warning_hints'][] = (string) $out['stale_running_attempt_candidates'] . ' stale running worker attempt(s) detected.';
    }
    if ($out['old_terminal_worker_jobs'] > 250 || $out['old_terminal_credential_runs'] > 250) {
        $out['warning_hints'][] = 'Large old terminal run/job history detected; consider manual prune dry-run.';
    }
    if (((int) $c['worker_job_events']) > 50000 || ((int) $c['credential_check_results']) > 50000 || ((int) $c['reconciliation_runs']) > 50000) {
        $out['warning_hints'][] = 'One or more operational history tables exceed 50k rows; plan retention maintenance.';
    }

    return $out;
}

try {
    $db = st_db();
} catch (Throwable $e) {
    @error_log('SurveyTrace health DB error: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string)$e->getMessage()));
    st_json(['ok' => false, 'error' => 'database unavailable'], 503);
}

$dataDir = ST_DATA_DIR;
$appDb = ST_DB_PATH;
$nvdDb = $dataDir . '/nvd.db';
$isAdminHealth = st_current_role() === 'admin';

$health = [
    'ok' => true,
    'version' => ST_VERSION,
    'server_time' => date('c'),
    'php' => [
        'version' => PHP_VERSION,
        'sapi' => PHP_SAPI,
    ],
    'paths' => $isAdminHealth ? [
        'data_dir' => $dataDir,
        'app_db' => $appDb,
        'nvd_db' => $nvdDb,
    ] : [
        'detail' => 'Absolute filesystem paths are shown to admin role only.',
    ],
    'data_dir' => [
        'exists' => is_dir($dataDir),
        'writable' => is_dir($dataDir) && is_writable($dataDir),
    ],
    'disk' => [
        'data_dir_free_bytes' => null,
        'data_dir_free_human' => null,
        'source' => 'none', // df | unavailable
        'hint' => null,
    ],
    'database' => [
        'reachable' => true,
        'file_bytes' => null,
        'file_bytes_human' => null,
        'size_source' => 'none', // stat | filesize | fseek
    ],
    'nvd' => [
        'db_exists' => is_file($nvdDb),
        'db_bytes' => null,
        'db_bytes_human' => null,
        'size_source' => 'none',
        'last_config_sync' => st_config('nvd_last_sync', ''),
    ],
    'feeds' => [
        'job_running' => false,
        'job_target' => '',
        'last_result' => null,
    ],
    'scans' => [
        'queued' => 0,
        'running' => 0,
        'retrying' => 0,
        'failed_recent_24h' => 0,
        'stale_running_long' => 0,
    ],
    'last_completed_scan' => null,
    'schedules' => [
        'enabled_active' => 0,
        'table_ok' => false,
    ],
    'services' => [
        'daemon' => st_health_systemd_unit('surveytrace-daemon'),
        'scheduler' => st_health_systemd_unit('surveytrace-scheduler'),
        'collector_ingest' => st_health_systemd_unit('surveytrace-collector-ingest'),
    ],
    'collector_ingest_runtime' => [],
    'scheduler_runtime' => [],
    'collectors' => [
        'total' => 0,
        'online_recent_2m' => 0,
        'stale' => 0,
        'queued_chunks' => 0,
        'retrying_chunks' => 0,
        'failed_chunks' => 0,
        'processing_chunks' => 0,
        'eligible_pending_chunks' => 0,
        'blocked_pending_chunks' => 0,
        'oldest_pending_age_sec' => 0,
        'oldest_eligible_pending_age_sec' => 0,
        'oldest_failed_age_sec' => 0,
    ],
    'ai' => [
        'configured' => st_config('ai_enrichment_enabled', '0') === '1',
        'provider' => (string)st_config('ai_provider', 'ollama'),
        'model' => (string)st_config('ai_model', 'phi3:mini'),
        'timeout_ms' => max(100, min(5000, (int)st_config('ai_timeout_ms', '700'))),
        'installed' => false,
        'running' => false,
        'models' => [],
        'detail' => '',
    ],
];

$dfree = st_health_df_free_bytes($dataDir);
$health['disk']['source'] = 'none';
if ($dfree !== null) {
    $health['disk']['data_dir_free_bytes'] = $dfree;
    $health['disk']['data_dir_free_human'] = st_health_fmt_bytes($dfree);
    $health['disk']['source'] = 'df';
} else {
    $health['disk']['source'] = 'unavailable';
    $health['disk']['hint'] = 'Free space is not available in this view (server permissions or configuration).';
}

$appDbBytes = null;
$health['database']['size_source'] = 'none';
if (is_file($appDb)) {
    [$appDbBytes, $health['database']['size_source']] = st_health_file_size_preferred($appDb);
}
$health['database']['file_bytes'] = $appDbBytes;
$health['database']['file_bytes_human'] = st_health_fmt_bytes($appDbBytes);

$nvdDbBytes = null;
$health['nvd']['size_source'] = 'none';
if (is_file($nvdDb)) {
    [$nvdDbBytes, $health['nvd']['size_source']] = st_health_file_size_preferred($nvdDb);
}
$health['nvd']['db_bytes'] = $nvdDbBytes;
$health['nvd']['db_bytes_human'] = st_health_fmt_bytes($nvdDbBytes);

$fs = st_feed_sync_state_read();
$health['feeds']['job_running'] = !empty($fs['running']);
$health['feeds']['job_target'] = (string)($fs['target'] ?? '');

$last = st_feed_sync_last_result_read();
if (is_array($last)) {
    $health['feeds']['last_result'] = [
        'ok' => !empty($last['ok']),
        'cancelled' => !empty($last['cancelled']),
        'target' => (string)($last['target'] ?? ''),
        'finished_at' => (int)($last['finished_at'] ?? 0),
        'error' => (string)($last['error'] ?? ''),
    ];
}

try {
    $health['scans']['queued'] = (int)$db->query("SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued'")->fetchColumn();
    $health['scans']['running'] = (int)$db->query("SELECT COUNT(*) FROM scan_jobs WHERE status = 'running'")->fetchColumn();
    $health['scans']['retrying'] = (int)$db->query("SELECT COUNT(*) FROM scan_jobs WHERE status = 'retrying'")->fetchColumn();
    $health['scans']['failed_recent_24h'] = (int)$db->query(
        "SELECT COUNT(*) FROM scan_jobs
         WHERE status = 'failed'
           AND deleted_at IS NULL
           AND datetime(COALESCE(finished_at, started_at, created_at)) >= datetime('now', '-1 day')"
    )->fetchColumn();
    $health['scans']['stale_running_long'] = (int)$db->query(
        "SELECT COUNT(*) FROM scan_jobs
         WHERE status = 'running'
           AND deleted_at IS NULL
           AND datetime(COALESCE(started_at, created_at)) < datetime('now', '-4 hours')"
    )->fetchColumn();
} catch (Throwable $e) {
    // keep zeros
}
try {
    $health['collectors']['total'] = (int)$db->query("SELECT COUNT(*) FROM collectors")->fetchColumn();
    $health['collectors']['online_recent_2m'] = (int)$db->query(
        "SELECT COUNT(*) FROM collectors WHERE last_seen_at >= datetime('now','-120 seconds') AND COALESCE(revoked_at,'')=''"
    )->fetchColumn();
    $health['collectors']['stale'] = max(0, $health['collectors']['total'] - $health['collectors']['online_recent_2m']);
    $health['collectors']['queued_chunks'] = (int)$db->query(
        "SELECT COUNT(*) FROM collector_ingest_queue WHERE status='pending'"
    )->fetchColumn();
    $health['collectors']['failed_chunks'] = (int)$db->query(
        "SELECT COUNT(*) FROM collector_ingest_queue WHERE status='failed'"
    )->fetchColumn();
    $health['collectors']['processing_chunks'] = (int)$db->query(
        "SELECT COUNT(*) FROM collector_ingest_queue WHERE status='processing'"
    )->fetchColumn();
    $health['collectors']['retrying_chunks'] = (int)$db->query(
        "SELECT COUNT(*) FROM collector_ingest_queue WHERE status='failed' AND COALESCE(attempts,0) > 0"
    )->fetchColumn();
    $health['collectors']['eligible_pending_chunks'] = (int)$db->query(
        "SELECT COUNT(*) FROM collector_ingest_queue
         WHERE status='pending' AND (next_attempt_at IS NULL OR datetime(next_attempt_at) <= datetime('now'))"
    )->fetchColumn();
    $health['collectors']['blocked_pending_chunks'] = (int)$db->query(
        "SELECT COUNT(*) FROM collector_ingest_queue
         WHERE status='pending' AND next_attempt_at IS NOT NULL AND datetime(next_attempt_at) > datetime('now')"
    )->fetchColumn();
    $oldest = $db->query(
        "SELECT CAST((strftime('%s','now') - strftime('%s', MIN(created_at))) AS INTEGER)
         FROM collector_ingest_queue WHERE status='pending'"
    )->fetchColumn();
    $health['collectors']['oldest_pending_age_sec'] = max(0, (int)($oldest ?: 0));
    $oldestEligible = $db->query(
        "SELECT CAST((strftime('%s','now') - strftime('%s', MIN(created_at))) AS INTEGER)
         FROM collector_ingest_queue
         WHERE status='pending' AND (next_attempt_at IS NULL OR datetime(next_attempt_at) <= datetime('now'))"
    )->fetchColumn();
    $health['collectors']['oldest_eligible_pending_age_sec'] = max(0, (int)($oldestEligible ?: 0));
    $oldestFailed = $db->query(
        "SELECT CAST((strftime('%s','now') - strftime('%s', MIN(COALESCE(processed_at, created_at)))) AS INTEGER)
         FROM collector_ingest_queue WHERE status='failed'"
    )->fetchColumn();
    $health['collectors']['oldest_failed_age_sec'] = max(0, (int)($oldestFailed ?: 0));
} catch (Throwable $e) {
    // collectors not yet initialized.
}

$row = null;
try {
    $row = $db->query("
        SELECT id, status, target_cidr, label, created_at, started_at, finished_at,
               COALESCE(error_msg, '') AS error_msg,
               COALESCE(failure_reason, '') AS failure_reason
        FROM scan_jobs
        WHERE status IN ('done', 'failed', 'aborted')
        ORDER BY id DESC
        LIMIT 1
    ")->fetch(PDO::FETCH_ASSOC);
} catch (Throwable) {
    try {
        $row = $db->query("
            SELECT id, status, target_cidr, label, created_at, started_at, finished_at,
                   COALESCE(error_msg, '') AS error_msg
            FROM scan_jobs
            WHERE status IN ('done', 'failed', 'aborted')
            ORDER BY id DESC
            LIMIT 1
        ")->fetch(PDO::FETCH_ASSOC);
    } catch (Throwable) {
        $row = null;
    }
}
if (is_array($row)) {
    $health['last_completed_scan'] = $row;
}

try {
    $t = $db->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'scan_schedules' LIMIT 1")->fetchColumn();
    if ($t) {
        $health['schedules']['table_ok'] = true;
        $health['schedules']['enabled_active'] = (int)$db->query(
            "SELECT COUNT(*) FROM scan_schedules WHERE enabled = 1 AND COALESCE(paused, 0) = 0"
        )->fetchColumn();
    }
} catch (Throwable $e) {
    // leave defaults
}

$health['scheduler_runtime'] = st_health_scheduler_runtime($dataDir);
foreach (st_health_scheduler_schedule_tick_warnings($health['schedules'], $health['scheduler_runtime']) as $_st_sch_warn) {
    $health['scheduler_runtime']['warnings'][] = $_st_sch_warn;
}
if (
    $health['services']['scheduler']['state'] === 'active'
    && is_array($health['scheduler_runtime'])
    && !empty($health['scheduler_runtime']['warnings'])
) {
    $health['services']['scheduler']['state'] = 'degraded';
    $health['services']['scheduler']['detail'] = 'Running with runtime warnings (see scheduler_runtime).';
}

$aiProvHealth = (string)$health['ai']['provider'];
if ($aiProvHealth === 'ollama') {
    $health['ai']['installed'] = st_health_cmd_available('ollama');
    $apiModels = [];
    $tagsUrl = 'http://127.0.0.1:11434/api/tags';
    $tagsRaw = '';
    if (function_exists('curl_init')) {
        $ch = curl_init($tagsUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if (defined('CURLOPT_NOSIGNAL')) {
            curl_setopt($ch, CURLOPT_NOSIGNAL, true);
        }
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        $res = curl_exec($ch);
        if (is_string($res)) {
            $tagsRaw = $res;
        }
        curl_close($ch);
    }
    if ($tagsRaw === '') {
        $ctx = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 2,
            ],
        ]);
        $res = @file_get_contents($tagsUrl, false, $ctx);
        if (is_string($res)) {
            $tagsRaw = $res;
        }
    }
    if ($tagsRaw !== '') {
        $doc = json_decode($tagsRaw, true);
        if (is_array($doc) && isset($doc['models']) && is_array($doc['models'])) {
            foreach ($doc['models'] as $m) {
                if (!is_array($m)) continue;
                $name = trim((string)($m['name'] ?? ''));
                if ($name !== '') $apiModels[] = $name;
            }
        }
    }
    if ($apiModels) {
        $health['ai']['running'] = true;
        $health['ai']['models'] = array_values(array_unique($apiModels));
        $health['ai']['detail'] = 'ollama runtime reachable';
        if (!$health['ai']['installed']) {
            $health['ai']['installed'] = true;
        }
    } elseif ($health['ai']['installed']) {
        $rows = [];
        $code = 1;
        @exec('ollama list 2>&1', $rows, $code);
        if ($code === 0) {
            $health['ai']['running'] = true;
            $mods = [];
            foreach ($rows as $i => $line) {
                $line = trim((string)$line);
                if ($line === '') continue;
                if ($i === 0 && stripos($line, 'NAME') !== false) continue;
                $parts = preg_split('/\s+/', $line);
                if ($parts && !empty($parts[0])) {
                    $mods[] = (string)$parts[0];
                }
            }
            $health['ai']['models'] = array_values(array_unique($mods));
            $health['ai']['detail'] = 'ollama reachable';
        } else {
            $health['ai']['detail'] = 'ollama installed, runtime not responding';
        }
    } else {
        $health['ai']['detail'] = 'ollama not installed';
    }
} elseif (in_array($aiProvHealth, ['openai', 'anthropic', 'google', 'openwebui'], true)) {
    require_once __DIR__ . '/lib_ai_cloud.php';
    $health['ai']['installed'] = true;
    $cloudOk = st_ai_cloud_provider_ready($aiProvHealth);
    $health['ai']['running'] = $cloudOk;
    $health['ai']['models'] = [];
    if ($cloudOk) {
        $health['ai']['detail'] = $aiProvHealth === 'openwebui'
            ? 'Open WebUI: base URL and API key present (env or Settings)'
            : ('Cloud AI (' . $aiProvHealth . '): API key present (env or Settings)');
    } else {
        $health['ai']['detail'] = $aiProvHealth === 'openwebui'
            ? 'Open WebUI: set a valid http(s) base URL and API key (env or Settings)'
            : ('Cloud AI (' . $aiProvHealth . '): no API key in env or Settings');
    }
}

$health['ok'] = $health['data_dir']['writable'] && $health['database']['reachable'];

require_once __DIR__ . '/lib_worker_jobs.php';
$health['worker_substrate'] = st_worker_substrate_health_snapshot($db);

require_once __DIR__ . '/lib_credential_check_ops.php';
try {
    $health['credential_scheduler'] = st_cc_schedule_health_snapshot($db);
} catch (Throwable $e) {
    $health['credential_scheduler'] = [
        'tables_ready'         => false,
        'enabled_jobs'         => 0,
        'due_jobs'             => 0,
        'overdue_jobs'         => 0,
        'last_launch_utc'      => null,
        'last_tick_utc'        => null,
        'scheduler_runtime_ok' => false,
        'jobs_with_schedule_error' => 0,
        'warning_hints'        => ['Credential scheduler health unavailable.'],
    ];
    @error_log('SurveyTrace health credential_scheduler: ' . $e->getMessage());
}
try {
    $health['credential_check_runs'] = st_cc_health_snapshot_runs($db);
} catch (Throwable $e) {
    $health['credential_check_runs'] = [
        'tables_ready'                      => false,
        'queued_or_active'                  => 0,
        'running'                           => 0,
        'completed_recent_24h'              => 0,
        'failed_recent_24h'                 => 0,
        'partial_results_recent_24h'        => 0,
        'avg_duration_ms_completed_24h'     => null,
        'stale_active_runs'                 => 0,
        'enabled_jobs_on_disabled_profiles' => 0,
        'approx_result_rows'                => 0,
        'approx_artifact_rows'              => 0,
        'summary'                           => 'Credentialed check run health unavailable.',
        'warning_hints'                     => [],
    ];
    @error_log('SurveyTrace health credential_check_runs: ' . $e->getMessage());
}

require_once __DIR__ . '/lib_reconciliation.php';
require_once __DIR__ . '/lib_vulnerability_correlation.php';
try {
    $health['trusted_data'] = st_recon_health_snapshot($db);
} catch (Throwable $e) {
    $health['trusted_data'] = [
        'tables_ready'                       => false,
        'observation_count'                  => 0,
        'assertion_count'                    => 0,
        'identity_observation_count'         => 0,
        'identity_assertion_count'           => 0,
        'identity_hostname_conflict_assets'  => 0,
        'reconciliation_runs_total'          => 0,
        'failed_runs_24h'                    => 0,
        'last_failure_message'               => null,
        'stale_os_assertions_30d'            => 0,
        'credentialed_observation_count'     => 0,
        'stale_cred_os_observations_90d'     => 0,
        'software_inventory_summary_assets'           => 0,
        'software_inventory_summary_low_confidence'     => 0,
        'software_inventory_summary_stale_assets'       => 0,
        'software_inventory_summary_partial_assets'     => 0,
        'software_observed_without_summary_assets'      => 0,
        'software_inventory_summary_stale_evidence_90_180d_assets' => 0,
        'software_inventory_summary_stale_evidence_over_180d_assets' => 0,
        'software_inventory_assets_repeat_partial_pkg_inventory' => 0,
        'software_inventory_summary_reconciled_after_sw_obs_assets' => 0,
        'software_inventory_summary_without_bounded_sw_obs_assets' => 0,
        'software_inventory_rows_total'                 => 0,
        'software_inventory_latest_active_last_seen'      => null,
        'warning_hints'                      => ['Trusted data health snapshot unavailable.'],
    ];
    @error_log('SurveyTrace health trusted_data: ' . $e->getMessage());
}

try {
    $health['vulnerability_correlation'] = st_vuln_correlation_health_snapshot($db);
} catch (Throwable $e) {
    $health['vulnerability_correlation'] = [
        'tables_ready'                => false,
        'advisory_count'              => 0,
        'advisory_package_rules'      => 0,
        'affected_rows'               => 0,
        'distinct_vulnerable_assets' => 0,
        'stale_advisory_warning'      => false,
        'last_correlation_finished_at' => null,
        'last_correlation_duration_ms' => null,
        'last_correlation_status'     => null,
        'correlation_runtime_warning' => false,
        'queued_correlation_jobs'     => 0,
        'summary'                     => 'Vulnerability correlation health unavailable.',
        'warning_hints'               => [],
    ];
    @error_log('SurveyTrace health vulnerability_correlation: ' . $e->getMessage());
}

try {
    $health['vulnerability_triage'] = st_vt_health_snapshot($db);
} catch (Throwable $e) {
    $health['vulnerability_triage'] = [
        'tables_ready'                  => false,
        'counts_by_priority'           => [],
        'stale_suppressions'            => 0,
        'affected_without_triage'       => 0,
        'oldest_untriaged_first_seen'  => null,
        'high_priority_aging_30d'      => 0,
        'summary'                       => 'Vulnerability triage health unavailable.',
        'warning_hints'                 => [],
    ];
    @error_log('SurveyTrace health vulnerability_triage: ' . $e->getMessage());
}

try {
    $health['vulnerability_dashboard'] = st_vuln_dashboard_health_snapshot($db);
} catch (Throwable $e) {
    $health['vulnerability_dashboard'] = [
        'total_open_findings'     => 0,
        'critical_open_findings'  => 0,
        'stale_findings_over_30d' => 0,
        'suppressed_active'       => 0,
        'override_active'         => 0,
        'top_risk_asset_id'       => null,
        'warnings'                => ['Vulnerability dashboard health unavailable.'],
    ];
    @error_log('SurveyTrace health vulnerability_dashboard: ' . $e->getMessage());
}

$health['maintenance'] = st_health_maintenance_snapshot($db);
$health['collector_ingest_runtime'] = st_health_collector_ingest_runtime($dataDir);
if (
    $health['services']['collector_ingest']['state'] === 'active'
    && is_array($health['collector_ingest_runtime'])
    && !empty($health['collector_ingest_runtime']['warnings'])
) {
    $health['services']['collector_ingest']['state'] = 'degraded';
    $health['services']['collector_ingest']['detail'] = 'Running with runtime warnings (see collector_ingest_runtime).';
}

st_json($health);
