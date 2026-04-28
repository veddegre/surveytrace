<?php
/**
 * SurveyTrace — GET /api/health.php
 *
 * Read-only system status: data paths, disk, DB, services (systemd when available),
 * scan queue, feed sync state, last completed job. For the dashboard “System health” panel.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/feed_sync_lib.php';

st_auth();
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
    $e = (int) min(
        (int) floor(log($x, 1024)),
        count($units) - 1
    );
    if ($e < 0) {
        $e = 0;
    }
    $v = $x / (1024 ** $e);
    return round($v, $e > 0 ? 1 : 0) . ' ' . $units[$e];
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

try {
    $db = st_db();
} catch (Throwable $e) {
    st_json(['ok' => false, 'error' => 'database: ' . $e->getMessage()], 503);
}

$dataDir = ST_DATA_DIR;
$appDb = ST_DB_PATH;
$nvdDb = $dataDir . '/nvd.db';

$health = [
    'ok' => true,
    'version' => ST_VERSION,
    'server_time' => date('c'),
    'php' => [
        'version' => PHP_VERSION,
        'sapi' => PHP_SAPI,
    ],
    'paths' => [
        'data_dir' => $dataDir,
        'app_db' => $appDb,
        'nvd_db' => $nvdDb,
    ],
    'data_dir' => [
        'exists' => is_dir($dataDir),
        'writable' => is_dir($dataDir) && is_writable($dataDir),
    ],
    'disk' => [
        'data_dir_free_bytes' => null,
        'data_dir_free_human' => null,
    ],
    'database' => [
        'reachable' => true,
        'file_bytes' => null,
        'file_bytes_human' => null,
    ],
    'nvd' => [
        'db_exists' => is_file($nvdDb),
        'db_bytes' => null,
        'db_bytes_human' => null,
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
    ],
    'last_completed_scan' => null,
    'schedules' => [
        'enabled_active' => 0,
        'table_ok' => false,
    ],
    'services' => [
        'daemon' => st_health_systemd_unit('surveytrace-daemon'),
        'scheduler' => st_health_systemd_unit('surveytrace-scheduler'),
    ],
];

$dfree = st_health_disk_free_bytes($dataDir);
if ($dfree !== null) {
    $health['disk']['data_dir_free_bytes'] = $dfree;
    $health['disk']['data_dir_free_human'] = st_health_fmt_bytes($dfree);
}

$appDbBytes = is_file($appDb) ? st_health_file_bytes($appDb) : null;
$health['database']['file_bytes'] = $appDbBytes;
$health['database']['file_bytes_human'] = st_health_fmt_bytes($appDbBytes);

$nvdDbBytes = is_file($nvdDb) ? st_health_file_bytes($nvdDb) : null;
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
} catch (Throwable $e) {
    // keep zeros
}

$row = $db->query("
    SELECT id, status, target_cidr, label, created_at, started_at, finished_at
    FROM scan_jobs
    WHERE status IN ('done', 'failed', 'aborted')
    ORDER BY id DESC
    LIMIT 1
")->fetch(PDO::FETCH_ASSOC);
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

$health['ok'] = $health['data_dir']['writable'] && $health['database']['reachable'];

st_json($health);
