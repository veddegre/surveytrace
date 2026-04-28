<?php
/**
 * SurveyTrace — GET /api/health.php
 *
 * Read-only system status: data paths, disk, DB, services (systemd when available),
 * scan queue, feed sync state, last completed job. Used by the System health tab.
 *
 * Free space: `df -kP` and the same 1K-block “Available” value as plain `df` (× 1024 → bytes).
 * File sizes: `stat` when it matches PHP; PHP’s filesize can misreport in some SAPIs.
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
        'source' => 'none', // df | disk_free_space | unavailable
        'df_path' => null, // realpath used for df (compare with: df -h <path> in SSH)
        'avail_1k' => null, // 1K-block “Available” (same as plain df) when source is df
        'hint' => null, // set when free space could not be determined reliably
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

$dfPathFor = is_dir($dataDir) ? $dataDir : dirname($dataDir);
$dfRp = @realpath($dfPathFor);
$health['disk']['df_path'] = $dfRp !== false ? $dfRp : (string) $dfPathFor;

$dfree = st_health_df_free_bytes($dataDir);
$health['disk']['source'] = 'none';
if ($dfree !== null) {
    $health['disk']['data_dir_free_bytes'] = $dfree;
    $health['disk']['data_dir_free_human'] = st_health_fmt_bytes($dfree);
    $health['disk']['source'] = 'df';
    $health['disk']['avail_1k'] = (int) round($dfree / 1024.0);
} else {
    $health['disk']['source'] = 'unavailable';
    $health['disk']['hint'] = 'Health uses only `df` (1K “Available” × 1024), not PHP disk space. The web process could not run/parse it (e.g. shell_exec, AppArmor, or as www-data: `LC_ALL=C df -kP` the data path).';
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
