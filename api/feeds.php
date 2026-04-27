<?php
/**
 * SurveyTrace — /api/feeds.php
 *
 * POST /api/feeds.php?sync=1
 * Body: {"target":"nvd"|"oui"|"webfp"|"all"}
 *
 * Runs fingerprint feed sync scripts on demand and returns stdout/stderr.
 */

require_once __DIR__ . '/db.php';
st_auth();
$db = st_db();

$lockPath   = ST_DATA_DIR . '/feed_sync.lock.json';
$statusPath = ST_DATA_DIR . '/feed_sync.status.json';
$logPath    = ST_DATA_DIR . '/feed_sync.last.log';

function st_pid_running(int $pid): bool {
    if ($pid <= 1) return false;
    if (function_exists('posix_kill')) {
        return @posix_kill($pid, 0);
    }
    $out = [];
    $code = 1;
    exec('ps -p ' . (int)$pid . ' >/dev/null 2>&1', $out, $code);
    return $code === 0;
}

if (isset($_GET['status'])) {
    st_method('GET');
    $running = false;
    $lock = null;
    if (is_file($lockPath)) {
        $raw = @file_get_contents($lockPath);
        $lock = $raw ? json_decode($raw, true) : null;
        $pid = (int)($lock['pid'] ?? 0);
        $running = st_pid_running($pid);
        if (!$running) {
            @unlink($lockPath);
        }
    }
    $status = [];
    if (is_file($statusPath)) {
        $raw = @file_get_contents($statusPath);
        $status = $raw ? (json_decode($raw, true) ?: []) : [];
    }
    $output = '';
    if (is_file($logPath)) {
        $raw = @file_get_contents($logPath);
        if ($raw !== false) {
            $max = 120000;
            $output = strlen($raw) > $max ? substr($raw, -$max) : $raw;
        }
    }
    st_json([
        'ok' => true,
        'running' => $running,
        'target' => $status['target'] ?? ($lock['target'] ?? ''),
        'started_at' => $status['started_at'] ?? ($lock['started_at'] ?? ''),
        'finished_at' => $status['finished_at'] ?? '',
        'sync_ok' => isset($status['ok']) ? (bool)$status['ok'] : null,
        'output' => $output,
    ]);
}

st_method('POST');
$body = st_input();

if (!isset($_GET['sync'])) {
    st_json(['error' => 'unsupported operation'], 400);
}

$target = strtolower(trim((string)($body['target'] ?? 'all')));
if (!in_array($target, ['nvd', 'oui', 'webfp', 'all'], true)) {
    st_json(['error' => 'target must be nvd, oui, webfp, or all'], 400);
}

$roots = array_values(array_unique(array_filter([
    dirname(__DIR__),                 // usual install root
    '/opt/surveytrace',               // default production path
    $_SERVER['DOCUMENT_ROOT'] ?? '',  // fallback if app lives under webroot
])));

$want = [];
if ($target === 'all' || $target === 'nvd') $want[] = 'sync_nvd.py';
if ($target === 'all' || $target === 'oui') $want[] = 'sync_oui.py';
if ($target === 'all' || $target === 'webfp') $want[] = 'sync_webfp.py';

$scripts = [];
$resolved_root = '';
foreach ($roots as $root) {
    $ok = true;
    foreach ($want as $fn) {
        if (!is_file($root . '/daemon/' . $fn)) {
            $ok = false;
            break;
        }
    }
    if ($ok) {
        $resolved_root = $root;
        foreach ($want as $fn) $scripts[] = $root . '/daemon/' . $fn;
        break;
    }
}

if (!$scripts) {
    st_json([
        'error' => 'sync scripts not found',
        'searched_roots' => $roots,
        'wanted' => $want,
    ], 500);
}

$venv_py = $resolved_root . '/venv/bin/python3';
$python = is_executable($venv_py) ? $venv_py : 'python3';

// Prevent overlapping sync workers.
if (is_file($lockPath)) {
    $raw = @file_get_contents($lockPath);
    $lock = $raw ? json_decode($raw, true) : null;
    $pid = (int)($lock['pid'] ?? 0);
    if (st_pid_running($pid)) {
        st_json([
            'ok' => false,
            'running' => true,
            'error' => 'feed sync already running',
            'target' => $lock['target'] ?? '',
            'started_at' => $lock['started_at'] ?? '',
        ], 409);
    }
    @unlink($lockPath);
}

$scriptsSh = [];
foreach ($scripts as $s) {
    $scriptsSh[] = escapeshellarg($s);
}
$pythonSh = escapeshellarg($python);
$logSh    = escapeshellarg($logPath);
$lockSh   = escapeshellarg($lockPath);
$statusSh = escapeshellarg($statusPath);
$targetSh = escapeshellarg($target);

$runnerParts = [];
$runnerParts[] = 'ok=1';
$runnerParts[] = 'started=$(date -u +%Y-%m-%dT%H:%M:%SZ)';
$runnerParts[] = 'echo "[feed-sync] start ${started} target=' . $target . '" > ' . $logSh;
foreach ($scripts as $script) {
    $scriptSh = escapeshellarg($script);
    $runnerParts[] = 'echo "" >> ' . $logSh;
    $runnerParts[] = 'echo "=== ' . basename($script) . ' ===" >> ' . $logSh;
    $runnerParts[] = $pythonSh . ' ' . $scriptSh . ' >> ' . $logSh . ' 2>&1 || ok=0';
}
$statusWriteCmd =
    'php -r ' . escapeshellarg(
        '$d=["target"=>$argv[1],"started_at"=>$argv[2],"finished_at"=>gmdate("c"),"ok"=>$argv[3]==="1"];' .
        'file_put_contents($argv[4], json_encode($d, JSON_UNESCAPED_SLASHES));'
    ) .
    ' ' . $targetSh . ' "$started" "$ok" ' . $statusSh;
$runnerParts[] = $statusWriteCmd;
$runnerParts[] = 'rm -f ' . $lockSh;
$runner = implode('; ', $runnerParts);

$cmd = 'nohup bash -lc ' . escapeshellarg($runner) . ' >/dev/null 2>&1 & echo $!';
$out = [];
$code = 1;
exec($cmd, $out, $code);
$pid = (int)trim($out[0] ?? '0');
if ($code !== 0 || $pid <= 1) {
    st_json(['ok' => false, 'error' => 'failed to start feed sync worker'], 500);
}

file_put_contents($lockPath, json_encode([
    'pid' => $pid,
    'target' => $target,
    'started_at' => gmdate('c'),
], JSON_UNESCAPED_SLASHES));

st_json([
    'ok' => true,
    'started' => true,
    'running' => true,
    'pid' => $pid,
    'target' => $target,
]);

