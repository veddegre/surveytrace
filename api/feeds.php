<?php
/**
 * SurveyTrace — /api/feeds.php
 *
 * GET  /api/feeds.php?status=1  -> { ok, feed_sync: { running, target?, started_at? } }
 * POST /api/feeds.php?sync=1    Body: {"target":"nvd"|"oui"|"webfp"|"all"}
 *
 * Runs fingerprint feed sync scripts on demand and returns stdout/stderr.
 * Writes data/feed_sync_state.json while a sync runs so reloads can show status.
 */

require_once __DIR__ . '/db.php';

function st_feed_sync_state_path(): string {
    return ST_DATA_DIR . '/feed_sync_state.json';
}

function st_feed_sync_state_ttl(): int {
    return 300;
}

function st_feed_sync_state_read(): array {
    $path = st_feed_sync_state_path();
    if (!is_file($path)) {
        return ['running' => false];
    }
    $raw = @file_get_contents($path);
    $j = json_decode((string)$raw, true);
    if (!is_array($j) || empty($j['running'])) {
        return ['running' => false];
    }
    $started = (int)($j['started_at'] ?? 0);
    if ($started > 0 && (time() - $started) > st_feed_sync_state_ttl()) {
        @unlink($path);
        return ['running' => false];
    }
    return [
        'running' => true,
        'target' => (string)($j['target'] ?? ''),
        'started_at' => $started,
    ];
}

function st_feed_sync_state_begin(string $target): void {
    $path = st_feed_sync_state_path();
    if (!is_dir(ST_DATA_DIR)) {
        @mkdir(ST_DATA_DIR, 0770, true);
    }
    file_put_contents($path, json_encode([
        'running' => true,
        'target' => $target,
        'started_at' => time(),
    ], JSON_UNESCAPED_SLASHES), LOCK_EX);
    register_shutdown_function(static function () use ($path): void {
        if (is_file($path)) {
            @unlink($path);
        }
    });
}

st_auth();

if (isset($_GET['status'])) {
    st_release_session_lock();
    st_json(['ok' => true, 'feed_sync' => st_feed_sync_state_read()]);
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
if ($target === 'all' || $target === 'nvd') {
    $want[] = 'sync_nvd.py';
}
if ($target === 'all' || $target === 'oui') {
    $want[] = 'sync_oui.py';
}
if ($target === 'all' || $target === 'webfp') {
    $want[] = 'sync_webfp.py';
}

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
        foreach ($want as $fn) {
            $scripts[] = $root . '/daemon/' . $fn;
        }
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

if (st_feed_sync_state_read()['running']) {
    st_json([
        'ok' => false,
        'busy' => true,
        'error' => 'A feed sync is already running on the server.',
    ], 409);
}

st_feed_sync_state_begin($target);

$venv_py = $resolved_root . '/venv/bin/python3';
$python = is_executable($venv_py) ? $venv_py : 'python3';

// Keep sync bounded so a stuck network call does not block the web UI forever.
@set_time_limit(240);

$results = [];
$ok = true;

foreach ($scripts as $script) {
    $cmd = escapeshellarg($python) . ' ' . escapeshellarg($script) . ' 2>&1';
    $output = [];
    $code = 1;
    exec($cmd, $output, $code);
    $results[] = [
        'script' => basename($script),
        'ok' => $code === 0,
        'exit_code' => $code,
        'output' => implode("\n", $output),
    ];
    if ($code !== 0) {
        $ok = false;
    }
}

st_json([
    'ok' => $ok,
    'target' => $target,
    'results' => $results,
]);
