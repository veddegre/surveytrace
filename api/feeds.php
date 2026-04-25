<?php
/**
 * SurveyTrace — /api/feeds.php
 *
 * POST /api/feeds.php?sync=1
 * Body: {"target":"oui"|"webfp"|"all"}
 *
 * Runs fingerprint feed sync scripts on demand and returns stdout/stderr.
 */

require_once __DIR__ . '/db.php';
st_auth();
st_method('POST');

$body = st_input();

if (!isset($_GET['sync'])) {
    st_json(['error' => 'unsupported operation'], 400);
}

$target = strtolower(trim((string)($body['target'] ?? 'all')));
if (!in_array($target, ['oui', 'webfp', 'all'], true)) {
    st_json(['error' => 'target must be oui, webfp, or all'], 400);
}

$root = dirname(__DIR__);
$venv_py = $root . '/venv/bin/python3';
$python = is_executable($venv_py) ? $venv_py : 'python3';

$scripts = [];
if ($target === 'all' || $target === 'oui') {
    $scripts[] = $root . '/daemon/sync_oui.py';
}
if ($target === 'all' || $target === 'webfp') {
    $scripts[] = $root . '/daemon/sync_webfp.py';
}

foreach ($scripts as $s) {
    if (!is_file($s)) {
        st_json(['error' => "script not found: " . basename($s)], 500);
    }
}

@set_time_limit(180);

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

