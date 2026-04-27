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

// NVD sync can exceed several minutes depending on feed size/network.
// Remove request time limit so manual sync doesn't fail mid-run.
@set_time_limit(0);

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

