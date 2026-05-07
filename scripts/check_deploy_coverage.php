#!/usr/bin/env php
<?php
/**
 * Flags drift between the repo tree and scripts/deploy_file_manifest.php (what deploy.sh installs).
 *
 * Usage:
 *   php scripts/check_deploy_coverage.php [/path/to/repo]
 *
 * Exit 0 = OK, 1 = issues found (non-fatal warnings still exit 1 if any ERROR).
 */
declare(strict_types=1);

$repo = isset($argv[1]) ? rtrim((string) $argv[1], '/') : dirname(__DIR__);
$manifestPath = $repo . '/scripts/deploy_file_manifest.php';
if (!is_readable($manifestPath)) {
    fwrite(STDERR, "check_deploy_coverage: missing manifest: {$manifestPath}\n");
    exit(2);
}

/** @var array<string, list<string>> $m */
$m = require $manifestPath;

$errors = [];
$warn = [];

/**
 * @param list<string> $acc
 */
function st_collect_paths(string $dir, string $pattern, array &$acc): void
{
    if (!is_dir($dir)) {
        return;
    }
    foreach (glob($dir . '/' . $pattern, GLOB_NOSORT) ?: [] as $p) {
        if (is_file($p)) {
            $acc[] = $p;
        }
    }
}

// --- Manifest paths must exist (manifest uses basenames for api/daemon/scripts subtrees) ---
foreach ($m['api_files'] ?? [] as $bn) {
    $p = $repo . '/api/' . $bn;
    if (!is_readable($p)) {
        $errors[] = 'manifest lists missing file (api_files): ' . $bn;
    }
}
foreach ($m['daemon_core_py'] ?? [] as $bn) {
    $p = $repo . '/daemon/' . $bn;
    if (!is_readable($p)) {
        $errors[] = 'manifest lists missing file (daemon_core_py): ' . $bn;
    }
}
foreach ($m['daemon_optional_py'] ?? [] as $bn) {
    $p = $repo . '/daemon/' . $bn;
    if (!is_readable($p)) {
        $errors[] = 'manifest lists missing file (daemon_optional_py): ' . $bn;
    }
}
foreach ($m['daemon_other_files'] ?? [] as $bn) {
    $p = $repo . '/daemon/' . $bn;
    if (!is_readable($p)) {
        $errors[] = 'manifest lists missing file (daemon_other_files): ' . $bn;
    }
}
foreach ($m['scripts_php'] ?? [] as $bn) {
    $p = $repo . '/scripts/' . $bn;
    if (!is_readable($p)) {
        $errors[] = 'manifest lists missing file (scripts_php): ' . $bn;
    }
}
foreach ($m['public_files'] ?? [] as $rel) {
    $p = $repo . '/' . $rel;
    if (!is_readable($p)) {
        $errors[] = 'manifest lists missing file (public_files): ' . $rel;
    }
}
foreach ($m['sql_files'] ?? [] as $rel) {
    $p = $repo . '/' . $rel;
    if (!is_readable($p)) {
        $errors[] = 'manifest lists missing file (sql_files): ' . $rel;
    }
}
foreach ($m['service_units'] ?? [] as $bn) {
    $p = $repo . '/' . $bn;
    if (!is_readable($p)) {
        $errors[] = 'manifest lists missing file (service_units): ' . $bn;
    }
}

foreach ($m['daemon_sources_py'] ?? [] as $base) {
    $p = $repo . '/daemon/sources/' . $base;
    if (!is_readable($p)) {
        $errors[] = 'manifest lists missing daemon/sources file: ' . $base;
    }
}

// --- api/*.php: nothing unexpected ---
$apiWant = array_flip($m['api_files']);
$apiPhp = [];
st_collect_paths($repo . '/api', '*.php', $apiPhp);
foreach ($apiPhp as $full) {
    $bn = basename($full);
    if (!isset($apiWant[$bn])) {
        $errors[] = 'api/*.php not in deploy manifest (add to api_files or remove): ' . $bn;
    }
}

// --- daemon/*.py ---
$daemonOtherPy = [];
foreach ($m['daemon_other_files'] ?? [] as $df) {
    if (str_ends_with($df, '.py')) {
        $daemonOtherPy[] = $df;
    }
}
$daemonFlatWant = array_flip(array_merge(
    $m['daemon_core_py'],
    $m['daemon_optional_py'],
    $m['daemon_dev_only_py'],
    $daemonOtherPy
));
$daemonPy = [];
st_collect_paths($repo . '/daemon', '*.py', $daemonPy);
foreach ($daemonPy as $full) {
    $bn = basename($full);
    if (!isset($daemonFlatWant[$bn])) {
        $errors[] = 'daemon/*.py not classified in manifest: ' . $bn;
    }
}

// --- scripts ---
$scriptsWant = array_flip($m['scripts_php']);
$scriptsDev = array_flip($m['scripts_dev_only'] ?? []);
$scriptPhp = [];
st_collect_paths($repo . '/scripts', '*.php', $scriptPhp);
foreach ($scriptPhp as $full) {
    $bn = basename($full);
    if (isset($scriptsDev[$bn])) {
        continue;
    }
    if (!isset($scriptsWant[$bn])) {
        $errors[] = 'scripts/*.php not in deploy manifest (scripts_php) or scripts_dev_only: ' . $bn;
    }
}

foreach ($m['scripts_php'] ?? [] as $bn) {
    if (isset($scriptsDev[$bn])) {
        $errors[] = 'script listed both scripts_php and scripts_dev_only: ' . $bn;
    }
}

// Non-PHP scripts (optional): warn if new shell/py appears and isn't allowlisted
$scriptExtras = [];
foreach (glob($repo . '/scripts/*', GLOB_NOSORT) ?: [] as $p) {
    if (!is_file($p)) {
        continue;
    }
    $ext = pathinfo($p, PATHINFO_EXTENSION);
    if ($ext === 'php') {
        continue;
    }
    $bn = basename($p);
    if (!isset($scriptsDev[$bn])) {
        $scriptExtras[] = $bn;
    }
}
if ($scriptExtras !== []) {
    $warn[] = 'non-PHP files under scripts/ (ensure intentional / allowlist if dev-only): ' . implode(', ', $scriptExtras);
}

foreach ($errors as $line) {
    fwrite(STDERR, '[ERROR] ' . $line . "\n");
}
foreach ($warn as $line) {
    fwrite(STDERR, '[WARN] ' . $line . "\n");
}

if ($errors !== []) {
    fwrite(STDERR, "\ncheck_deploy_coverage: FAILED (" . count($errors) . ' error(s), ' . count($warn) . " warning(s))\n");
    exit(1);
}

fwrite(STDOUT, 'check_deploy_coverage: OK (' . count($warn) . " warning(s))\n");
exit(0);
