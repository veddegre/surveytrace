<?php
/**
 * Shared feed sync resolution + execution (used by feeds.php and CLI worker).
 */

require_once __DIR__ . '/db.php';

function st_feed_sync_state_path(): string {
    return ST_DATA_DIR . '/feed_sync_state.json';
}

/** Long jobs (NVD) can exceed 5 minutes — avoid stale state while still running. */
function st_feed_sync_state_ttl(): int {
    return 28800; // 8 hours
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
}

function st_feed_sync_state_clear(): void {
    @unlink(st_feed_sync_state_path());
}

function st_feed_sync_last_result_read(): ?array {
    $p = ST_DATA_DIR . '/feed_sync_result.json';
    if (!is_file($p)) {
        return null;
    }
    $raw = @file_get_contents($p);
    $j = json_decode((string)$raw, true);
    return is_array($j) ? $j : null;
}

/**
 * @return array{root: string, scripts: list<string>, python: string}|null
 */
function st_feed_sync_resolve(string $target): ?array {
    $roots = array_values(array_unique(array_filter([
        dirname(__DIR__),
        '/opt/surveytrace',
        $_SERVER['DOCUMENT_ROOT'] ?? '',
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
        return null;
    }

    $venv_py = $resolved_root . '/venv/bin/python3';
    $python = is_executable($venv_py) ? $venv_py : 'python3';

    return ['root' => $resolved_root, 'scripts' => $scripts, 'python' => $python];
}

/**
 * @param list<string> $scriptPaths
 * @return array{ok: bool, results: list<array{script: string, ok: bool, exit_code: int, output: string}>}
 */
function st_feed_sync_run_sync(array $scriptPaths, string $python): array {
    $results = [];
    $ok = true;
    foreach ($scriptPaths as $script) {
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
    return ['ok' => $ok, 'results' => $results];
}

function st_feed_sync_write_result(string $target, array $payload): void {
    $payload['target'] = $target;
    $payload['finished_at'] = time();
    if (!is_dir(ST_DATA_DIR)) {
        @mkdir(ST_DATA_DIR, 0770, true);
    }
    file_put_contents(
        ST_DATA_DIR . '/feed_sync_result.json',
        json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        LOCK_EX
    );
}

/**
 * Spawn detached PHP worker (when fastcgi_finish_request is unavailable).
 */
function st_feed_sync_spawn_worker(string $phpCli, string $workerPath, string $target, string $root): void {
    if (PHP_OS_FAMILY === 'Windows') {
        $cmd = sprintf(
            'start /B "" %s %s %s %s',
            escapeshellarg($phpCli),
            escapeshellarg($workerPath),
            escapeshellarg($target),
            escapeshellarg($root)
        );
        pclose(popen($cmd, 'r'));
        return;
    }
    $log = ST_DATA_DIR . '/feed_sync_worker.log';
    $cmd = sprintf(
        'cd %s && nohup %s %s %s %s >> %s 2>&1 &',
        escapeshellarg($root),
        escapeshellarg($phpCli),
        escapeshellarg($workerPath),
        escapeshellarg($target),
        escapeshellarg($root),
        escapeshellarg($log)
    );
    exec($cmd);
}

/**
 * PHP CLI binary for spawning the worker (avoid php-fpm binary when PHP_BINARY is FPM).
 */
function st_feed_sync_php_cli(): string {
    $env = getenv('SURVEYTRACE_PHP_CLI');
    if (is_string($env) && $env !== '' && is_executable($env)) {
        return $env;
    }
    if (PHP_OS_FAMILY === 'Windows') {
        $b = PHP_BINARY;
        if (is_string($b) && str_ends_with(strtolower($b), 'php.exe')) {
            return $b;
        }
        return 'php';
    }
    foreach (['/usr/bin/php', '/usr/local/bin/php', '/bin/php'] as $c) {
        if (is_executable($c)) {
            return $c;
        }
    }
    return 'php';
}
