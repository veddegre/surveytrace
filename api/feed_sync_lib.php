<?php
/**
 * Shared feed sync resolution + execution (used by feeds.php and CLI worker).
 */

require_once __DIR__ . '/db.php';

function st_feed_sync_state_path(): string {
    return ST_DATA_DIR . '/feed_sync_state.json';
}

/** Empty marker file — sync scripts poll and exit 10 when present. */
function st_feed_sync_cancel_path(): string {
    return ST_DATA_DIR . '/feed_sync_cancel';
}

/** @return bool false if the cancel marker could not be written (permissions / disk) */
function st_feed_sync_cancel_request(): bool {
    if (!is_dir(ST_DATA_DIR)) {
        if (!@mkdir(ST_DATA_DIR, 0770, true) && !is_dir(ST_DATA_DIR)) {
            return false;
        }
    }
    if (!is_writable(ST_DATA_DIR)) {
        return false;
    }
    $p = st_feed_sync_cancel_path();
    if (@touch($p) === false) {
        return false;
    }
    @chmod($p, 0660);
    return is_file($p);
}

function st_feed_sync_cancel_clear(): void {
    @unlink(st_feed_sync_cancel_path());
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

/**
 * @return bool false if data directory is missing/unwritable or state file cannot be written
 */
function st_feed_sync_state_begin(string $target): bool {
    $path = st_feed_sync_state_path();
    if (!is_dir(ST_DATA_DIR)) {
        if (!@mkdir(ST_DATA_DIR, 0770, true) && !is_dir(ST_DATA_DIR)) {
            return false;
        }
    }
    if (!is_writable(ST_DATA_DIR)) {
        return false;
    }
    st_feed_sync_cancel_clear();
    $payload = json_encode([
        'running' => true,
        'target' => $target,
        'started_at' => time(),
    ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($payload === false) {
        return false;
    }
    $bytes = @file_put_contents($path, $payload, LOCK_EX);
    return $bytes !== false;
}

function st_feed_sync_state_clear(): void {
    @unlink(st_feed_sync_state_path());
    st_feed_sync_cancel_clear();
}

function st_feed_sync_last_result_read(): ?array {
    $p = ST_DATA_DIR . '/feed_sync_result.json';
    if (!is_file($p)) {
        return null;
    }
    $maxBytes = 4 * 1024 * 1024;
    $sz = @filesize($p);
    if ($sz !== false && $sz > $maxBytes) {
        return [
            'ok' => false,
            'error' => 'feed_sync_result.json is ' . $sz . ' bytes (over API limit ' . $maxBytes . '); delete or trim it on the server.',
            'results' => [],
        ];
    }
    $raw = @file_get_contents($p);
    $j = json_decode((string)$raw, true);
    return is_array($j) ? $j : null;
}

/**
 * Shrink feed_sync_result.json payloads for API responses so status polling
 * does not OOM or break json_encode when script stdout is huge (e.g. NVD).
 *
 * @return array<string, mixed>|null
 */
function st_feed_sync_truncate_result_for_api(?array $last, int $maxOutputBytes = 98304): ?array {
    if ($last === null) {
        return null;
    }
    $copy = $last;
    if (!empty($copy['results']) && is_array($copy['results'])) {
        $copy['results'] = array_map(
            static function ($row) use ($maxOutputBytes): array {
                if (!is_array($row)) {
                    return [
                        'script' => 'unknown',
                        'ok' => false,
                        'exit_code' => -1,
                        'output' => 'invalid row in feed_sync_result.json',
                    ];
                }
                $out = (string)($row['output'] ?? '');
                $len = strlen($out);
                if ($len > $maxOutputBytes) {
                    $row['output'] = substr($out, 0, $maxOutputBytes)
                        . "\n\n... [truncated for API response: {$len} bytes total; see data/feed_sync_result.json on server]";
                    $row['output_truncated'] = true;
                }
                return $row;
            },
            $copy['results']
        );
    }
    if (isset($copy['error']) && is_string($copy['error']) && strlen($copy['error']) > $maxOutputBytes) {
        $copy['error'] = substr($copy['error'], 0, $maxOutputBytes) . "\n... [truncated]";
    }
    return $copy;
}

/**
 * Possible SurveyTrace install roots (directory containing daemon/ and api/).
 *
 * @return list<string>
 */
function st_feed_sync_install_root_candidates(): array {
    $roots = [];

    $env = getenv('SURVEYTRACE_ROOT');
    if (is_string($env) && $env !== '') {
        $rp = realpath($env);
        $roots[] = $rp !== false ? $rp : rtrim($env, '/\\');
    }

    $sf = $_SERVER['SCRIPT_FILENAME'] ?? '';
    if ($sf !== '' && preg_match('~/api/feeds\.php$~i', str_replace('\\', '/', $sf))) {
        $parent = dirname($sf);
        $rp = realpath($parent . DIRECTORY_SEPARATOR . '..');
        if ($rp !== false) {
            $roots[] = $rp;
        }
    }

    $apiParent = dirname(__DIR__);
    $rpApi = realpath($apiParent);
    $roots[] = $rpApi !== false ? $rpApi : $apiParent;

    $roots[] = '/opt/surveytrace';

    $doc = isset($_SERVER['DOCUMENT_ROOT']) ? (string)$_SERVER['DOCUMENT_ROOT'] : '';
    if ($doc !== '') {
        $doc = rtrim(str_replace('\\', '/', $doc), '/');
        if ($doc !== '') {
            $roots[] = $doc;
            $parent = dirname($doc);
            if ($parent !== '' && $parent !== '/' && $parent !== '.') {
                $rpDoc = realpath($parent);
                $roots[] = $rpDoc !== false ? $rpDoc : $parent;
            }
        }
    }

    $out = [];
    foreach ($roots as $r) {
        $r = trim((string)$r);
        if ($r === '') {
            continue;
        }
        $out[] = $r;
    }
    return array_values(array_unique($out));
}

/**
 * @return array{root: string, scripts: list<string>, python: string}|null
 */
function st_feed_sync_resolve(string $target): ?array {
    $roots = st_feed_sync_install_root_candidates();

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
        // Match weekly cron: incremental only. Plain sync_nvd.py pulls the entire
        // CVE corpus (hours) and often dies under PHP-FPM request timeouts — CLI
        // users typically pass --recent; the UI must do the same.
        $suffix = basename($script) === 'sync_nvd.py' ? ' --recent' : '';
        $cmd = escapeshellarg($python) . ' ' . escapeshellarg($script) . $suffix . ' 2>&1';
        $output = [];
        $code = 1;
        exec($cmd, $output, $code);
        $userCancel = ($code === 10);
        $results[] = [
            'script' => basename($script),
            'ok' => $code === 0 || $userCancel,
            'exit_code' => $code,
            'output' => implode("\n", $output),
            'cancelled' => $userCancel,
        ];
        if ($userCancel) {
            return ['ok' => true, 'cancelled' => true, 'results' => $results];
        }
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
    $enc = json_encode(
        $payload,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
    );
    if ($enc === false) {
        $enc = json_encode(
            [
                'ok' => false,
                'target' => $target,
                'results' => [],
                'error' => 'Could not serialize sync result: ' . json_last_error_msg(),
                'finished_at' => time(),
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
        ) ?: '{"ok":false,"error":"json encode failed"}';
    }
    file_put_contents(ST_DATA_DIR . '/feed_sync_result.json', $enc, LOCK_EX);
}

/** @return list<string> */
function st_feed_sync_disabled_functions(): array {
    $df = ini_get('disable_functions');
    if ($df === false || $df === '') {
        return [];
    }
    return array_values(array_filter(array_map(
        static fn(string $s): string => strtolower(trim($s)),
        explode(',', (string)$df)
    )));
}

/**
 * Whether we can launch the CLI worker via shell (Apache mod_php path).
 */
function st_feed_sync_shell_available(): bool {
    $df = st_feed_sync_disabled_functions();
    if (PHP_OS_FAMILY === 'Windows') {
        return function_exists('popen')
            && function_exists('pclose')
            && !in_array('popen', $df, true)
            && !in_array('pclose', $df, true);
    }
    return function_exists('exec') && !in_array('exec', $df, true);
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
    @exec($cmd);
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
