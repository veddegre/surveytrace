<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

function st_cred_secret_helper_install_root(): string
{
    $e = getenv('SURVEYTRACE_INSTALL_DIR');
    if (is_string($e) && trim($e) !== '') {
        return rtrim(trim($e), '/');
    }
    return dirname(__DIR__);
}

function st_cred_secret_helper_is_safe_php_path(string $path): bool
{
    if ($path === '' || $path[0] !== '/') {
        return false;
    }
    if (!preg_match('#^/(usr/bin|usr/local/bin)/php([0-9.]+)?$#', $path)) {
        return false;
    }
    return is_executable($path);
}

function st_cred_secret_helper_is_cli_php(string $candidate): bool
{
    if (!st_cred_secret_helper_is_safe_php_path($candidate)) {
        return false;
    }
    if (!function_exists('proc_open') || !function_exists('proc_close')) {
        return false;
    }
    $desc = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = @proc_open(
        [$candidate, '-r', 'echo PHP_SAPI, PHP_EOL;'],
        $desc,
        $pipes,
        null,
        null,
        ['bypass_shell' => true]
    );
    if (!is_resource($proc)) {
        return false;
    }
    fclose($pipes[0]);
    $out = trim((string) stream_get_contents($pipes[1]));
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit = proc_close($proc);
    return $exit === 0 && strtolower($out) === 'cli';
}

/**
 * @return array{bin:string,source:string}
 */
function st_cred_secret_helper_php_bin_detect(): array
{
    $envNames = ['SURVEYTRACE_PHP_CLI_BIN', 'SURVEYTRACE_PHP_CLI'];
    foreach ($envNames as $envName) {
        $env = getenv($envName);
        if (!is_string($env)) {
            continue;
        }
        $candidate = trim($env);
        if ($candidate !== '' && st_cred_secret_helper_is_cli_php($candidate)) {
            return ['bin' => $candidate, 'source' => 'env:' . $envName];
        }
    }
    if (st_cred_secret_helper_is_cli_php('/usr/bin/php')) {
        return ['bin' => '/usr/bin/php', 'source' => 'fallback:/usr/bin/php'];
    }
    if (st_cred_secret_helper_is_cli_php('/usr/local/bin/php')) {
        return ['bin' => '/usr/local/bin/php', 'source' => 'fallback:/usr/local/bin/php'];
    }
    $versioned = glob('/usr/bin/php[0-9.]*');
    if (is_array($versioned)) {
        rsort($versioned, SORT_NATURAL);
        foreach ($versioned as $candidate) {
            if (is_string($candidate) && st_cred_secret_helper_is_cli_php($candidate)) {
                return ['bin' => $candidate, 'source' => 'fallback:versioned_usr_bin'];
            }
        }
    }
    return ['bin' => '/usr/bin/php', 'source' => 'fallback:default'];
}

function st_cred_secret_helper_php_bin(): string
{
    $detected = st_cred_secret_helper_php_bin_detect();
    return $detected['bin'];
}

function st_cred_secret_helper_path(): string
{
    return st_cred_secret_helper_install_root() . '/daemon/cred_secret_ops_cli.php';
}

/**
 * @return array{ok:bool,payload?:array<string,mixed>,error_code?:string,error?:string}
 */
function st_cred_secret_helper_call(array $payload, int $timeoutSec = 20): array
{
    if (!function_exists('proc_open') || !function_exists('proc_close')) {
        return ['ok' => false, 'error_code' => 'helper_unavailable', 'error' => 'proc_open unavailable'];
    }
    $helper = st_cred_secret_helper_path();
    if (!is_file($helper)) {
        return ['ok' => false, 'error_code' => 'helper_unavailable', 'error' => 'helper missing'];
    }
    $stdin = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if (!is_string($stdin)) {
        return ['ok' => false, 'error_code' => 'protocol_error', 'error' => 'encode_failed'];
    }
    $root = st_cred_secret_helper_install_root();
    $phpBinDetected = st_cred_secret_helper_php_bin_detect();
    $phpBin = $phpBinDetected['bin'];
    $cmd = ['sudo', '-n', '-u', 'surveytrace', '--', $phpBin, $helper];
    $desc = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $env = [];
    foreach (['PATH', 'HOME', 'SURVEYTRACE_INSTALL_DIR'] as $k) {
        $v = getenv($k);
        if (is_string($v) && $v !== '') {
            $env[$k] = $v;
        }
    }
    $env['SURVEYTRACE_INSTALL_DIR'] = $root;
    $proc = @proc_open($cmd, $desc, $pipes, $root, $env, ['bypass_shell' => true]);
    if (!is_resource($proc)) {
        return [
            'ok' => false,
            'error_code' => 'helper_unavailable',
            'error' => 'proc_open_failed',
            'php_cli_bin_used' => $phpBin,
            'php_cli_detect_source' => $phpBinDetected['source'],
            'sudo_exit_code' => null,
        ];
    }
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $out = '';
    $err = '';
    $start = time();
    $exit = null;
    while (true) {
        $out .= (string) stream_get_contents($pipes[1]);
        $err .= (string) stream_get_contents($pipes[2]);
        $s = proc_get_status($proc);
        if (($s['running'] ?? false) !== true) {
            $exit = (int) ($s['exitcode'] ?? 1);
            break;
        }
        if ((time() - $start) >= max(5, min(60, $timeoutSec))) {
            proc_terminate($proc, 15);
            $exit = -1;
            break;
        }
        usleep(50_000);
    }
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
    if ($exit === -1) {
        return [
            'ok' => false,
            'error_code' => 'helper_timeout',
            'error' => 'helper timeout',
            'php_cli_bin_used' => $phpBin,
            'php_cli_detect_source' => $phpBinDetected['source'],
            'sudo_exit_code' => -1,
        ];
    }
    $out = trim($out);
    if ($out === '') {
        return [
            'ok' => false,
            'error_code' => 'helper_unavailable',
            'error' => 'empty helper output',
            'php_cli_bin_used' => $phpBin,
            'php_cli_detect_source' => $phpBinDetected['source'],
            'sudo_exit_code' => $exit,
        ];
    }
    try {
        $decoded = json_decode($out, true, 16, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return [
            'ok' => false,
            'error_code' => 'protocol_error',
            'error' => 'invalid helper json',
            'php_cli_bin_used' => $phpBin,
            'php_cli_detect_source' => $phpBinDetected['source'],
            'sudo_exit_code' => $exit,
        ];
    }
    if (!is_array($decoded)) {
        return [
            'ok' => false,
            'error_code' => 'protocol_error',
            'error' => 'invalid helper shape',
            'php_cli_bin_used' => $phpBin,
            'php_cli_detect_source' => $phpBinDetected['source'],
            'sudo_exit_code' => $exit,
        ];
    }
    if (!empty($decoded['ok'])) {
        return [
            'ok' => true,
            'payload' => $decoded,
            'php_cli_bin_used' => $phpBin,
            'php_cli_detect_source' => $phpBinDetected['source'],
            'sudo_exit_code' => $exit,
        ];
    }
    $code = isset($decoded['code']) ? (string) $decoded['code'] : 'helper_error';
    $msg = substr(preg_replace('/\s+/', ' ', (string) ($decoded['error'] ?? 'helper error')) ?? 'helper error', 0, 200);
    return [
        'ok' => false,
        'error_code' => $code,
        'error' => $msg,
        'php_cli_bin_used' => $phpBin,
        'php_cli_detect_source' => $phpBinDetected['source'],
        'sudo_exit_code' => $exit,
        'helper_error_code' => $code,
    ];
}

/**
 * @return array<string,mixed>
 */
function st_cred_secret_status_via_helper(): array
{
    $base = [
        'available' => false,
        'key_fingerprint' => null,
        'source' => 'helper_unavailable',
        'preferred_alg' => null,
        'libsodium_loaded' => false,
        'openssl_cipher' => null,
        'helper_available' => false,
    ];
    $res = st_cred_secret_helper_call(['action' => 'status'], 8);
    if (!$res['ok']) {
        $base['helper_error_code'] = (string) ($res['error_code'] ?? 'helper_unavailable');
        $base['php_cli_bin_used'] = isset($res['php_cli_bin_used']) ? (string) $res['php_cli_bin_used'] : null;
        $base['php_cli_detect_source'] = isset($res['php_cli_detect_source']) ? (string) $res['php_cli_detect_source'] : null;
        $base['sudo_exit_code'] = isset($res['sudo_exit_code']) ? (int) $res['sudo_exit_code'] : null;
        return $base;
    }
    $p = is_array($res['payload'] ?? null) ? $res['payload'] : [];
    $s = is_array($p['status'] ?? null) ? $p['status'] : [];
    $base['available'] = !empty($s['available']);
    $base['key_fingerprint'] = isset($s['key_fingerprint']) ? (string) $s['key_fingerprint'] : null;
    $base['source'] = isset($s['source']) ? (string) $s['source'] : 'helper';
    $base['preferred_alg'] = isset($s['preferred_alg']) ? (string) $s['preferred_alg'] : null;
    $base['libsodium_loaded'] = !empty($s['libsodium_loaded']);
    $base['openssl_cipher'] = isset($s['openssl_cipher']) ? (string) $s['openssl_cipher'] : null;
    $base['helper_available'] = true;
    $base['php_cli_bin_used'] = isset($res['php_cli_bin_used']) ? (string) $res['php_cli_bin_used'] : null;
    $base['php_cli_detect_source'] = isset($res['php_cli_detect_source']) ? (string) $res['php_cli_detect_source'] : null;
    $base['sudo_exit_code'] = isset($res['sudo_exit_code']) ? (int) $res['sudo_exit_code'] : null;
    return $base;
}
