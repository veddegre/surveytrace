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

function st_cred_secret_helper_php_bin(): string
{
    $env = getenv('SURVEYTRACE_PHP_CLI');
    if (is_string($env) && trim($env) !== '') {
        return trim($env);
    }
    return 'php';
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
    $cmd = ['sudo', '-n', '-u', 'surveytrace', '--', st_cred_secret_helper_php_bin(), $helper];
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
        return ['ok' => false, 'error_code' => 'helper_unavailable', 'error' => 'proc_open_failed'];
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
        return ['ok' => false, 'error_code' => 'helper_timeout', 'error' => 'helper timeout'];
    }
    $out = trim($out);
    if ($out === '') {
        return ['ok' => false, 'error_code' => 'helper_unavailable', 'error' => 'empty helper output'];
    }
    try {
        $decoded = json_decode($out, true, 16, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return ['ok' => false, 'error_code' => 'protocol_error', 'error' => 'invalid helper json'];
    }
    if (!is_array($decoded)) {
        return ['ok' => false, 'error_code' => 'protocol_error', 'error' => 'invalid helper shape'];
    }
    if (!empty($decoded['ok'])) {
        return ['ok' => true, 'payload' => $decoded];
    }
    $code = isset($decoded['code']) ? (string) $decoded['code'] : 'helper_error';
    $msg = isset($decoded['error']) ? (string) $decoded['error'] : 'helper error';
    $msg = substr(preg_replace('/\s+/', ' ', $msg) ?? 'helper error', 0, 200);
    $errSafe = trim((string) $err);
    if ($errSafe !== '') {
        $msg = substr($msg . ' (' . substr($errSafe, 0, 80) . ')', 0, 200);
    }
    return ['ok' => false, 'error_code' => $code, 'error' => $msg];
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
    return $base;
}
