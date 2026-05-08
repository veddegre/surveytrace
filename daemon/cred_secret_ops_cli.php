#!/usr/bin/env php
<?php
declare(strict_types=1);

require_once __DIR__ . '/../api/db.php';
require_once __DIR__ . '/../api/lib_secrets.php';
require_once __DIR__ . '/../api/lib_credential_profiles.php';
require_once __DIR__ . '/../api/lib_credential_profile_transport_test.php';

const ST_CRED_OPS_ENV_FILE = '/etc/surveytrace/surveytrace.env';

/**
 * Only these keys from surveytrace.env are applied into the helper process (defense in depth).
 * Do not broaden: arbitrary SURVEYTRACE_* values could alter DB paths or other runtime behavior.
 */
const ST_CRED_OPS_ENV_ALLOW = [
    'SURVEYTRACE_CRED_SECRET_KEY',
    'SURVEYTRACE_CRED_SECRET_KEY_STRICT',
    'SURVEYTRACE_SQLITE_BUSY_TIMEOUT_MS',
    'SURVEYTRACE_SQLITE_MMAP_BYTES',
];

/**
 * @return array{env_file:string,env_file_present:bool,env_file_readable:bool,key_loaded:bool}
 */
function st_load_runtime_env_file(string $path = ST_CRED_OPS_ENV_FILE): array
{
    $meta = [
        'env_file' => $path,
        'env_file_present' => is_file($path),
        'env_file_readable' => is_readable($path),
        'key_loaded' => false,
    ];
    if (!$meta['env_file_present'] || !$meta['env_file_readable']) {
        return $meta;
    }
    $lines = @file($path, FILE_IGNORE_NEW_LINES);
    if (!is_array($lines)) {
        return $meta;
    }
    foreach ($lines as $line) {
        $s = trim((string) $line);
        if ($s === '' || str_starts_with($s, '#')) {
            continue;
        }
        if (str_starts_with($s, 'export ')) {
            $s = trim(substr($s, 7));
        }
        $eq = strpos($s, '=');
        if ($eq === false) {
            continue;
        }
        $k = trim(substr($s, 0, $eq));
        if (! in_array($k, ST_CRED_OPS_ENV_ALLOW, true)) {
            continue;
        }
        $v = trim(substr($s, $eq + 1));
        if ((str_starts_with($v, '"') && str_ends_with($v, '"')) || (str_starts_with($v, "'") && str_ends_with($v, "'"))) {
            $v = substr($v, 1, -1);
        }
        putenv($k . '=' . $v);
        $_ENV[$k] = $v;
        $_SERVER[$k] = $v;
        if ($k === 'SURVEYTRACE_CRED_SECRET_KEY' && $v !== '') {
            $meta['key_loaded'] = true;
        }
    }
    if (!$meta['key_loaded']) {
        $kv = getenv('SURVEYTRACE_CRED_SECRET_KEY');
        $meta['key_loaded'] = is_string($kv) && trim($kv) !== '';
    }
    return $meta;
}

function st_cred_ops_running_user(): string
{
    if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
        $uid = (int) posix_geteuid();
        $pw = @posix_getpwuid($uid);
        if (is_array($pw) && isset($pw['name']) && trim((string) $pw['name']) !== '') {
            return (string) $pw['name'];
        }
        return (string) $uid;
    }
    return (string) get_current_user();
}

/**
 * @param array<string,mixed> $data
 */
function st_cred_ops_out(array $data, int $code = 0): void
{
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if (!is_string($json)) {
        $json = '{"ok":false,"code":"protocol_error","error":"encode_failed"}';
        $code = 1;
    }
    fwrite(STDOUT, $json);
    exit($code);
}

$raw = stream_get_contents(STDIN);
if (!is_string($raw) || trim($raw) === '') {
    st_cred_ops_out(['ok' => false, 'code' => 'invalid_request', 'error' => 'empty_request'], 1);
}
try {
    $in = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
} catch (Throwable) {
    st_cred_ops_out(['ok' => false, 'code' => 'invalid_request', 'error' => 'invalid_json'], 1);
}
if (!is_array($in)) {
    st_cred_ops_out(['ok' => false, 'code' => 'invalid_request', 'error' => 'invalid_shape'], 1);
}
$action = strtolower(trim((string) ($in['action'] ?? '')));
$envMeta = st_load_runtime_env_file();
if ($action === 'status') {
    $status = st_secret_status();
    $status['env_file'] = $envMeta['env_file'];
    $status['env_file_present'] = $envMeta['env_file_present'];
    $status['env_file_readable'] = $envMeta['env_file_readable'];
    $status['key_loaded'] = $envMeta['key_loaded'];
    $status['running_user'] = st_cred_ops_running_user();
    st_cred_ops_out([
        'ok' => true,
        'status' => $status,
    ]);
}

if ($action === 'encrypt_for_profile') {
    $id = (int) ($in['profile_id'] ?? 0);
    $transport = strtolower(trim((string) ($in['transport'] ?? '')));
    $mat = $in['secret_material'] ?? null;
    if ($id < 1 || !is_array($mat) || $transport === '') {
        st_cred_ops_out(['ok' => false, 'code' => 'invalid_request', 'error' => 'profile_id, transport, secret_material required'], 1);
    }
    [$norm, $normErr] = st_cred_profile_normalize_secret_material($transport, $mat);
    if ($normErr !== null || !is_array($norm) || $norm === []) {
        st_cred_ops_out(['ok' => false, 'code' => 'invalid_profile', 'error' => (string) ($normErr ?: 'invalid secret material')], 1);
    }
    try {
        $plain = json_encode($norm, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (!is_string($plain)) {
            throw new RuntimeException('encode_failed');
        }
        $env = st_secret_encrypt($plain, ['credential_profile_id' => $id]);
    } catch (Throwable $e) {
        $m = strtolower(trim((string) $e->getMessage()));
        if (str_contains($m, 'not configured')) {
            st_cred_ops_out(['ok' => false, 'code' => 'encryption_unavailable', 'error' => 'Credential helper encryption unavailable'], 1);
        }
        st_cred_ops_out(['ok' => false, 'code' => 'encrypt_failed', 'error' => 'Could not encrypt secret'], 1);
    }
    st_cred_ops_out([
        'ok' => true,
        'envelope' => $env,
        'envelope_summary' => st_secret_redact_summary($env),
        'status' => st_secret_status(),
    ]);
}

if ($action === 'transport_test_for_profile') {
    $id = (int) ($in['profile_id'] ?? 0);
    $rawHost = (string) ($in['target_host'] ?? '');
    $port = (int) ($in['port'] ?? 0);
    $timeoutSec = isset($in['timeout_sec']) ? (int) $in['timeout_sec'] : 15;
    if ($id < 1) {
        st_cred_ops_out(['ok' => false, 'code' => 'invalid_profile', 'error' => 'profile_id required'], 1);
    }
    [$host, $hostErr] = st_cred_transport_validate_target_host($rawHost);
    if ($host === null || $hostErr !== null) {
        st_cred_ops_out(['ok' => false, 'code' => 'invalid_profile', 'error' => (string) ($hostErr ?: 'invalid host')], 1);
    }
    if ($port < 0 || $port > 65535) {
        st_cred_ops_out(['ok' => false, 'code' => 'invalid_profile', 'error' => 'port must be between 0 and 65535'], 1);
    }
    $db = st_db();
    $row = st_cred_profile_internal_by_id($db, $id);
    if ($row === null) {
        st_cred_ops_out(['ok' => false, 'code' => 'invalid_profile', 'error' => 'Profile not found'], 1);
    }
    if ((int) ($row['enabled'] ?? 0) === 0) {
        st_cred_ops_out(['ok' => false, 'code' => 'invalid_profile', 'error' => 'Profile is disabled'], 1);
    }
    $transport = strtolower(trim((string) ($row['transport'] ?? '')));
    if (!in_array($transport, ['ssh', 'snmpv3'], true)) {
        st_cred_ops_out(['ok' => false, 'code' => 'unsupported_transport', 'error' => 'Transport does not support handshake tests'], 1);
    }
    $cipher = (string) ($row['secret_ciphertext'] ?? '');
    if ($cipher === '') {
        st_cred_ops_out(['ok' => false, 'code' => 'invalid_profile', 'error' => 'Stored secret required'], 1);
    }
    try {
        $plain = st_secret_decrypt($cipher, ['credential_profile_id' => $id]);
    } catch (Throwable $e) {
        $m = strtolower(trim((string) $e->getMessage()));
        if (str_contains($m, 'not configured')) {
            st_cred_ops_out(['ok' => false, 'code' => 'encryption_unavailable', 'error' => 'Credential helper encryption unavailable'], 1);
        }
        st_cred_ops_out(['ok' => false, 'code' => 'decrypt_failed', 'error' => 'Could not decrypt stored secret'], 1);
    }
    $secret = [];
    try {
        $decoded = json_decode($plain, true, 16, JSON_THROW_ON_ERROR);
        if (is_array($decoded)) {
            foreach ($decoded as $k => $v) {
                if (is_string($k) && is_string($v)) {
                    $secret[$k] = $v;
                }
            }
        }
    } catch (Throwable) {
        st_cred_ops_out(['ok' => false, 'code' => 'decrypt_failed', 'error' => 'Stored secret payload is invalid'], 1);
    }
    $principal = st_cred_profile_decode_json(isset($row['principal_json']) ? (string) $row['principal_json'] : null);
    $timeoutSec = max(5, min(25, $timeoutSec));
    [$stdinPayload, $buildErr] = st_cred_transport_build_stdin_payload($transport, $host, $port, $timeoutSec, $principal, $secret);
    if ($stdinPayload === null) {
        st_cred_ops_out(['ok' => false, 'code' => 'invalid_profile', 'error' => (string) ($buildErr ?: 'invalid profile for test')], 1);
    }
    // Do not call st_cred_transport_lock_acquire() here. The web API already holds
    // data/cred_profile_transport_test.lock (www-data) for the whole sudo+helper call; this CLI runs as
    // surveytrace and would always see "busy" (same path, non-blocking flock).
    $run = st_cred_transport_run_cli($stdinPayload);
    $allowedCodes = [
        'ok', 'auth_failed', 'timeout', 'network_unreachable', 'host_key_mismatch',
        'protocol_error', 'unsupported_transport', 'encryption_unavailable', 'decrypt_failed',
        'invalid_profile', 'busy', 'runner_error', 'dependency_missing',
    ];
    $code = isset($run['code']) && in_array((string) $run['code'], $allowedCodes, true) ? (string) $run['code'] : 'protocol_error';
    $ok = !empty($run['ok']) && $code === 'ok';
    $dur = max(0, (int) ($run['duration_ms'] ?? 0));
    $hint = isset($run['hint']) && is_string($run['hint']) ? substr(preg_replace('/\s+/', ' ', $run['hint']) ?? '', 0, 256) : null;
    if (($hint === null || $hint === '') && isset($run['runner_error']) && is_string($run['runner_error'])) {
        $re = trim((string) $run['runner_error']);
        if ($re !== '') {
            $hint = substr(preg_replace('/\s+/', ' ', $re) ?? '', 0, 256);
        }
    }
    st_cred_ops_out([
        'ok' => true,
        'test' => [
            'success' => $ok,
            'code' => $code,
            'duration_ms' => $dur,
            'transport' => $transport,
            'target_host' => $host,
            'port' => $port > 0 ? $port : ($transport === 'snmpv3' ? 161 : 22),
            'hint' => $hint,
        ],
        'status' => st_secret_status(),
    ]);
}

st_cred_ops_out(['ok' => false, 'code' => 'invalid_request', 'error' => 'unsupported action'], 1);
