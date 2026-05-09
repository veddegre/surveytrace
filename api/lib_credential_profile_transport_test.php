<?php
/**
 * SurveyTrace — credential profile transport handshake test (slice 5).
 *
 * Invokes daemon/cred_transport_cli.py with JSON on stdin (short-lived; no logging of secrets).
 *
 * @see docs/CREDENTIALED_CHECKS_MVP_PLAN.md
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_credential_profiles.php';
require_once __DIR__ . '/lib_secrets.php';
require_once __DIR__ . '/lib_cred_secret_helper.php';

/** @return array{0:bool,1:?string} */
function st_cred_transport_proc_available(): array
{
    if (! function_exists('proc_open') || ! function_exists('proc_close')) {
        return [false, 'proc_open is disabled in PHP'];
    }
    $df = (string) ini_get('disable_functions');
    if ($df === '') {
        return [true, null];
    }
    $parts = array_map('trim', explode(',', $df));

    return in_array('proc_open', $parts, true) || in_array('proc_close', $parts, true)
        ? [false, 'proc_open is disabled in PHP']
        : [true, null];
}

function st_cred_transport_install_root(): string
{
    $e = getenv('SURVEYTRACE_INSTALL_DIR');
    if (is_string($e) && trim($e) !== '') {
        return rtrim(trim($e), '/');
    }

    return dirname(__DIR__);
}

/**
 * Validate explicit test target (hostname or IP). Rejects shell metacharacters.
 *
 * @return array{0:?string,1:?string} [host or null, error]
 */
function st_cred_transport_validate_target_host(string $raw): array
{
    $h = trim($raw);
    if ($h === '' || strlen($h) > 253) {
        return [null, 'target_host is required (max 253 characters)'];
    }
    if (strpbrk($h, " \t\n\r;|&`$<>\\\"'(){}[]*?!#%\\") !== false) {
        return [null, 'target_host contains invalid characters'];
    }
    if (filter_var($h, FILTER_VALIDATE_IP) !== false) {
        return [$h, null];
    }
    if (preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$/', $h) === 1) {
        return [$h, null];
    }

    return [null, 'target_host must be a valid IPv4/IPv6 address or hostname'];
}

/**
 * @param array<string, mixed> $principal
 * @param array<string, string> $secret
 *
 * @return array{0:?array<string,mixed>,1:?string}
 */
function st_cred_transport_build_stdin_payload(
    string $transport,
    string $targetHost,
    int $port,
    int $timeoutSec,
    array $principal,
    array $secret
): array {
    $t = strtolower($transport);
    if ($t === 'ssh') {
        $u = trim((string) ($principal['username'] ?? ''));
        if ($u === '') {
            return [null, 'principal_json must include username for SSH test'];
        }

        return [[
            'transport'    => 'ssh',
            'target_host'  => $targetHost,
            'port'         => $port > 0 ? $port : 22,
            'timeout_sec'  => $timeoutSec,
            'principal'    => ['username' => $u],
            'secret'       => $secret,
        ], null];
    }
    if ($t === 'snmpv3') {
        $sn = trim((string) ($principal['securityName'] ?? $principal['security_name'] ?? ''));
        if ($sn === '') {
            return [null, 'principal_json must include securityName for SNMPv3 test'];
        }
        $ap = strtoupper(trim((string) ($principal['authProtocol'] ?? $principal['auth_protocol'] ?? 'SHA')));
        $pp = strtoupper(trim((string) ($principal['privProtocol'] ?? $principal['priv_protocol'] ?? 'AES')));
        $authPw = $secret['auth_password'] ?? '';
        $privPw = $secret['priv_password'] ?? '';
        if ($authPw === '' && $privPw !== '') {
            return [null, 'SNMPv3 privacy password requires an auth password for this handshake'];
        }
        if ($authPw === '' && $privPw === '') {
            return [null, 'Stored secret must include auth and/or priv passwords for SNMPv3'];
        }

        return [[
            'transport'   => 'snmpv3',
            'target_host' => $targetHost,
            'port'        => $port > 0 ? $port : 161,
            'timeout_sec' => $timeoutSec,
            'principal'   => [
                'securityName' => $sn,
                'authProtocol' => $ap !== '' ? $ap : 'SHA',
                'privProtocol' => $pp !== '' ? $pp : 'AES',
            ],
            'secret'      => $secret,
        ], null];
    }
    if ($t === 'winrm') {
        return [null, 'WinRM transport test is not implemented yet'];
    }

    return [null, 'unsupported_transport'];
}

/**
 * Exclusive non-blocking lock for transport tests (one at a time per server).
 *
 * @return resource|false
 */
function st_cred_transport_lock_acquire()
{
    if (! is_dir(ST_DATA_DIR) && ! @mkdir(ST_DATA_DIR, 0770, true) && ! is_dir(ST_DATA_DIR)) {
        return false;
    }
    $path = ST_DATA_DIR . '/cred_profile_transport_test.lock';
    $fh = @fopen($path, 'c+');
    if ($fh === false) {
        return false;
    }
    if (! flock($fh, LOCK_EX | LOCK_NB)) {
        fclose($fh);

        return false;
    }

    return $fh;
}

function st_cred_transport_lock_release($fh): void
{
    if (! is_resource($fh)) {
        return;
    }
    flock($fh, LOCK_UN);
    fclose($fh);
}

/**
 * @param array<string, mixed> $stdinPayload
 *
 * @return array{ok:bool,code:string,transport:string,duration_ms:int,hint?:string,runner_error?:string}
 */
function st_cred_transport_run_cli(array $stdinPayload): array
{
    [$okP, $errP] = st_cred_transport_proc_available();
    if (! $okP) {
        return [
            'ok'            => false,
            'code'          => 'protocol_error',
            'transport'     => (string) ($stdinPayload['transport'] ?? ''),
            'duration_ms'   => 0,
            'runner_error'  => $errP ?? 'proc_open unavailable',
        ];
    }
    $root = st_cred_transport_install_root();
    $venvPy = $root . '/venv/bin/python3';
    $python = is_executable($venvPy) ? $venvPy : 'python3';
    $cli = $root . '/daemon/cred_transport_cli.py';
    if (! is_file($cli)) {
        return [
            'ok'            => false,
            'code'          => 'protocol_error',
            'transport'     => (string) ($stdinPayload['transport'] ?? ''),
            'duration_ms'   => 0,
            'runner_error'  => 'cred_transport_cli.py missing',
        ];
    }
    $json = json_encode($stdinPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return [
            'ok'            => false,
            'code'          => 'invalid_profile',
            'transport'     => (string) ($stdinPayload['transport'] ?? ''),
            'duration_ms'   => 0,
            'runner_error'  => 'encode_failed',
        ];
    }
    $timeoutWall = (int) ($stdinPayload['timeout_sec'] ?? 15) + 8;
    $timeoutWall = max(12, min(45, $timeoutWall));
    $env = [];
    foreach (['PATH', 'HOME', 'SURVEYTRACE_INSTALL_DIR'] as $k) {
        $v = getenv($k);
        if (is_string($v) && $v !== '') {
            $env[$k] = $v;
        }
    }
    $env['SURVEYTRACE_INSTALL_DIR'] = $root;
    // Handshake-only: force AutoAddPolicy in cred_transport_ssh (do not forward
    // SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY — pool may set reject for other paths).
    $env['SURVEYTRACE_CRED_TRANSPORT_HANDSHAKE'] = '1';
    $desc = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $cmd = [$python, $cli];
    $proc = @proc_open($cmd, $desc, $pipes, $root, $env, ['bypass_shell' => true]);
    if (! is_resource($proc)) {
        return [
            'ok'            => false,
            'code'          => 'protocol_error',
            'transport'     => (string) ($stdinPayload['transport'] ?? ''),
            'duration_ms'   => 0,
            'runner_error'  => 'proc_open failed',
        ];
    }
    fwrite($pipes[0], $json);
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $stdout = '';
    $stderr = '';
    $start = time();
    $status = null;
    while (true) {
        $stdout .= (string) stream_get_contents($pipes[1]);
        $stderr .= (string) stream_get_contents($pipes[2]);
        $s = proc_get_status($proc);
        if ($s['running'] !== true) {
            $status = (int) ($s['exitcode'] ?? 1);
            break;
        }
        if ((time() - $start) >= $timeoutWall) {
            proc_terminate($proc, 15);
            $status = -1;
            break;
        }
        usleep(50_000);
    }
    fclose($pipes[1]);
    fclose($pipes[2]);
    if ($status === -1) {
        proc_close($proc);

        return [
            'ok'            => false,
            'code'          => 'timeout',
            'transport'     => (string) ($stdinPayload['transport'] ?? ''),
            'duration_ms'   => $timeoutWall * 1000,
            'runner_error'  => 'runner_wall_timeout',
        ];
    }
    proc_close($proc);
    $stdout = trim($stdout);
    $stderrTrim = trim($stderr);
    if ($stdout === '') {
        $re = 'empty_stdout';
        if ($stderrTrim !== '') {
            $re .= ': ' . substr(preg_replace('/\s+/', ' ', $stderrTrim) ?? '', 0, 400);
        }

        return [
            'ok'            => false,
            'code'          => 'protocol_error',
            'transport'     => (string) ($stdinPayload['transport'] ?? ''),
            'duration_ms'   => 0,
            'runner_error'  => $re,
        ];
    }
    try {
        $out = json_decode($stdout, true, 16, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        $clip = substr(preg_replace('/\s+/', ' ', $stdout) ?? '', 0, 160);

        return [
            'ok'            => false,
            'code'          => 'protocol_error',
            'transport'     => (string) ($stdinPayload['transport'] ?? ''),
            'duration_ms'   => 0,
            'runner_error'  => 'bad_json stdout=' . $clip,
        ];
    }
    if (! is_array($out)) {
        return [
            'ok'            => false,
            'code'          => 'protocol_error',
            'transport'     => (string) ($stdinPayload['transport'] ?? ''),
            'duration_ms'   => 0,
            'runner_error'  => 'bad_shape',
        ];
    }
    $out['ok'] = ! empty($out['ok']);
    $out['code'] = isset($out['code']) ? (string) $out['code'] : 'protocol_error';
    $out['transport'] = isset($out['transport']) ? (string) $out['transport'] : (string) ($stdinPayload['transport'] ?? '');
    $out['duration_ms'] = isset($out['duration_ms']) ? (int) $out['duration_ms'] : 0;
    if (isset($out['hint'])) {
        $out['hint'] = substr(preg_replace('/\s+/', ' ', (string) $out['hint']) ?? '', 0, 256);
    }

    return $out;
}

/**
 * @return array{http_status:int, payload:array<string,mixed>}
 */
function st_cred_profile_transport_test_run(PDO $db, array $in, ?int $actorId, ?string $actorName): array
{
    $fail = static function (int $http, string $clientMsg, string $code, ?int $pid = null) use ($actorId, $actorName): array {
        $details = ['code' => $code];
        if ($pid !== null) {
            $details['credential_profile_id'] = $pid;
        }
        st_audit_log('credential_profile.test_failed', $actorId, $actorName, null, null, $details);

        return [
            'http_status' => $http,
            'payload'     => ['ok' => false, 'error' => $clientMsg, 'code' => $code],
        ];
    };

    $allowedCodes = [
        'ok', 'auth_failed', 'timeout', 'network_unreachable', 'host_key_mismatch',
        'protocol_error', 'unsupported_transport', 'encryption_unavailable', 'decrypt_failed',
        'invalid_profile', 'busy', 'runner_error',
    ];

    $id = (int) ($in['id'] ?? 0);
    if ($id < 1) {
        return $fail(400, 'id required', 'invalid_profile');
    }
    $rawHost = (string) ($in['target_host'] ?? $in['host'] ?? '');
    [$host, $hostErr] = st_cred_transport_validate_target_host($rawHost);
    if ($host === null || $hostErr !== null) {
        return $fail(400, $hostErr ?? 'Invalid target_host', 'invalid_profile', $id);
    }
    $port = isset($in['port']) ? (int) $in['port'] : 0;
    if ($port < 0 || $port > 65535) {
        return $fail(400, 'port must be between 0 and 65535', 'invalid_profile', $id);
    }

    $row = st_cred_profile_internal_by_id($db, $id);
    if ($row === null) {
        return $fail(404, 'Profile not found', 'invalid_profile', $id);
    }
    if ((int) ($row['enabled'] ?? 0) === 0) {
        return $fail(400, 'Profile is disabled', 'invalid_profile', $id);
    }
    $transport = strtolower(trim((string) ($row['transport'] ?? '')));
    if ($transport === 'winrm') {
        return $fail(400, 'WinRM transport test is not implemented yet', 'unsupported_transport', $id);
    }
    if (! in_array($transport, ['ssh', 'snmpv3'], true)) {
        return $fail(400, 'Unsupported transport', 'unsupported_transport', $id);
    }
    $cipher = (string) ($row['secret_ciphertext'] ?? '');
    if ($cipher === '' || strlen($cipher) < 10) {
        return $fail(400, 'Profile has no stored secret; set a secret before testing', 'invalid_profile', $id);
    }
    $timeoutSec = isset($in['timeout_sec']) ? (int) $in['timeout_sec'] : 15;
    $timeoutSec = max(5, min(25, $timeoutSec));

    $lock = st_cred_transport_lock_acquire();
    if ($lock === false) {
        return $fail(429, 'Another credential test is already running. Try again shortly.', 'busy', $id);
    }
    try {
        st_audit_log('credential_profile.test_started', $actorId, $actorName, null, null, [
            'credential_profile_id' => $id,
            'transport'               => $transport,
            'target_host'             => $host,
        ]);
        $call = st_cred_secret_helper_call([
            'action' => 'transport_test_for_profile',
            'profile_id' => $id,
            'target_host' => $host,
            'port' => $port,
            'timeout_sec' => $timeoutSec,
        ], 30);
        if (! $call['ok']) {
            $hc = (string) ($call['error_code'] ?? 'helper_error');
            if ($hc === 'helper_unavailable') {
                return $fail(503, 'Credential helper unavailable; configure sudoers helper.', $hc, $id);
            }
            if ($hc === 'busy') {
                return $fail(429, 'Another credential test is already running. Try again shortly.', 'busy', $id);
            }

            return $fail(503, 'Credential test helper failed', $hc, $id);
        }
        $cp = is_array($call['payload'] ?? null) ? $call['payload'] : [];
        $run = is_array($cp['test'] ?? null) ? $cp['test'] : [];
        $code = in_array((string) ($run['code'] ?? ''), $allowedCodes, true) ? (string) $run['code'] : 'protocol_error';
        $ok = $run['ok'] && $code === 'ok';
        if (array_key_exists('success', $run)) {
            $ok = (bool) $run['success'] && $code === 'ok';
        }
        $dur = max(0, (int) ($run['duration_ms'] ?? 0));
        $status = $ok ? 'ok' : 'failed';
        $errCol = $ok ? null : $code;
        try {
            $up = $db->prepare(
                'UPDATE credential_profiles SET last_test_at = datetime(\'now\'), last_test_status = ?, last_test_error_code = ?, last_test_duration_ms = ?, updated_at = datetime(\'now\') WHERE id = ? AND deleted_at IS NULL'
            );
            $up->execute([$status, $errCol, $dur > 0 ? $dur : null, $id]);
        } catch (Throwable) {
            st_audit_log('credential_profile.test_failed', $actorId, $actorName, null, null, [
                'credential_profile_id' => $id,
                'code'                    => 'protocol_error',
                'phase'                   => 'db_update',
            ]);

            return [
                'http_status' => 500,
                'payload'     => ['ok' => false, 'error' => 'Could not save test result', 'code' => 'protocol_error'],
            ];
        }
        if ($ok) {
            st_audit_log('credential_profile.test_succeeded', $actorId, $actorName, null, null, [
                'credential_profile_id' => $id,
                'transport'             => $transport,
                'target_host'           => $host,
                'duration_ms'           => $dur,
            ]);
        } else {
            st_audit_log('credential_profile.test_failed', $actorId, $actorName, null, null, [
                'credential_profile_id' => $id,
                'transport'             => $transport,
                'target_host'           => $host,
                'code'                  => $code,
                'duration_ms'           => $dur,
            ]);
        }
        $profile = st_cred_profile_get_active($db, $id);
        $hint = isset($run['hint']) && is_string($run['hint']) ? substr($run['hint'], 0, 256) : null;
        if (($hint === null || $hint === '') && isset($run['runner_error']) && is_string($run['runner_error'])) {
            $re = trim((string) $run['runner_error']);
            if ($re !== '') {
                $hint = substr(preg_replace('/\s+/', ' ', $re) ?? '', 0, 256);
            }
        }
        $effPort = $port > 0 ? $port : ($transport === 'snmpv3' ? 161 : 22);
        st_audit_log('credential_profile.secret_tested', $actorId, $actorName, null, null, [
            'credential_profile_id' => $id,
            'transport'             => $transport,
            'target_host'           => $host,
            'plugin_key'            => 'credential_profile.transport_test',
            'result_code'           => $code,
            'duration_ms'           => $dur,
        ]);
        $payload = [
            'ok'          => true,
            'test'        => [
                'success'     => $ok,
                'code'        => $code,
                'duration_ms' => $dur,
                'transport'   => $transport,
                'target_host' => isset($run['target_host']) ? (string) $run['target_host'] : $host,
                'port'        => isset($run['port']) ? (int) $run['port'] : $effPort,
                'hint'        => $hint,
            ],
            'profile'     => $profile,
            'encryption'  => st_cred_secret_status_via_helper(),
        ];

        return ['http_status' => 200, 'payload' => $payload];
    } finally {
        st_cred_transport_lock_release($lock);
    }
}
