#!/usr/bin/env php
<?php
/**
 * SurveyTrace — read-only operational security validation (no mutation, no network scan).
 *
 * Validates permissions, credential-helper assumptions, manifest presence, systemd expectations,
 * SQLite hygiene signals, and static web/API hygiene checks. Not a vulnerability or CVE scanner.
 *
 * Usage:
 *   php scripts/security_runtime_audit.php [--install-root=/opt/surveytrace] [--env-file=/etc/surveytrace/surveytrace.env] [--json] [--strict]
 *
 * Exit: 0 = PASS and WARN only (strict: WARN also fails exit). 1 = FAIL present. 2 = tool/runtime error.
 *
 * @see docs/wiki/troubleshooting.md — Credential secret helper — security model
 */
declare(strict_types=1);

/** @var list<string> */
const ST_SRA_KNOWN_RENAMED_PATHS = [
    'scripts/st_recon_slice10_selftest.php',
    'scripts/st_software_inventory_slice2_selftest.php',
    'scripts/st_software_inventory_slice3_selftest.php',
    'scripts/st_software_inventory_slice4_selftest.php',
    'scripts/st_cc_normalized_preview_slice8_selftest.php',
    'daemon/cred_check_slice7_selftest.py',
    'daemon/cred_check_slice8_pkg_selftest.py',
    'daemon/cred_check_slice9_snmp_selftest.py',
    'daemon/st_software_obs_slice1_selftest.py',
];

/**
 * @return array{
 *   install_root:string,
 *   env_file:string,
 *   json:bool,
 *   strict:bool,
 *   wal_warn_bytes:int,
 *   stale_run_warn_minutes:int
 * }
 */
function st_sra_parse_argv(array $argv): array
{
    $out = [
        'install_root'         => '/opt/surveytrace',
        'env_file'             => '/etc/surveytrace/surveytrace.env',
        'json'                 => false,
        'strict'               => false,
        'wal_warn_bytes'       => 64 * 1024 * 1024,
        'stale_run_warn_minutes' => 120,
    ];
    foreach (array_slice($argv, 1) as $a) {
        if ($a === '--json') {
            $out['json'] = true;
            continue;
        }
        if ($a === '--strict') {
            $out['strict'] = true;
            continue;
        }
        if (preg_match('/^--install-root=(.+)$/', $a, $m)) {
            $out['install_root'] = $m[1];

            continue;
        }
        if (preg_match('/^--env-file=(.+)$/', $a, $m)) {
            $out['env_file'] = $m[1];

            continue;
        }
        if (preg_match('/^--wal-warn-mb=(\d+)$/', $a, $m)) {
            $out['wal_warn_bytes'] = max(1, (int) $m[1]) * 1024 * 1024;

            continue;
        }
        if (preg_match('/^--stale-run-warn-minutes=(\d+)$/', $a, $m)) {
            $out['stale_run_warn_minutes'] = max(1, (int) $m[1]);

            continue;
        }
        if ($a === '--help' || $a === '-h') {
            fwrite(STDOUT, "usage: php security_runtime_audit.php [--install-root=PATH] [--env-file=PATH] [--json] [--strict] [--wal-warn-mb=N] [--stale-run-warn-minutes=N]\n");

            exit(0);
        }
        fwrite(STDERR, "Unknown argument: {$a}\n");

        exit(2);
    }

    return $out;
}

/**
 * @param array{pass:int,warn:int,fail:int,lines:list<array{level:string,code:string,msg:string}>} $st
 */
function st_sra_emit(array &$st, string $level, string $code, string $msg): void
{
    $line = strtoupper($level) . '  ' . $code . '  ' . $msg;
    if (empty($st['_json_output'])) {
        fwrite(STDOUT, $line . "\n");
    }
    $st['lines'][] = ['level' => $level, 'code' => $code, 'msg' => $msg];
    if ($level === 'pass') {
        ++$st['pass'];
    } elseif ($level === 'warn') {
        ++$st['warn'];
    } elseif ($level === 'fail') {
        ++$st['fail'];
    }
}

function st_sra_realpath_dir(string $p): ?string
{
    $rp = realpath($p);

    return ($rp !== false && is_dir($rp)) ? $rp : null;
}

function st_sra_realpath_file(string $p): ?string
{
    $rp = realpath($p);

    return ($rp !== false && is_file($rp)) ? $rp : null;
}

/**
 * @return array{0:int,1:int,2:int,3:int}|null  uid,gid,mode,link
 */
function st_sra_lstat_meta(string $path): ?array
{
    $st = @lstat($path);
    if (! is_array($st) || ! isset($st['uid'], $st['gid'], $st['mode'])) {
        return null;
    }

    return [(int) $st['uid'], (int) $st['gid'], (int) ($st['mode'] & 07777), (int) ($st['nlink'] ?? 0)];
}

/**
 * True if "others" have write, or primary group www-data with group-write on a file.
 */
function st_sra_world_or_group_www_writable_file(string $path, int $mode, int $gid, ?int $wwwGid): bool
{
    if (($mode & 0002) !== 0) {
        return true;
    }
    if ($wwwGid !== null && $gid === $wwwGid && ($mode & 0020) !== 0) {
        return true;
    }

    return false;
}

/**
 * @return array{out:string,err:string,code:int}
 */
function st_sra_proc(array $argv, ?string $stdin, float $timeoutSec): array
{
    $des = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = @proc_open($argv, $des, $pipes, null, null, ['bypass_shell' => true]);
    if (! is_resource($proc)) {
        return ['out' => '', 'err' => 'proc_open_failed', 'code' => -1];
    }
    if ($stdin !== null && isset($pipes[0])) {
        fwrite($pipes[0], $stdin);
    }
    if (isset($pipes[0]) && is_resource($pipes[0])) {
        fclose($pipes[0]);
    }
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $out = '';
    $err = '';
    $deadline = microtime(true) + $timeoutSec;
    while (true) {
        $r = [$pipes[1], $pipes[2]];
        $w = null;
        $e = null;
        $sec = 0;
        $usec = 200000;
        @stream_select($r, $w, $e, $sec, $usec);
        foreach ($r as $pipe) {
            if ($pipe === $pipes[1]) {
                $out .= (string) stream_get_contents($pipes[1]);
            } elseif ($pipe === $pipes[2]) {
                $err .= (string) stream_get_contents($pipes[2]);
            }
        }
        $st = proc_get_status($proc);
        if (! $st['running']) {
            break;
        }
        if (microtime(true) > $deadline) {
            proc_terminate($proc, 15);
            break;
        }
    }
    if (is_resource($pipes[1])) {
        $out .= (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);
    }
    if (is_resource($pipes[2])) {
        $err .= (string) stream_get_contents($pipes[2]);
        fclose($pipes[2]);
    }
    $code = proc_close($proc);

    return ['out' => $out, 'err' => $err, 'code' => $code];
}

function st_sra_php_cli_sapi(string $phpBin): ?string
{
    $r = st_sra_proc([$phpBin, '-r', 'echo PHP_SAPI;'], null, 5.0);
    if ($r['code'] !== 0) {
        return null;
    }
    $s = trim($r['out']);

    return $s !== '' ? $s : null;
}

/** @return array{name:string,uid:int,gid:int}|null */
function st_sra_user_by_name(string $name): ?array
{
    if (! function_exists('posix_getpwnam')) {
        return null;
    }
    $pw = @posix_getpwnam($name);
    if (! is_array($pw) || ! isset($pw['uid'], $pw['gid'], $pw['name'])) {
        return null;
    }

    return ['name' => (string) $pw['name'], 'uid' => (int) $pw['uid'], 'gid' => (int) $pw['gid']];
}

function st_sra_cred_helper_web_user(): string
{
    foreach (['SURVEYTRACE_CRED_HELPER_WEB_USER', 'APACHE_RUN_USER'] as $k) {
        $v = getenv($k);
        if (is_string($v) && trim($v) !== '') {
            return trim($v);
        }
    }
    foreach (['www-data', 'apache', 'nginx'] as $u) {
        if (st_sra_user_by_name($u) !== null) {
            return $u;
        }
    }

    return 'www-data';
}

/**
 * @param array<string, list<string>> $manifest
 *
 * @return array<string, true>
 */
function st_sra_expected_rel_paths(array $manifest): array
{
    $set = [];
    foreach ($manifest['api_files'] ?? [] as $bn) {
        $set['api/' . $bn] = true;
    }
    foreach ($manifest['daemon_core_py'] ?? [] as $bn) {
        $set['daemon/' . $bn] = true;
    }
    foreach ($manifest['daemon_optional_py'] ?? [] as $bn) {
        $set['daemon/' . $bn] = true;
    }
    foreach ($manifest['daemon_other_files'] ?? [] as $bn) {
        $set['daemon/' . $bn] = true;
    }
    foreach ($manifest['daemon_sources_py'] ?? [] as $bn) {
        $set['daemon/sources/' . $bn] = true;
    }
    foreach ($manifest['scripts_php'] ?? [] as $bn) {
        $set['scripts/' . $bn] = true;
    }
    foreach ($manifest['scripts_sh'] ?? [] as $bn) {
        $set['scripts/' . $bn] = true;
    }
    foreach ($manifest['public_files'] ?? [] as $rel) {
        $set[$rel] = true;
    }
    foreach ($manifest['sql_files'] ?? [] as $rel) {
        $set[$rel] = true;
    }
    // service_units live in the repo root and are installed to /etc/systemd/system/ — not under the
    // install tree. Presence is validated separately via systemctl cat in this script.
    $set['VERSION'] = true;

    return $set;
}

/**
 * @return array<string, mixed>|null
 */
function st_sra_json_decode_safe(string $json): ?array
{
    try {
        $v = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return null;
    }

    return is_array($v) ? $v : null;
}

/**
 * Reject suspiciously large secret-like strings in decoded helper output (defense in depth).
 *
 * @param mixed $v
 */
function st_sra_output_has_secret_leak($v, int $depth = 0): bool
{
    if ($depth > 12) {
        return false;
    }
    if (is_string($v)) {
        if (strlen($v) > 512) {
            return true;
        }
        if (preg_match('/BEGIN [A-Z ]*PRIVATE KEY/', $v)) {
            return true;
        }

        return false;
    }
    if (is_array($v)) {
        foreach ($v as $k => $x) {
            if (is_string($k) && strtoupper($k) === 'SURVEYTRACE_CRED_SECRET_KEY') {
                return true;
            }
            if (st_sra_output_has_secret_leak($x, $depth + 1)) {
                return true;
            }
        }
    }

    return false;
}

/**
 * @param array<string, list<string>> $manifest
 */
function st_sra_audit_sudoers_narrow(string $path, string $installRoot, string $webUser, array &$st): void
{
    if (! is_readable($path)) {
        st_sra_emit($st, 'warn', 'sudoers_unreadable', 'sudoers drop-in not readable; skipped narrow-rule parse');

        return;
    }
    $raw = @file_get_contents($path);
    if (! is_string($raw)) {
        st_sra_emit($st, 'warn', 'sudoers_read_failed', 'could not read sudoers drop-in');

        return;
    }
    $lines = [];
    foreach (explode("\n", $raw) as $ln) {
        $t = trim($ln);
        if ($t === '' || str_starts_with($t, '#')) {
            continue;
        }
        $lines[] = $t;
    }
    $joined = implode("\n", $lines);
    if (preg_match('/NOPASSWD:\s*ALL\b/i', $joined) && ! preg_match('/ALL=\(surveytrace\)/', $joined)) {
        st_sra_emit($st, 'fail', 'sudoers_nopasswd_all', 'sudoers appears to grant NOPASSWD: ALL (unacceptable)');
    }
    if (str_contains($joined, '*') && preg_match('/Cmnd_Alias\s+\w+\s*=\s*[^\n]*\*/', $joined)) {
        st_sra_emit($st, 'fail', 'sudoers_wildcard', 'Cmnd_Alias line contains shell wildcard');
    }
    $helperNeedle = rtrim($installRoot, '/') . '/daemon/cred_secret_ops_cli.php';
    $okAlias = false;
    foreach ($lines as $t) {
        if (preg_match('/^Cmnd_Alias\s+(\S+)\s*=\s*(.+)$/', $t, $m)) {
            $rhs = trim($m[2]);
            if (str_contains($rhs, '&&') || str_contains($rhs, '|') || str_contains($rhs, ';')) {
                st_sra_emit($st, 'fail', 'sudoers_cmnd_shell', 'Cmnd_Alias RHS contains shell metacharacters');

                continue;
            }
            $parts = preg_split('/\s+/', $rhs) ?: [];
            if (count($parts) !== 2) {
                st_sra_emit($st, 'fail', 'sudoers_cmnd_count', 'Cmnd_Alias must list exactly two argv tokens (php binary + helper script)');

                continue;
            }
            $phpBin = $parts[0];
            $scr = $parts[1];
            if ($phpBin === '' || $scr === '' || $phpBin[0] !== '/' || $scr[0] !== '/') {
                st_sra_emit($st, 'fail', 'sudoers_cmnd_paths', 'Cmnd_Alias paths must be absolute');

                continue;
            }
            if (! str_contains($scr, 'cred_secret_ops_cli.php')) {
                continue;
            }
            if ($scr !== $helperNeedle && ! str_ends_with($scr, '/daemon/cred_secret_ops_cli.php')) {
                st_sra_emit($st, 'warn', 'sudoers_helper_path', 'helper path in sudoers does not match install-root helper (verify intentional)');
            }
            $okAlias = true;
        }
    }
    if (! $okAlias) {
        st_sra_emit($st, 'fail', 'sudoers_no_cmnd_alias', 'no Cmnd_Alias defining ST_CRED_SECRET_OPS (or equivalent) found');
    }
    $userOk = false;
    foreach ($lines as $t) {
        if (preg_match('/^' . preg_quote($webUser, '/') . '\s+ALL=\(surveytrace\)\s+NOPASSWD:\s*(\S+)\s*$/i', $t, $m)) {
            if (strtoupper($m[1]) === 'ST_CRED_SECRET_OPS' || str_contains($m[1], 'ST_CRED')) {
                $userOk = true;
            }
        }
    }
    if (! $userOk) {
        st_sra_emit($st, 'fail', 'sudoers_user_line', 'expected ' . $webUser . ' ALL=(surveytrace) NOPASSWD: ST_CRED_SECRET_OPS line not found');
    }
}

/**
 * @param array<string, list<string>> $manifest
 */
function st_sra_run(array $opts, array $manifest): int
{
    $st = [
        'pass'        => 0,
        'warn'        => 0,
        'fail'        => 0,
        'lines'       => [],
        '_json_output' => $opts['json'],
    ];
    $root = st_sra_realpath_dir($opts['install_root']);
    if ($root === null) {
        st_sra_emit($st, 'fail', 'install_root_missing', 'install root not found or not a directory: ' . $opts['install_root']);
        goto summary;
    }
    if (! is_file($root . '/api/db.php')) {
        st_sra_emit($st, 'fail', 'install_root_not_surveytrace', 'install root missing api/db.php');
        goto summary;
    }
    st_sra_emit($st, 'info', 'install_root', 'using ' . $root);

    $manifestPath = $root . '/scripts/deploy_file_manifest.php';
    if (! is_readable($manifestPath)) {
        st_sra_emit($st, 'fail', 'manifest_missing', 'deploy_file_manifest.php not readable at ' . $manifestPath);
    } else {
        $m = require $manifestPath;
        if (! is_array($m)) {
            st_sra_emit($st, 'fail', 'manifest_invalid', 'manifest did not return array');
        } else {
            $expected = st_sra_expected_rel_paths($m);
            $missing = [];
            $checked = 0;
            foreach ($expected as $rel => $_) {
                if (str_contains($rel, '..')) {
                    continue;
                }
                ++$checked;
                $full = $root . '/' . $rel;
                if (! file_exists($full)) {
                    $missing[] = $rel;
                }
            }
            foreach ($missing as $rel) {
                st_sra_emit($st, 'fail', 'manifest_file_missing', 'missing shipped path: ' . $rel);
            }
            if ($missing === []) {
                st_sra_emit($st, 'pass', 'manifest_complete', 'all ' . $checked . ' manifest paths present under install root');
            }
        }
    }

    if (! is_file($root . '/scripts/cleanup_deployed_stale_files.php')) {
        st_sra_emit($st, 'fail', 'cleanup_script_missing', 'scripts/cleanup_deployed_stale_files.php missing');
    } else {
        st_sra_emit($st, 'pass', 'cleanup_script', 'cleanup_deployed_stale_files.php present');
    }

    $staleFound = false;
    foreach (ST_SRA_KNOWN_RENAMED_PATHS as $rel) {
        if (is_file($root . '/' . $rel) || is_link($root . '/' . $rel)) {
            st_sra_emit($st, 'warn', 'stale_renamed_file', 'obsolete path still present (safe to remove after review): ' . $rel);
            $staleFound = true;
        }
    }
    if (! $staleFound) {
        st_sra_emit($st, 'pass', 'stale_renamed', 'no known renamed slice/phase selftest paths present');
    }

    $etcDir = '/etc/surveytrace';
    if (! is_dir($etcDir)) {
        st_sra_emit($st, 'warn', 'etc_surveytrace_missing', '/etc/surveytrace not a directory (helper model checks skipped or incomplete)');
    } else {
        $em = st_sra_lstat_meta($etcDir);
        if ($em === null) {
            st_sra_emit($st, 'warn', 'etc_stat_failed', 'could not stat /etc/surveytrace');
        } else {
            [, , $mode] = $em;
            if (($mode & 07777) > 0750) {
                st_sra_emit($st, 'fail', 'etc_surveytrace_mode', '/etc/surveytrace mode ' . sprintf('%04o', $mode) . ' is looser than 0750');
            } else {
                st_sra_emit($st, 'pass', 'etc_surveytrace_mode', '/etc/surveytrace mode ok (' . sprintf('%04o', $mode) . ')');
            }
        }
    }

    $envFile = $opts['env_file'];
    if (! is_file($envFile)) {
        st_sra_emit($st, 'warn', 'env_file_missing', 'env file not found: ' . $envFile);
    } else {
        $em = st_sra_lstat_meta($envFile);
        if ($em !== null) {
            [, , $mode] = $em;
            if (($mode & 07777) > 0640) {
                st_sra_emit($st, 'fail', 'env_file_mode', 'surveytrace.env mode ' . sprintf('%04o', $mode) . ' is looser than 0640');
            } else {
                st_sra_emit($st, 'pass', 'env_file_mode', 'env file mode ok');
            }
        }
        $web = st_sra_cred_helper_web_user();
        $rW = st_sra_proc(['sudo', '-u', $web, 'test', '-r', $envFile], null, 10.0);
        if ($rW['code'] < 0 || str_contains(strtolower($rW['err']), 'a password is required')) {
            st_sra_emit($st, 'warn', 'sudo_unavailable', 'could not run sudo -u ' . $web . ' (skip www-data env read probe)');
        } elseif ($rW['code'] === 0) {
            st_sra_emit($st, 'fail', 'www_data_reads_env', $web . ' can read env file (must not)');
        } elseif ($rW['code'] === 1) {
            st_sra_emit($st, 'pass', 'www_data_env', $web . ' cannot read env file');
        } else {
            st_sra_emit($st, 'warn', 'www_data_env_ambiguous', 'sudo test exit ' . $rW['code'] . ' for www-data read probe');
        }
        $rS = st_sra_proc(['sudo', '-u', 'surveytrace', 'test', '-r', $envFile], null, 10.0);
        if ($rS['code'] < 0 || str_contains(strtolower($rS['err']), 'a password is required')) {
            st_sra_emit($st, 'warn', 'sudo_unavailable_st', 'could not run sudo -u surveytrace (skip surveytrace env read probe)');
        } elseif ($rS['code'] !== 0) {
            st_sra_emit($st, 'fail', 'surveytrace_env', 'surveytrace cannot read env file');
        } else {
            st_sra_emit($st, 'pass', 'surveytrace_env', 'surveytrace can read env file');
        }
    }

    $phpFromEnv = '';
    if (is_readable($envFile)) {
        foreach (file($envFile, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $s = trim((string) $line);
            if ($s === '' || str_starts_with($s, '#')) {
                continue;
            }
            if (preg_match('/^export\s+/', $s)) {
                $s = trim(substr($s, 7));
            }
            if (str_starts_with($s, 'SURVEYTRACE_PHP_CLI_BIN=')) {
                $phpFromEnv = trim(substr($s, strlen('SURVEYTRACE_PHP_CLI_BIN=')));
                if ((str_starts_with($phpFromEnv, '"') && str_ends_with($phpFromEnv, '"')) || (str_starts_with($phpFromEnv, "'") && str_ends_with($phpFromEnv, "'"))) {
                    $phpFromEnv = substr($phpFromEnv, 1, -1);
                }
                break;
            }
        }
    }
    $phpCandidates = $phpFromEnv !== ''
        ? [$phpFromEnv]
        : array_values(array_unique(array_filter([
            (defined('PHP_BINARY') && is_string(PHP_BINARY) && PHP_BINARY !== '') ? PHP_BINARY : null,
            (is_string(PHP_BINDIR) && PHP_BINDIR !== '') ? rtrim(PHP_BINDIR, '/') . '/php' : null,
            '/usr/bin/php',
            '/usr/bin/php8.4',
            '/usr/bin/php8.3',
            '/usr/bin/php8.2',
            '/bin/php',
            '/usr/local/bin/php',
        ])));
    $phpBinRp = '';
    foreach ($phpCandidates as $cand) {
        $rp = st_sra_realpath_file($cand) ?? $cand;
        if (is_executable($rp)) {
            $phpBinRp = $rp;
            break;
        }
    }
    if ($phpBinRp === '') {
        st_sra_emit($st, 'fail', 'php_cli_missing', 'no executable PHP CLI (set SURVEYTRACE_PHP_CLI_BIN in env file)');
    } else {
        st_sra_emit($st, 'pass', 'php_cli_exec', 'PHP CLI path executable');
        $sapi = st_sra_php_cli_sapi($phpBinRp);
        if ($sapi !== 'cli') {
            st_sra_emit($st, 'fail', 'php_cli_sapi', 'PHP binary is not CLI SAPI (got: ' . ($sapi ?? 'null') . ')');
        } else {
            st_sra_emit($st, 'pass', 'php_cli_sapi', 'PHP CLI SAPI confirmed');
        }
    }

    $sudoers = '/etc/sudoers.d/surveytrace-credential-secret-helper';
    if (! is_file($sudoers)) {
        st_sra_emit($st, 'warn', 'sudoers_missing', 'sudoers drop-in missing: ' . $sudoers);
    } else {
        $vis = st_sra_proc(['sudo', 'visudo', '-cf', $sudoers], null, 15.0);
        if ($vis['code'] < 0 || str_contains(strtolower($vis['err'] . $vis['out']), 'a password is required')) {
            st_sra_emit($st, 'warn', 'visudo_skipped', 'visudo -cf not runnable (sudo); skipped syntax check');
        } elseif ($vis['code'] !== 0) {
            st_sra_emit($st, 'fail', 'visudo_cf', 'visudo -cf failed for ' . $sudoers);
        } else {
            st_sra_emit($st, 'pass', 'visudo_cf', 'visudo -cf OK');
        }
        st_sra_audit_sudoers_narrow($sudoers, $root, st_sra_cred_helper_web_user(), $st);
    }

    $helperScript = $root . '/daemon/cred_secret_ops_cli.php';
    if ($phpBinRp === '' || ! is_file($helperScript)) {
        st_sra_emit($st, 'warn', 'helper_skipped', 'credential helper status check skipped (no PHP CLI or helper script missing)');
    } else {
        $web = st_sra_cred_helper_web_user();
        $stdin = "{\"action\":\"status\"}\n";
        $cmd = ['sudo', '-u', $web, 'sudo', '-n', '-u', 'surveytrace', '--', $phpBinRp, $helperScript];
        $hp = st_sra_proc($cmd, $stdin, 25.0);
        if ($hp['code'] < 0 || str_contains(strtolower($hp['err'] . $hp['out']), 'a password is required')) {
            st_sra_emit($st, 'warn', 'helper_sudo_skipped', 'helper sudo chain not runnable; skipped status JSON check');
        } elseif ($hp['code'] !== 0) {
            st_sra_emit($st, 'fail', 'helper_invocation', 'helper sudo chain exit ' . $hp['code']);
        } else {
            $j = st_sra_json_decode_safe(trim($hp['out']));
            if ($j === null) {
                st_sra_emit($st, 'fail', 'helper_json', 'helper did not return JSON');
            } else {
                $expectKey = false;
                if (is_readable($envFile) && is_file($envFile)) {
                    $rawE = @file_get_contents($envFile);
                    $expectKey = is_string($rawE) && preg_match('/^\s*SURVEYTRACE_CRED_SECRET_KEY=/m', $rawE);
                }
                $ok = ! empty($j['ok']);
                $s = is_array($j['status'] ?? null) ? $j['status'] : [];
                $ok = $ok && ! empty($s['available']) && ! empty($s['env_file_present']) && ! empty($s['env_file_readable']);
                if ($expectKey) {
                    $ok = $ok && ! empty($s['key_loaded']);
                }
                if (! $ok) {
                    st_sra_emit($st, 'fail', 'helper_status_fields', 'helper status missing required true fields (expect key: ' . ($expectKey ? 'yes' : 'no') . ')');
                } else {
                    st_sra_emit($st, 'pass', 'helper_status', 'helper status OK');
                }
                if (st_sra_output_has_secret_leak($j)) {
                    st_sra_emit($st, 'fail', 'helper_leak', 'helper output may contain disallowed material');
                }
                $es = trim($hp['err']);
                if ($es !== '' && strlen($es) < 4000) {
                    if (preg_match('/(SURVEYTRACE_CRED_SECRET_KEY|BEGIN .*PRIVATE)/i', $es)) {
                        st_sra_emit($st, 'fail', 'helper_stderr_secret', 'helper stderr looks sensitive');
                    } else {
                        st_sra_emit($st, 'warn', 'helper_stderr', 'helper stderr non-empty (length ' . strlen($es) . ')');
                    }
                }
            }
        }
    }

    $www = st_sra_user_by_name(st_sra_cred_helper_web_user());
    $wwwGid = $www['gid'] ?? null;
    $checkWritable = function (string $rel) use ($root, &$st, $wwwGid): void {
        $full = $root . '/' . $rel;
        if (! is_file($full)) {
            return;
        }
        $m = st_sra_lstat_meta($full);
        if ($m === null) {
            return;
        }
        [, $gid, $mode] = $m;
        if (st_sra_world_or_group_www_writable_file($full, $mode, $gid, $wwwGid)) {
            st_sra_emit($st, 'fail', 'writable_by_www', 'insecure mode/group write for web pool on: ' . $rel);
        }
    };
    foreach (glob($root . '/daemon/*.py', GLOB_NOSORT) ?: [] as $f) {
        $checkWritable('daemon/' . basename((string) $f));
    }
    foreach (glob($root . '/api/*.php', GLOB_NOSORT) ?: [] as $f) {
        $checkWritable('api/' . basename((string) $f));
    }
    $checkWritable('daemon/cred_secret_ops_cli.php');
    $deployCandidates = [];
    foreach (['setup.sh', 'deploy.sh'] as $sh) {
        $deployCandidates[$root . '/' . $sh] = true;
        $deployCandidates[dirname($root) . '/' . $sh] = true;
    }
    foreach (array_keys($deployCandidates) as $deployPath) {
        if (! is_file($deployPath)) {
            continue;
        }
        $m = st_sra_lstat_meta($deployPath);
        if ($m !== null && (($m[2] & 0002) !== 0 || ($wwwGid !== null && $m[1] === $wwwGid && ($m[2] & 0020) !== 0))) {
            st_sra_emit($st, 'fail', 'deploy_script_perm', 'insecure perms on ' . $deployPath);
        }
    }
    foreach ($manifest['service_units'] ?? [] as $unit) {
        $uf = $root . '/' . $unit;
        if (is_file($uf)) {
            $m = st_sra_lstat_meta($uf);
            if ($m !== null && (($m[2] & 0002) !== 0 || ($wwwGid !== null && $m[1] === $wwwGid && ($m[2] & 0020) !== 0))) {
                st_sra_emit($st, 'fail', 'unit_template_perm', 'insecure perms on shipped unit ' . $unit);
            }
        }
    }
    if (is_file($sudoers)) {
        $m = @stat($sudoers);
        if (is_array($m) && (($m['mode'] & 07777) & 0002) !== 0) {
            st_sra_emit($st, 'fail', 'sudoers_o+w', 'sudoers drop-in is world-writable');
        }
    }

    foreach (['/opt/surveytrace/data', $root . '/data'] as $dd) {
        if (! is_dir($dd)) {
            continue;
        }
        $m = st_sra_lstat_meta($dd);
        if ($m !== null && ($m[2] & 0002) !== 0) {
            st_sra_emit($st, 'warn', 'data_dir_world_writable', 'data directory world-writable: ' . $dd);
        }
    }

    $units = ['surveytrace-daemon.service', 'surveytrace-scheduler.service', 'surveytrace-collector-ingest.service', 'surveytrace-credential-check-worker.service'];
    foreach ($units as $unit) {
        $cat = st_sra_proc(['systemctl', 'cat', $unit], null, 8.0);
        if ($cat['code'] !== 0 || trim($cat['out']) === '') {
            st_sra_emit($st, 'warn', 'systemd_unit_absent', 'systemctl cat failed or empty: ' . $unit);
            continue;
        }
        $body = $cat['out'];
        st_sra_emit($st, 'pass', 'systemd_unit', 'unit present: ' . $unit);
        if (preg_match('/^User=surveytrace$/m', $body) !== 1) {
            st_sra_emit($st, 'warn', 'systemd_user', $unit . ': expected User=surveytrace');
        }
        if (preg_match('/^Group=surveytrace$/m', $body) !== 1) {
            st_sra_emit($st, 'warn', 'systemd_group', $unit . ': expected Group=surveytrace');
        }
        if ($unit === 'surveytrace-credential-check-worker.service' || $unit === 'surveytrace-collector-ingest.service') {
            if (! preg_match('/^Restart=on-failure$/m', $body)) {
                st_sra_emit($st, 'warn', 'systemd_restart', $unit . ': expected Restart=on-failure');
            }
        }
        if (preg_match('/^ProtectSystem=strict$/m', $body)) {
            if (! preg_match('/ReadWritePaths=.*\/data/m', $body)) {
                st_sra_emit($st, 'fail', 'systemd_rw_data', $unit . ': ProtectSystem=strict without ReadWritePaths to data');
            }
        }
        if ($unit === 'surveytrace-credential-check-worker.service' || $unit === 'surveytrace-collector-ingest.service') {
            if (! preg_match('/^EnvironmentFile=-?\/etc\/surveytrace\/surveytrace\.env$/m', $body)) {
                st_sra_emit($st, 'warn', 'systemd_env_file', $unit . ': EnvironmentFile for surveytrace.env not found');
            }
        }
        $wdNeedle = 'WorkingDirectory=' . rtrim($root, '/') . '/daemon';
        if ($root === '/opt/surveytrace' && ! str_contains($body, $wdNeedle)) {
            if (! preg_match('#^WorkingDirectory=/opt/surveytrace/daemon$#m', $body)) {
                st_sra_emit($st, 'warn', 'systemd_workdir', $unit . ': WorkingDirectory may not match install root');
            }
        }
    }

    $statusJson = $root . '/data/collector_ingest_status.json';
    $ingestUnit = st_sra_proc(['systemctl', 'is-active', 'surveytrace-collector-ingest.service'], null, 5.0);
    if (trim($ingestUnit['out']) === 'active' && ! is_file($statusJson)) {
        st_sra_emit($st, 'warn', 'collector_status_file', 'collector ingest active but status file missing (may appear after first loop)');
    }

    $db = $root . '/data/surveytrace.db';
    if (! is_file($db)) {
        st_sra_emit($st, 'warn', 'sqlite_missing', 'surveytrace.db not found under data/');
    } else {
        $m = st_sra_lstat_meta($db);
        if ($m !== null) {
            $wr = st_sra_proc(['sudo', '-u', 'surveytrace', 'test', '-w', $db], null, 8.0);
            if ($wr['code'] < 0 || str_contains(strtolower($wr['err']), 'a password is required')) {
                st_sra_emit($st, 'warn', 'sqlite_writable_skipped', 'could not verify surveytrace.db writability (sudo)');
            } elseif ($wr['code'] !== 0) {
                st_sra_emit($st, 'fail', 'sqlite_not_writable', 'surveytrace cannot write surveytrace.db');
            } else {
                st_sra_emit($st, 'pass', 'sqlite_writable', 'surveytrace can write surveytrace.db');
            }
        }
        foreach (['-wal', '-shm'] as $suf) {
            $side = $db . $suf;
            if (is_file($side)) {
                st_sra_emit($st, 'pass', 'sqlite_sidecar', basename($side) . ' present');
            }
        }
        $wal = $db . '-wal';
        if (is_file($wal) && filesize($wal) > $opts['wal_warn_bytes']) {
            st_sra_emit($st, 'warn', 'sqlite_wal_large', 'WAL size exceeds threshold (' . (int) (filesize($wal) / 1024 / 1024) . ' MiB)');
        }
        try {
            $pdo = new PDO('sqlite:' . $db, null, null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            ]);
            $pdo->exec('PRAGMA query_only=ON');
            $q = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='worker_jobs'");
            if ($q && $q->fetchColumn()) {
                $thr = (int) $opts['stale_run_warn_minutes'];
                $sql = "SELECT COUNT(*) FROM worker_jobs WHERE status IN ('running','leased','retrying')
                  AND datetime(updated_at) < datetime('now', '-" . $thr . " minutes')";
                $n = (int) $pdo->query($sql)->fetchColumn();
                if ($n > 0) {
                    st_sra_emit($st, 'warn', 'stale_worker_jobs', 'worker_jobs in active-ish state older than ' . $thr . ' minutes: count=' . $n);
                }
            }
            $q2 = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='credential_check_runs'");
            if ($q2 && $q2->fetchColumn()) {
                $thr = (int) $opts['stale_run_warn_minutes'];
                $sql2 = "SELECT COUNT(*) FROM credential_check_runs WHERE status IN ('running','queued','resolving_targets','ready')
                  AND datetime(started_at) < datetime('now', '-" . $thr . " minutes') AND finished_at IS NULL";
                try {
                    $n2 = (int) $pdo->query($sql2)->fetchColumn();
                    if ($n2 > 0) {
                        st_sra_emit($st, 'warn', 'stale_cred_runs', 'credential_check_runs non-terminal older than ' . $thr . ' minutes: count=' . $n2);
                    }
                } catch (Throwable) {
                    // column differences
                }
            }
            $runtimeWarnRows = 200000;
            foreach (
                [
                    'worker_job_events' => 'runtime_worker_job_events_large',
                    'credential_check_results' => 'runtime_cred_check_results_large',
                    'credential_check_artifacts' => 'runtime_cred_check_artifacts_large',
                ] as $tbl => $code
            ) {
                $chk = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1");
                $chk->execute([$tbl]);
                if ($chk->fetchColumn()) {
                    $n = (int) $pdo->query('SELECT COUNT(*) FROM ' . $tbl)->fetchColumn();
                    if ($n > $runtimeWarnRows) {
                        st_sra_emit($st, 'warn', $code, $tbl . ' row count high: ' . $n . ' (consider prune_operational_history or prune_credential_runtime_history)');
                    }
                }
            }
            $qpr = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='user_audit_log' LIMIT 1");
            if ($qpr && $qpr->fetchColumn()) {
                $stpr = $pdo->prepare(
                    "SELECT COUNT(*) FROM user_audit_log
                     WHERE action = 'maintenance.prune_credential_runtime_history'
                       AND datetime(created_at) > datetime('now', '-40 days')"
                );
                $stpr->execute();
                $npr = (int) $stpr->fetchColumn();
                if ($npr < 1) {
                    st_sra_emit(
                        $st,
                        'warn',
                        'prune_credential_runtime_not_recent',
                        'No maintenance.prune_credential_runtime_history audit in the last 40 days (optional: php scripts/prune_credential_runtime_history.php --apply)'
                    );
                }
            }
        } catch (Throwable $e) {
            st_sra_emit($st, 'warn', 'sqlite_readonly_probe', 'SQLite read-only probe failed: ' . $e->getMessage());
        }
    }

    foreach (
        [
            'scripts/prune_operational_history.php',
            'scripts/prune_credential_runtime_history.php',
            'scripts/recover_stale_worker_jobs.php',
            'scripts/validate_backup_restore_readiness.php',
        ] as $rel
    ) {
        if (! is_file($root . '/' . $rel)) {
            st_sra_emit($st, 'warn', 'maintenance_script_missing', $rel);
        } else {
            st_sra_emit($st, 'pass', 'maintenance_script', $rel);
        }
    }

    $idx = $root . '/public/index.php';
    if (is_readable($idx)) {
        $c = (string) file_get_contents($idx);
        foreach (['confirm(', 'alert(', 'prompt('] as $bad) {
            if (str_contains($c, $bad)) {
                st_sra_emit($st, 'fail', 'js_dialog', 'public/index.php contains ' . $bad);
            }
        }
        st_sra_emit($st, 'pass', 'index_no_native_dialogs', 'public/index.php: no confirm/alert/prompt(');
        if (preg_match('/stCredProfileDebugState[\s\S]{0,2000}\bsecret_ciphertext\b/i', $c)) {
            st_sra_emit($st, 'warn', 'index_debug_secret', 'public/index.php: stCredProfileDebugState near secret_ciphertext (manual review)');
        }
    }
    $cp = $root . '/api/credential_profiles.php';
    if (is_readable($cp)) {
        $cc = (string) file_get_contents($cp);
        if (str_contains($cc, "isset(\$in['secret_ciphertext'])") && str_contains($cc, '400')) {
            st_sra_emit($st, 'pass', 'api_rejects_ciphertext', 'credential_profiles rejects client secret_ciphertext');
        } else {
            st_sra_emit($st, 'warn', 'api_ciphertext_check', 'could not verify secret_ciphertext rejection pattern in credential_profiles.php');
        }
    }

    $getenvHits = [];
    foreach (glob($root . '/api/*.php', GLOB_NOSORT) ?: [] as $f) {
        $bn = basename((string) $f);
        if ($bn === 'lib_secrets.php') {
            continue;
        }
        $t = @file_get_contents((string) $f);
        if (! is_string($t)) {
            continue;
        }
        if (preg_match("/getenv\\(\\s*['\"]SURVEYTRACE_CRED_SECRET_KEY['\"]\\s*\\)/", $t)) {
            $getenvHits[] = $bn;
        }
    }
    if ($getenvHits !== []) {
        st_sra_emit($st, 'info', 'getenv_cred_key', 'getenv(SURVEYTRACE_CRED_SECRET_KEY) outside lib_secrets.php: ' . implode(', ', $getenvHits));
    }

    $docChecks = [
        ['rel' => 'docs/wiki/deployment.md', 'needle' => 'cred_secret_ops_cli.php', 'code' => 'doc_deployment_helper'],
        ['rel' => 'docs/wiki/troubleshooting.md', 'needle' => 'Credential secret helper', 'code' => 'doc_troubleshooting_model'],
        ['rel' => 'docs/wiki/security_model.md', 'needle' => 'cred_secret_ops_cli.php', 'code' => 'doc_security_model'],
        ['rel' => 'docs/RELEASE_READINESS_CHECKLIST.md', 'needle' => 'release_security_gate.php', 'code' => 'doc_release_gate'],
    ];
    foreach ($docChecks as $dc) {
        $p = $root . '/' . $dc['rel'];
        if (! is_readable($p)) {
            st_sra_emit($st, 'warn', 'doc_missing', 'doc not readable: ' . $dc['rel']);
        } elseif (! str_contains((string) file_get_contents($p), $dc['needle'])) {
            st_sra_emit($st, 'warn', $dc['code'], 'doc may be stale (missing expected phrase): ' . $dc['rel']);
        } else {
            st_sra_emit($st, 'pass', $dc['code'], $dc['rel'] . ' contains expected reference');
        }
    }

    summary:
    $sum = 'SUMMARY: fail=' . $st['fail'] . ' warn=' . $st['warn'] . ' pass=' . $st['pass'];
    if ($opts['json']) {
        fwrite(STDOUT, json_encode([
            'summary' => ['fail' => $st['fail'], 'warn' => $st['warn'], 'pass' => $st['pass']],
            'lines'   => $st['lines'],
        ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n");
    } else {
        fwrite(STDOUT, $sum . "\n");
    }

    if ($st['fail'] > 0) {
        return 1;
    }
    if ($opts['strict'] && $st['warn'] > 0) {
        return 1;
    }

    return 0;
}

try {
    $opts = st_sra_parse_argv($argv);
    $repoManifest = __DIR__ . '/deploy_file_manifest.php';
    if (! is_readable($repoManifest)) {
        fwrite(STDERR, "security_runtime_audit: cannot read deploy_file_manifest.php next to this script\n");

        exit(2);
    }
    /** @var array<string, list<string>> $manifest */
    $manifest = require $repoManifest;
    if (! is_array($manifest)) {
        fwrite(STDERR, "security_runtime_audit: invalid manifest\n");

        exit(2);
    }
    $code = st_sra_run($opts, $manifest);
    exit($code);
} catch (Throwable $e) {
    fwrite(STDERR, 'security_runtime_audit: ' . $e->getMessage() . "\n");

    exit(2);
}
