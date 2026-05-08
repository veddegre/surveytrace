#!/usr/bin/env php
<?php
/**
 * Backup / restore readiness validation (read-only).
 *
 * Usage:
 *   php scripts/validate_backup_restore_readiness.php [--db=/path/to/surveytrace.db]
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_secrets.php';

/**
 * @return array{db_path:string}
 */
function st_brr_parse_args(array $argv): array
{
    $dbPath = dirname(__DIR__) . '/data/surveytrace.db';
    foreach (array_slice($argv, 1) as $arg) {
        if (str_starts_with($arg, '--db=')) {
            $dbPath = (string) substr($arg, strlen('--db='));
            continue;
        }
        if ($arg === '--help' || $arg === '-h') {
            fwrite(STDOUT, "Usage: php scripts/validate_backup_restore_readiness.php [--db=/path/to/surveytrace.db]\n");
            exit(0);
        }
        fwrite(STDERR, "Unknown argument: {$arg}\n");
        exit(2);
    }

    return ['db_path' => $dbPath];
}

function st_brr_has_table(PDO $pdo, string $name): bool
{
    $st = $pdo->prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1");
    $st->execute([$name]);
    $v = $st->fetchColumn();

    return $v !== false && $v !== null;
}

function st_brr_q_count(PDO $pdo, string $sql): int
{
    try {
        return (int) $pdo->query($sql)->fetchColumn();
    } catch (Throwable) {
        return 0;
    }
}

/**
 * @return array{ok:bool,status?:array<string,mixed>}
 */
function st_brr_helper_status(): array
{
    $php = PHP_BINARY !== '' ? PHP_BINARY : 'php';
    $cli = dirname(__DIR__) . '/daemon/cred_secret_ops_cli.php';
    if (!is_file($cli) || !is_executable($php)) {
        return ['ok' => false];
    }
    $desc = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = @proc_open([$php, $cli], $desc, $pipes, dirname(__DIR__), [], ['bypass_shell' => true]);
    if (!is_resource($proc)) {
        return ['ok' => false];
    }
    fwrite($pipes[0], '{"action":"status"}');
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
    if (!is_string($out) || trim($out) === '') {
        return ['ok' => false];
    }
    try {
        $j = json_decode($out, true, 32, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return ['ok' => false];
    }
    if (!is_array($j) || empty($j['ok']) || !is_array($j['status'] ?? null)) {
        return ['ok' => false];
    }
    return ['ok' => true, 'status' => $j['status']];
}

/**
 * @return array{pass:bool,warn:bool}
 */
function st_brr_emit(string $level, string $msg): array
{
    $lvl = strtoupper(trim($level));
    if (! in_array($lvl, ['PASS', 'WARN', 'FAIL'], true)) {
        $lvl = 'WARN';
    }
    fwrite(STDOUT, str_pad($lvl, 4, ' ', STR_PAD_RIGHT) . "  {$msg}\n");

    return ['pass' => $lvl === 'PASS', 'warn' => $lvl === 'WARN'];
}

$opt = st_brr_parse_args($argv);
$fails = 0;
$warns = 0;
$passes = 0;

try {
    $pdo = new PDO('sqlite:' . $opt['db_path'], null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA busy_timeout = 60000');
    st_brr_emit('PASS', 'Database is readable.');
    $passes++;
} catch (Throwable) {
    st_brr_emit('FAIL', 'Database is not readable.');
    $fails++;
    fwrite(STDOUT, "SUMMARY: fail={$fails} warn={$warns} pass={$passes}\n");
    exit(1);
}

$requiredTables = [
    'credential_profiles',
    'worker_jobs',
    'worker_job_attempts',
    'worker_job_events',
    'credential_check_runs',
    'credential_check_run_targets',
    'credential_check_results',
    'credential_check_artifacts',
    'reconciliation_runs',
];
$missing = [];
foreach ($requiredTables as $t) {
    if (! st_brr_has_table($pdo, $t)) {
        $missing[] = $t;
    }
}
if ($missing === []) {
    st_brr_emit('PASS', 'Required worker/credential/reconciliation tables are present.');
    $passes++;
} else {
    st_brr_emit('WARN', 'Some optional operational tables are missing for this DB/schema state.');
    $warns++;
}

$profilesWithSecrets = 0;
if (st_brr_has_table($pdo, 'credential_profiles')) {
    $st = $pdo->query(
        "SELECT COUNT(*)
         FROM credential_profiles
         WHERE deleted_at IS NULL
           AND length(trim(COALESCE(secret_ciphertext, ''))) > 0"
    );
    $profilesWithSecrets = (int) $st->fetchColumn();
}
st_brr_emit('PASS', 'Credential profiles with stored secrets: ' . $profilesWithSecrets . '.');
$passes++;

$secretAvail = st_secret_available();
$secretStatus = st_secret_status();
$helper = st_brr_helper_status();
$helperAvail = $helper['ok'] && !empty($helper['status']['available']);
if ($profilesWithSecrets > 0 && ! $secretAvail && ! $helperAvail) {
    st_brr_emit('FAIL', 'SURVEYTRACE_CRED_SECRET_KEY is unavailable while encrypted credential profiles exist.');
    $fails++;
} elseif ($profilesWithSecrets === 0 && ! $secretAvail && ! $helperAvail) {
    st_brr_emit('WARN', 'SURVEYTRACE_CRED_SECRET_KEY is unavailable (no stored credential profiles detected).');
    $warns++;
} else {
    st_brr_emit('PASS', 'Credential secret key appears available for decrypt operations (direct or helper).');
    $passes++;
}
if ($helperAvail) {
    $hs = is_array($helper['status']) ? $helper['status'] : [];
    st_brr_emit('PASS', 'Secret helper status: available=yes env_file_present=' . (!empty($hs['env_file_present']) ? 'yes' : 'no')
        . ' env_file_readable=' . (!empty($hs['env_file_readable']) ? 'yes' : 'no')
        . ' key_loaded=' . (!empty($hs['key_loaded']) ? 'yes' : 'no')
        . ' running_user=' . (string) ($hs['running_user'] ?? 'unknown'));
    $passes++;
} elseif ($secretAvail) {
    $fp = (string) ($secretStatus['key_fingerprint'] ?? '');
    $alg = (string) ($secretStatus['preferred_alg'] ?? '');
    st_brr_emit('PASS', 'Secret env visibility: available=yes source=' . (string) ($secretStatus['source'] ?? 'unknown')
        . ($alg !== '' ? ' preferred_alg=' . $alg : '')
        . ($fp !== '' ? ' key_fp=' . $fp : ''));
    $passes++;
} else {
    st_brr_emit('WARN', 'Secret env visibility: available=no source=' . (string) ($secretStatus['source'] ?? 'missing'));
    $warns++;
}

if ($profilesWithSecrets > 0) {
    try {
        $st = $pdo->query(
            "SELECT id, secret_ciphertext
             FROM credential_profiles
             WHERE deleted_at IS NULL
               AND length(trim(COALESCE(secret_ciphertext, ''))) > 0
             ORDER BY id ASC
             LIMIT 1"
        );
        $row = $st->fetch(PDO::FETCH_ASSOC);
        $pid = is_array($row) ? (int) ($row['id'] ?? 0) : 0;
        $cipher = is_array($row) ? (string) ($row['secret_ciphertext'] ?? '') : '';
        if ($pid < 1 || $cipher === '') {
            st_brr_emit('FAIL', 'Could not load a profile for decrypt validation.');
            $fails++;
        } else {
            $plain = st_secret_decrypt($cipher, ['credential_profile_id' => $pid]);
            if ($plain === '') {
                st_brr_emit('WARN', 'Decrypt validation returned an empty payload.');
                $warns++;
            } else {
                st_brr_emit('PASS', 'Decrypt validation succeeded on one stored profile secret.');
                $passes++;
            }
        }
    } catch (Throwable) {
        st_brr_emit('FAIL', 'Decrypt validation failed for stored profile secrets.');
        $fails++;
    }
} else {
    st_brr_emit('PASS', 'Decrypt validation skipped (no stored profile secrets).');
    $passes++;
}

$counts = [
    'worker_job_events' => st_brr_has_table($pdo, 'worker_job_events') ? st_brr_q_count($pdo, 'SELECT COUNT(*) FROM worker_job_events') : 0,
    'worker_job_attempts' => st_brr_has_table($pdo, 'worker_job_attempts') ? st_brr_q_count($pdo, 'SELECT COUNT(*) FROM worker_job_attempts') : 0,
    'credential_check_results' => st_brr_has_table($pdo, 'credential_check_results') ? st_brr_q_count($pdo, 'SELECT COUNT(*) FROM credential_check_results') : 0,
    'credential_check_artifacts' => st_brr_has_table($pdo, 'credential_check_artifacts') ? st_brr_q_count($pdo, 'SELECT COUNT(*) FROM credential_check_artifacts') : 0,
    'reconciliation_runs' => st_brr_has_table($pdo, 'reconciliation_runs') ? st_brr_q_count($pdo, 'SELECT COUNT(*) FROM reconciliation_runs') : 0,
];
st_brr_emit(
    'PASS',
    'Operational row counts: events=' . $counts['worker_job_events']
    . ', attempts=' . $counts['worker_job_attempts']
    . ', results=' . $counts['credential_check_results']
    . ', artifacts=' . $counts['credential_check_artifacts']
    . ', reconciliation_runs=' . $counts['reconciliation_runs'] . '.'
);
$passes++;

$tools = [
    'scripts/rewrap_credential_secrets.php',
    'scripts/prune_operational_history.php',
    'scripts/recover_stale_worker_jobs.php',
];
$missingTools = [];
foreach ($tools as $t) {
    $p = dirname(__DIR__) . '/' . $t;
    if (! is_file($p)) {
        $missingTools[] = $t;
    }
}
if ($missingTools === []) {
    st_brr_emit('PASS', 'Maintenance tools are present.');
    $passes++;
} else {
    st_brr_emit('WARN', 'One or more maintenance tools are missing from this workspace.');
    $warns++;
}

st_brr_emit('PASS', 'Reminder: restore requires the same SURVEYTRACE_CRED_SECRET_KEY across web and worker nodes.');
$passes++;

fwrite(STDOUT, "SUMMARY: fail={$fails} warn={$warns} pass={$passes}\n");
exit($fails > 0 ? 1 : 0);
