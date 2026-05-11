#!/usr/bin/env php
<?php
/**
 * Read-only release gate: aggregates security selftests (exit non-zero on failure).
 *
 *   php scripts/release_security_gate.php [--install-root=DIR] [--env-file=PATH] [--static-only] [--require-helper-parity]
 *
 * Default (full gate): check_deploy_coverage, st_credential_secret_no_leak_selftest,
 * st_cred_secret_rewrap_selftest, st_backup_restore_readiness_selftest, security_runtime_audit
 * (non-strict). Optional: st_cred_secret_helper_web_parity_selftest with --require-helper-parity
 * (needs sudoers + sudo on the host).
 *
 * --static-only: same first four steps only (manifest + leak regression + rewrap + backup readiness).
 * Skips security_runtime_audit.php so deploy/setup can run this on any checkout without failing on
 * host/env/sudoers checks. For pre-release, run the full gate on a configured staging/master host.
 *
 * Use scripts/security_runtime_audit.php --strict separately for CI that must fail on WARN.
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$installRoot = $root;
$envFile = '/etc/surveytrace/surveytrace.env';
$requireHelperParity = false;
$staticOnly = false;
foreach (array_slice($argv, 1) as $a) {
    if (str_starts_with($a, '--install-root=')) {
        $installRoot = (string) substr($a, strlen('--install-root='));
    } elseif (str_starts_with($a, '--env-file=')) {
        $envFile = (string) substr($a, strlen('--env-file='));
    } elseif ($a === '--require-helper-parity') {
        $requireHelperParity = true;
    } elseif ($a === '--static-only') {
        $staticOnly = true;
    } elseif ($a === '-h' || $a === '--help') {
        fwrite(STDOUT, "Usage: php scripts/release_security_gate.php [--install-root=DIR] [--env-file=PATH] [--static-only] [--require-helper-parity]\n");
        exit(0);
    }
}

function gate_run(string $label, array $cmd, string $cwd): int
{
    fwrite(STDOUT, "[gate] {$label} …\n");
    $des = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $des, $pipes, $cwd, null, ['bypass_shell' => true]);
    if (! is_resource($proc)) {
        fwrite(STDERR, "[gate] FAIL {$label}: proc_open\n");

        return 2;
    }
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $rc = proc_close($proc);
    if ($rc !== 0) {
        fwrite(STDERR, "[gate] FAIL {$label} exit={$rc}\n" . $out . $err);

        return $rc;
    }
    fwrite(STDOUT, $out);

    return 0;
}

$php = PHP_BINARY;
$steps = [
    ['check_deploy_coverage', [$php, $root . '/scripts/check_deploy_coverage.php', $root]],
    ['st_credential_secret_no_leak_selftest', [$php, $root . '/scripts/st_credential_secret_no_leak_selftest.php']],
    ['st_cred_secret_rewrap_selftest', [$php, $root . '/scripts/st_cred_secret_rewrap_selftest.php']],
    ['st_backup_restore_readiness_selftest', [$php, $root . '/scripts/st_backup_restore_readiness_selftest.php']],
    ['check_database_integrity', [$php, $root . '/scripts/check_database_integrity.php']],
    ['run_operational_integrity_suite', [$php, $root . '/scripts/run_operational_integrity_suite.php']],
];
if (! $staticOnly) {
    $steps[] = [
        'security_runtime_audit',
        [$php, $root . '/scripts/security_runtime_audit.php', '--install-root=' . $installRoot, '--env-file=' . $envFile],
    ];
} else {
    fwrite(STDOUT, "[gate] SKIP security_runtime_audit.php (--static-only; run full gate on staging/master)\n");
}
if ($requireHelperParity) {
    array_splice($steps, 2, 0, [
        ['st_cred_secret_helper_web_parity_selftest', [$php, $root . '/scripts/st_cred_secret_helper_web_parity_selftest.php']],
    ]);
} elseif ($staticOnly) {
    fwrite(STDOUT, "[gate] SKIP st_cred_secret_helper_web_parity_selftest (optional: --require-helper-parity)\n");
} else {
    fwrite(STDOUT, "[gate] SKIP st_cred_secret_helper_web_parity_selftest (pass --require-helper-parity on a host with sudoers helper)\n");
}

foreach ($steps as [$label, $cmd]) {
    $rc = gate_run((string) $label, $cmd, $root);
    if ($rc !== 0) {
        exit($rc);
    }
}

fwrite(STDOUT, $staticOnly ? "OK release_security_gate (static-only; all steps passed)\n" : "OK release_security_gate (all steps passed)\n");
exit(0);
