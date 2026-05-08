#!/usr/bin/env php
<?php
/**
 * CLI parity: invokes the same helper path as the web API (lib_cred_secret_helper).
 *
 * Run as the web user for apples-to-apples checks, e.g.:
 *   sudo -u www-data php /opt/surveytrace/scripts/st_cred_secret_helper_web_parity_selftest.php
 *
 * Exit 0 only when helper status call succeeds (same as API happy path).
 */

declare(strict_types=1);

$repoRoot = dirname(__DIR__);
require_once $repoRoot . '/api/lib_cred_secret_helper.php';

$call = st_cred_secret_helper_call(['action' => 'status'], 15);

$out = [
    'parity'               => 'st_cred_secret_helper_web_parity_selftest',
    'runtime'              => st_cred_secret_helper_runtime_diagnostics(),
    'call_ok'              => $call['ok'],
    'call_error_code'      => $call['error_code'] ?? null,
    'call_error'           => $call['error'] ?? null,
    'sudo_exit_code'       => $call['sudo_exit_code'] ?? null,
    'php_cli_bin_used'     => $call['php_cli_bin_used'] ?? null,
    'php_cli_detect_source'=> $call['php_cli_detect_source'] ?? null,
    'diagnostics_public'   => st_cred_secret_helper_public_diagnostics($call['diagnostics'] ?? null, true),
];
if ($call['ok'] && isset($call['payload']['status']) && is_array($call['payload']['status'])) {
    $out['helper_status'] = $call['payload']['status'];
}

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

exit($call['ok'] ? 0 : 1);
