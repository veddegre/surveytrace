<?php
/**
 * SurveyTrace — admin-only credential secret helper diagnostics (no key material).
 *
 * GET /api/cred_secret_helper_debug.php
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_cred_secret_helper.php';

st_auth();
st_require_role(['admin']);

$runtime = st_cred_secret_helper_runtime_diagnostics();
$call = st_cred_secret_helper_call(['action' => 'status'], 15);

$helperCall = [
    'call_ok'               => $call['ok'],
    'error_code'            => $call['error_code'] ?? null,
    'error'                 => $call['error'] ?? null,
    'sudo_exit_code'        => $call['sudo_exit_code'] ?? null,
    'php_cli_bin_used'      => $call['php_cli_bin_used'] ?? null,
    'php_cli_detect_source' => $call['php_cli_detect_source'] ?? null,
    'diagnostics'           => st_cred_secret_helper_public_diagnostics($call['diagnostics'] ?? null, true),
];
if ($call['ok'] && isset($call['payload']['status']) && is_array($call['payload']['status'])) {
    $helperCall['status'] = $call['payload']['status'];
}

st_json([
    'ok'          => true,
    'runtime'     => $runtime,
    'helper_call' => $helperCall,
]);
