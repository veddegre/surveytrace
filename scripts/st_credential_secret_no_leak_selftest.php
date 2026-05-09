#!/usr/bin/env php
<?php
/**
 * Regression selftest: credential API payloads, previews, and audit-shaped JSON
 * must not contain secret material patterns (helper ciphertext in DB is out of scope here).
 *
 *   php scripts/st_credential_secret_no_leak_selftest.php
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_credential_profiles.php';
require_once dirname(__DIR__) . '/api/lib_secrets.php';
require_once dirname(__DIR__) . '/api/lib_credential_check_ops.php';

function st_cred_nl_fail(string $msg): void
{
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

/**
 * Fail if $haystack matches high-risk secret / credential leak patterns.
 *
 * @param list<string> $allow_substrings If matched only inside these spans, skip (e.g. known-safe literals).
 */
function st_cred_nl_assert_no_leak(string $label, string $haystack, array $allow_substrings = []): void
{
    $h = $haystack;
    foreach ($allow_substrings as $lit) {
        if ($lit !== '') {
            $h = str_replace($lit, '', $h);
        }
    }
    $patterns = [
        'json_password_key'     => '/(?i)"(password|passphrase|private_key|auth_password|priv_password|priv_passphrase|secret_ciphertext)"\s*:/',
        'json_token_key'        => '/(?i)"(api_token|access_token|refresh_token|client_secret)"\s*:/',
        'pem_private'           => '/-----BEGIN\s+[A-Z0-9 ]*PRIVATE\s+KEY-----/',
        'aws_access_key'        => '/\bAKIA[0-9A-Z]{16}\b/',
        'http_authorization'    => '/(?i)Authorization:\s*Bearer\s+\S+/',
        'assignment_password'   => '/(?i)(?:^|[\s;,{])(password|passwd|passphrase|token)\s*=\s*\S{3,}/',
        'ssh_rsa_header'        => '/-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----/',
        'ssh_ec_header'         => '/-----BEGIN\s+EC\s+PRIVATE\s+KEY-----/',
        'ssh_openssh_header'    => '/-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/',
        'long_base64_line'      => '/["\'][A-Za-z0-9+\/]{120,}={0,2}["\']/',
    ];
    foreach ($patterns as $name => $re) {
        if (preg_match($re, $h) === 1) {
            st_cred_nl_fail("{$label}: pattern {$name} matched");
        }
    }
}

// ---- 1) Public profile row (API list/detail simulation) ----
$fakeEnv = json_encode([
    'v' => 1,
    'alg' => 'sodium_secretbox',
    'nonce' => 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=',
    'ciphertext' => 'YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYg==',
    'ctxh' => str_repeat('a', 64),
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if (! is_string($fakeEnv)) {
    st_cred_nl_fail('fixture envelope encode');
}
$row = [
    'id'                 => 42,
    'name'               => 'p',
    'transport'          => 'ssh',
    'enabled'            => 1,
    'principal_json'     => '{"username":"u"}',
    'scope_json'         => '{}',
    'secret_ciphertext'  => $fakeEnv,
    '_secret_len'        => strlen($fakeEnv),
    '_secret_envelope_raw' => $fakeEnv,
];
$pub = st_cred_profile_public_row($row);
if (isset($pub['secret_ciphertext'])) {
    st_cred_nl_fail('public row still has secret_ciphertext');
}
$js = json_encode($pub, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if (! is_string($js)) {
    st_cred_nl_fail('profile json');
}
st_cred_nl_assert_no_leak('st_cred_profile_public_row JSON', $js);

// ---- 2) Normalized previews (operator / run detail) ----
$pkgNorm = json_encode([
    'package_manager' => 'dpkg',
    'package_count'   => 2,
    'packages'        => [['name' => 'curl', 'version' => '8', 'arch' => 'amd64']],
    'partial'         => false,
    'truncated'       => false,
    'source'          => 'credentialed_check',
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$prev = st_cc_normalized_preview_public('ssh.linux.package_inventory', is_string($pkgNorm) ? $pkgNorm : '');
st_cred_nl_assert_no_leak('package_inventory preview', $prev);

$osOk = json_encode([
    'os_release'     => ['ID' => 'ubuntu', 'VERSION_ID' => '24.04'],
    'normalized_os'  => 'ubuntu_24_4_x',
    'source'         => 'credentialed_check',
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$osPrev = st_cc_normalized_preview_public('ssh.linux.os_release', is_string($osOk) ? $osOk : '');
st_cred_nl_assert_no_leak('os_release preview', $osPrev);

// ---- 3) Timeline redaction must neutralize risky strings ----
$dirty = 'export password=hunter2 and token=abc123def456ghi789012345678901234567890';
$red = st_cc_timeline_redact_sensitive_string($dirty, 400);
if ($red === $dirty || stripos($red, 'hunter2') !== false) {
    st_cred_nl_fail('timeline redaction ineffective');
}
st_cred_nl_assert_no_leak('timeline redacted output', $red);

// ---- 4) Audit-shaped payloads (no values) ----
$audit = json_encode([
    'credential_profile_id' => 7,
    'transport'             => 'ssh',
    'result_code'           => 'auth_failed',
    'run_id'                => 99,
    'plugin_key'            => 'ssh.linux.os_release',
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if (! is_string($audit)) {
    st_cred_nl_fail('audit json');
}
st_cred_nl_assert_no_leak('audit fixture', $audit);

// ---- 5) public/index.php — stCredProfileDebugState must not return secret-bearing keys ----
$indexPath = dirname(__DIR__) . '/public/index.php';
$index = @file_get_contents($indexPath);
if (! is_string($index) || $index === '') {
    st_cred_nl_fail('read public/index.php');
}
if (! preg_match('/window\.stCredProfileDebugState\s*=\s*function\s+stCredProfileDebugState\s*\(\)\s*\{[^}]*return\s*\{([^}]+)\}/s', $index, $m)) {
    st_cred_nl_fail('could not locate stCredProfileDebugState return object');
}
$retBody = $m[1];
foreach (['password', 'passphrase', 'private_key', 'secret_ciphertext', 'token', 'envelope'] as $badKey) {
    if (preg_match('/\b' . preg_quote($badKey, '/') . '\s*:/', $retBody) === 1) {
        st_cred_nl_fail("stCredProfileDebugState return mentions forbidden key: {$badKey}");
    }
}

// ---- 6) Sanity: core JSON key pattern must match obvious leak ----
if (preg_match('/(?i)"password"\s*:/', '{"password":"x"}') !== 1) {
    st_cred_nl_fail('negative_control regex broken');
}

echo "OK st_credential_secret_no_leak_selftest\n";
