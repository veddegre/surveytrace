<?php
/**
 * CLI-only: assert run-detail preview never exposes full ssh.linux.package_inventory packages[].
 *
 *   php scripts/st_cc_normalized_preview_selftest.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_credential_check_ops.php';

$pkgs = [];
for ($i = 0; $i < 80; ++$i) {
    $pkgs[] = ['name' => 'pkg' . $i, 'version' => '1.' . $i, 'arch' => 'all'];
}

$nj = json_encode([
    'package_manager' => 'dpkg',
    'package_count'   => 80,
    'packages'        => $pkgs,
    'partial'         => false,
    'truncated'       => false,
    'source'          => 'credentialed_check',
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if (! is_string($nj)) {
    fwrite(STDERR, "FAIL: json_encode packages fixture\n");
    exit(1);
}

$prev = st_cc_normalized_preview_public('ssh.linux.package_inventory', $nj);
$dec = json_decode($prev, true);
if (! is_array($dec)) {
    fwrite(STDERR, "FAIL: preview not JSON: " . substr($prev, 0, 200) . "\n");
    exit(1);
}
if (array_key_exists('packages', $dec)) {
    fwrite(STDERR, "FAIL: preview must not contain full packages key\n");
    exit(1);
}
if (! isset($dec['packages_sample']) || ! is_array($dec['packages_sample'])) {
    fwrite(STDERR, "FAIL: packages_sample missing\n");
    exit(1);
}
if (count($dec['packages_sample']) > 5) {
    fwrite(STDERR, 'FAIL: packages_sample too long: ' . count($dec['packages_sample']) . "\n");
    exit(1);
}

$n2 = json_encode([
    'package_manager' => 'rpm',
    'package_count'   => 3,
    'packages'        => [['name' => 'a', 'version' => '1', 'arch' => 'x86_64']],
    'partial'         => true,
    'truncated'       => true,
    'source'          => 'credentialed_check',
]);
$p2 = st_cc_normalized_preview_public('ssh.linux.package_inventory', is_string($n2) ? $n2 : '');
$d2 = json_decode($p2, true);
if (! is_array($d2) || array_key_exists('packages', $d2)) {
    fwrite(STDERR, "FAIL: small preview leaked packages key\n");
    exit(1);
}

$osFail = json_encode([
    'source'            => 'credentialed_check',
    'error_code'        => 'protocol_error',
    'error_detail_safe' => 'Incompatible ssh peer (example)',
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$pos = st_cc_normalized_preview_public('ssh.linux.os_release', is_string($osFail) ? $osFail : '');
$decOs = json_decode($pos, true);
if (! is_array($decOs) || ($decOs['error_code'] ?? '') !== 'protocol_error'
    || strpos((string) ($decOs['error_detail_safe'] ?? ''), 'Incompatible') === false) {
    fwrite(STDERR, 'FAIL: os_release failure preview: ' . substr($pos, 0, 400) . "\n");
    exit(1);
}

$osOk = json_encode([
    'os_release'    => [
        'ID'            => 'ubuntu',
        'VERSION_ID'    => '24.04',
        'PRETTY_NAME'   => 'Ubuntu 24.04 LTS with a long pretty name suffix ' . str_repeat('x', 200),
        'BUILD_ID'      => 'unused',
    ],
    'normalized_os' => 'ubuntu_24_4_x',
    'source'        => 'credentialed_check',
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$posOk = st_cc_normalized_preview_public('ssh.linux.os_release', is_string($osOk) ? $osOk : '');
$dOk = json_decode($posOk, true);
if (! is_array($dOk) || array_key_exists('os_release', $dOk)) {
    fwrite(STDERR, "FAIL: os_release success preview must not embed full os_release object, got {$posOk}\n");
    exit(1);
}
if (($dOk['normalized_os'] ?? '') !== 'ubuntu_24_4_x' || ! isset($dOk['display_preview']) || ! isset($dOk['os_release_fields'])) {
    fwrite(STDERR, "FAIL: os_release success preview shape: {$posOk}\n");
    exit(1);
}
if (strlen((string) ($dOk['display_preview'] ?? '')) > 120) {
    fwrite(STDERR, "FAIL: display_preview should be bounded\n");
    exit(1);
}

echo "OK st_cc_normalized_preview_selftest\n";
