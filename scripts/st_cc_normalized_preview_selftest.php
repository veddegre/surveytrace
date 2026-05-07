<?php
/**
 * CLI-only: assert run-detail preview never exposes full ssh.linux.package_inventory packages[].
 *
 *   php scripts/st_cc_normalized_preview_slice8_selftest.php
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

echo "OK st_cc_normalized_preview_slice8_selftest\n";
