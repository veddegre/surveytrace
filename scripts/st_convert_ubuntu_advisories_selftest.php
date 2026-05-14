<?php
/**
 * Selftest: Ubuntu advisory convert helper (lib + CLI smoke).
 *
 *   php scripts/st_convert_ubuntu_advisories_selftest.php
 */

declare(strict_types=1);

function st_cu_fail(string $m): void
{
    fwrite(STDERR, 'FAIL: ' . $m . "\n");
    exit(1);
}

require_once dirname(__DIR__) . '/api/lib_ubuntu_advisory_convert.php';

$root = dirname(__DIR__);
$intPath = $root . '/docs/samples/ubuntu_intermediate.sample.json';
$ovalPath = $root . '/docs/samples/ubuntu_oval_fragment.xml';
$prodPath = $root . '/docs/samples/ubuntu_production.sample.json';

if (! is_readable($intPath) || ! is_readable($ovalPath)) {
    st_cu_fail('sample fixtures missing');
}

$intRaw = file_get_contents($intPath);
$intDoc = json_decode($intRaw, true);
if (! is_array($intDoc)) {
    st_cu_fail('intermediate sample JSON');
}

$out = st_ubuntu_intermediate_v1_to_import($intDoc);
if (($out['distro_source'] ?? '') !== 'ubuntu') {
    st_cu_fail('distro_source ubuntu');
}
if (count($out['advisories']) !== 2) {
    st_cu_fail('expected 2 advisories for multi-release CVE (jammy + noble), got ' . count($out['advisories']));
}
$jam = null;
$nob = null;
foreach ($out['advisories'] as $a) {
    if (($a['distro_release'] ?? '') === 'jammy') {
        $jam = $a;
    }
    if (($a['distro_release'] ?? '') === 'noble') {
        $nob = $a;
    }
}
if (! is_array($jam) || ! is_array($nob)) {
    st_cu_fail('jammy and noble rows');
}
if (count($jam['packages']) !== 1 || ($jam['packages'][0]['binary_package'] ?? '') !== 'testpkg-a') {
    st_cu_fail('jammy: missing-fv and needed packages must be skipped');
}
if (count($nob['packages']) !== 1) {
    st_cu_fail('noble package count');
}
if (strpos($jam['description'] ?? '', '<') !== false) {
    st_cu_fail('HTML should be stripped from description');
}
if (count($jam['references'] ?? []) > 24) {
    st_cu_fail('references bound');
}

$pass = json_decode(file_get_contents($prodPath), true);
if (! is_array($pass)) {
    st_cu_fail('production sample read');
}
$norm = st_ubuntu_normalize_pass_through($pass, 'jammy', 1000);
$cJam = count($norm['advisories']);
$norm2 = st_ubuntu_normalize_pass_through($pass, null, 2);
if (count($norm2['advisories']) !== 2) {
    st_cu_fail('--limit style slice: expected 2 advisories');
}
if ($cJam < 1) {
    st_cu_fail('jammy filter should keep jammy advisories');
}

$tmpOut = sys_get_temp_dir() . '/st_cu_out_' . bin2hex(random_bytes(4)) . '.json';
$cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/scripts/convert_ubuntu_advisories.php')
    . ' --input=' . escapeshellarg($ovalPath)
    . ' --output=' . escapeshellarg($tmpOut)
    . ' --release=jammy --format=oval --limit=50';
exec($cmd, $o, $code);
if ($code !== 0) {
    st_cu_fail('CLI oval convert exit ' . $code);
}
$ovalOut = json_decode((string) file_get_contents($tmpOut), true);
@unlink($tmpOut);
if (! is_array($ovalOut) || ($ovalOut['distro_source'] ?? '') !== 'ubuntu') {
    st_cu_fail('oval CLI output shape');
}
if (count($ovalOut['advisories'] ?? []) !== 1) {
    st_cu_fail('oval fragment: expected 1 advisory');
}
$a0 = $ovalOut['advisories'][0];
if (($a0['cve_id'] ?? '') !== 'CVE-2099-99999' || count($a0['packages'] ?? []) !== 1) {
    st_cu_fail('oval CVE / package');
}
if (($a0['packages'][0]['binary_package'] ?? '') !== 'ovaltestpkg') {
    st_cu_fail('oval binary name');
}

$tmpOut2 = sys_get_temp_dir() . '/st_cu_int_' . bin2hex(random_bytes(4)) . '.json';
$cmd2 = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/scripts/convert_ubuntu_advisories.php')
    . ' --input=' . escapeshellarg($intPath)
    . ' --output=' . escapeshellarg($tmpOut2)
    . ' --format=intermediate --limit=50';
exec($cmd2, $o2, $code2);
if ($code2 !== 0) {
    st_cu_fail('CLI intermediate convert exit ' . $code2);
}
$cliInt = json_decode((string) file_get_contents($tmpOut2), true);
@unlink($tmpOut2);
if (count($cliInt['advisories'] ?? []) !== 2) {
    st_cu_fail('CLI intermediate should match lib advisory count');
}

echo "OK st_convert_ubuntu_advisories_selftest\n";
exit(0);
