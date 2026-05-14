<?php
/**
 * Selftest: Ubuntu advisory convert helper (lib + CLI smoke).
 *
 * Fixtures are embedded so this passes on installs where docs/samples may lag
 * deploy check_file parity; CLI tests write temp files under sys_get_temp_dir().
 *
 *   php scripts/st_convert_ubuntu_advisories_selftest.php
 */

declare(strict_types=1);

function st_cu_fail(string $m): void
{
    fwrite(STDERR, 'FAIL: ' . $m . "\n");
    exit(1);
}

function st_cu_tmp(string $suffix): string
{
    return rtrim(sys_get_temp_dir(), '/') . '/st_cu_' . bin2hex(random_bytes(6)) . $suffix;
}

require_once dirname(__DIR__) . '/api/lib_ubuntu_advisory_convert.php';

$root = dirname(__DIR__);

// --- Embedded fixtures (must match convert_ubuntu_advisories.php + lib contracts) ---

$fixtureIntermediateJson = <<<'JSON'
{
  "surveytrace_ubuntu_intermediate_v1": true,
  "distro_release": "jammy",
  "cves": [
    {
      "cve_id": "CVE-2099-88881",
      "description": "<p>Test <b>HTML</b> stripped.</p>",
      "severity": "high",
      "cvss_score": 8.1,
      "published_at": "2026-01-01T00:00:00Z",
      "modified_at": "2026-01-02T00:00:00Z",
      "distro_release": "jammy",
      "withdrawn": false,
      "references": [
        {"url": "https://ubuntu.com/security/CVE-2099-88881"},
        {"url": "https://www.cve.org/CVERecord?id=CVE-2099-88881"}
      ],
      "packages": [
        {"binary_package": "testpkg-a", "source_package": "testsrc-a", "fixed_version": "1.0-1ubuntu1", "status": "released"},
        {"binary_package": "testpkg-no-fv", "status": "released"},
        {"binary_package": "testpkg-needed", "fixed_version": "2.0-1", "status": "needed"}
      ]
    },
    {
      "cve_id": "CVE-2099-88881",
      "description": "Same CVE on noble (multi-release preservation).",
      "severity": "high",
      "published_at": "2026-01-01T00:00:00Z",
      "distro_release": "noble",
      "packages": [
        {"binary_package": "testpkg-a", "fixed_version": "1.2-0ubuntu2", "status": "released"}
      ]
    }
  ]
}
JSON;

$fixtureOvalXml = <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
    <definition class="vulnerability" id="oval:com.ubuntu.jammy:def:20999990001" version="1">
      <metadata>
        <title>CVE-2099-99999 on Ubuntu 22.04 LTS (jammy) - high</title>
        <description>Test &lt;b&gt;HTML&lt;/b&gt; in OVAL description.</description>
        <reference source="CVE" ref_id="CVE-2099-99999" ref_url="https://ubuntu.com/security/CVE-2099-99999"/>
        <advisory>
          <severity>High</severity>
          <public_date>2026-01-01 12:00:00 UTC</public_date>
          <cve href="https://ubuntu.com/security/CVE-2099-99999" cvss_score="9.1" cvss_severity="critical">CVE-2099-99999</cve>
        </advisory>
      </metadata>
      <criteria>
        <criteria operator="OR">
          <criterion comment="ovaltestpkg package in jammy was vulnerable but has been fixed (note: '2.4-1ubuntu3')."/>
        </criteria>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>
XML;

$fixturePassThroughJson = <<<'JSON'
{
  "distro_source": "ubuntu",
  "advisories": [
    {
      "cve_id": "CVE-2099-77701",
      "distro_release": "jammy",
      "description": "one",
      "packages": [{"binary_package": "pkg-a", "fixed_version": "1-1", "status": "released"}]
    },
    {
      "cve_id": "CVE-2099-77702",
      "distro_release": "noble",
      "packages": [{"binary_package": "pkg-b", "fixed_version": "2-1", "status": "released"}]
    },
    {
      "cve_id": "CVE-2099-77703",
      "distro_release": "jammy",
      "packages": [{"binary_package": "pkg-c", "fixed_version": "3-1", "status": "released"}]
    }
  ]
}
JSON;

$intDoc = json_decode($fixtureIntermediateJson, true);
if (! is_array($intDoc)) {
    st_cu_fail('embedded intermediate JSON');
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

$pass = json_decode($fixturePassThroughJson, true);
if (! is_array($pass)) {
    st_cu_fail('embedded pass-through JSON');
}
$norm = st_ubuntu_normalize_pass_through($pass, 'jammy', 1000);
$cJam = count($norm['advisories']);
$norm2 = st_ubuntu_normalize_pass_through($pass, null, 2);
if (count($norm2['advisories']) !== 2) {
    st_cu_fail('--limit style slice: expected 2 advisories');
}
if ($cJam !== 2) {
    st_cu_fail('jammy filter should keep 2 jammy advisories');
}

if (! function_exists('exec')) {
    st_cu_fail('exec() required for CLI subprocess smoke');
}
$df = ini_get('disable_functions');
if (is_string($df) && $df !== '') {
    foreach (array_map('trim', explode(',', $df)) as $fn) {
        if (strtolower($fn) === 'exec') {
            st_cu_fail('exec() disabled in php.ini (disable_functions)');
        }
    }
}

$php = PHP_BINARY;
if (! is_executable($php) && PHP_BINARY !== '') {
    $php = 'php';
}

$intFile = st_cu_tmp('.intermediate.json');
$ovalFile = st_cu_tmp('.fragment.xml');
if (@file_put_contents($intFile, $fixtureIntermediateJson) === false) {
    st_cu_fail('temp intermediate write');
}
if (@file_put_contents($ovalFile, $fixtureOvalXml) === false) {
    @unlink($intFile);
    st_cu_fail('temp oval write');
}

$tmpOut = st_cu_tmp('.out.json');
$cmd = escapeshellarg($php) . ' ' . escapeshellarg($root . '/scripts/convert_ubuntu_advisories.php')
    . ' --input=' . escapeshellarg($ovalFile)
    . ' --output=' . escapeshellarg($tmpOut)
    . ' --release=jammy --format=oval --limit=50';
exec($cmd, $o, $code);
if ($code !== 0) {
    @unlink($intFile);
    @unlink($ovalFile);
    @unlink($tmpOut);
    st_cu_fail('CLI oval convert exit ' . $code);
}
$ovalOut = json_decode((string) @file_get_contents($tmpOut), true);
@unlink($tmpOut);
@unlink($ovalFile);
if (! is_array($ovalOut) || ($ovalOut['distro_source'] ?? '') !== 'ubuntu') {
    @unlink($intFile);
    st_cu_fail('oval CLI output shape');
}
if (count($ovalOut['advisories'] ?? []) !== 1) {
    @unlink($intFile);
    st_cu_fail('oval fragment: expected 1 advisory');
}
$a0 = $ovalOut['advisories'][0];
if (($a0['cve_id'] ?? '') !== 'CVE-2099-99999' || count($a0['packages'] ?? []) !== 1) {
    @unlink($intFile);
    st_cu_fail('oval CVE / package');
}
if (($a0['packages'][0]['binary_package'] ?? '') !== 'ovaltestpkg') {
    @unlink($intFile);
    st_cu_fail('oval binary name');
}

$tmpOut2 = st_cu_tmp('.out2.json');
$cmd2 = escapeshellarg($php) . ' ' . escapeshellarg($root . '/scripts/convert_ubuntu_advisories.php')
    . ' --input=' . escapeshellarg($intFile)
    . ' --output=' . escapeshellarg($tmpOut2)
    . ' --format=intermediate --limit=50';
exec($cmd2, $o2, $code2);
if ($code2 !== 0) {
    @unlink($intFile);
    @unlink($tmpOut2);
    st_cu_fail('CLI intermediate convert exit ' . $code2);
}
$cliInt = json_decode((string) @file_get_contents($tmpOut2), true);
@unlink($tmpOut2);
@unlink($intFile);
if (count($cliInt['advisories'] ?? []) !== 2) {
    st_cu_fail('CLI intermediate should match lib advisory count');
}

echo "OK st_convert_ubuntu_advisories_selftest\n";
exit(0);
