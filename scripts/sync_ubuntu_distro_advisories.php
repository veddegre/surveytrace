#!/usr/bin/env php
<?php
/**
 * Fetch Canonical Ubuntu CVE OVAL per release, convert to import JSON, run import_distro_advisories.php.
 *
 * Network: uses convert_ubuntu_advisories.php --fetch (Canonical security-metadata host).
 *
 * Environment (optional):
 *   SURVEYTRACE_INSTALL_DIR   — default: parent of scripts/
 *   SURVEYTRACE_UBUNTU_ADVISORY_RELEASES — comma-separated codenames (default: resolute,noble,jammy — 26.04 LTS, 24.04 LTS, 22.04 LTS)
 *   SURVEYTRACE_UBUNTU_ADVISORY_FETCH_LIMIT — max advisories per release (default: 15000)
 *   SURVEYTRACE_UBUNTU_ADVISORY_IMPORT_MAX — max advisories passed to import_distro_advisories when chaining (default: max(30000, FETCH_LIMIT))
 *
 * CLI:
 *   php scripts/sync_ubuntu_distro_advisories.php [--dry-run] [--correlate]
 *
 *   --dry-run   Print planned releases and paths; no network or DB writes.
 *   --correlate After successful imports, run bounded inventory correlation (same host, offline).
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

require_once dirname(__DIR__) . '/api/lib_ubuntu_advisory_convert.php';

$dry = in_array('--dry-run', $argv, true);
$correlate = in_array('--correlate', $argv, true);

$install = getenv('SURVEYTRACE_INSTALL_DIR');
if (! is_string($install) || $install === '' || $install === '0') {
    $rp = realpath(dirname(__DIR__));
    $install = $rp !== false ? $rp : dirname(__DIR__);
}

$relEnv = getenv('SURVEYTRACE_UBUNTU_ADVISORY_RELEASES');
$relStr = is_string($relEnv) && $relEnv !== '' && $relEnv !== '0' ? $relEnv : 'resolute,noble,jammy';
$releases = [];
foreach (array_map('trim', explode(',', $relStr)) as $r) {
    if ($r === '') {
        continue;
    }
    $lr = strtolower($r);
    if (! st_ubuntu_validate_release($lr)) {
        fwrite(STDERR, "SKIP invalid release codename (not in allowlist): {$r}\n");
        continue;
    }
    $releases[] = $lr;
}
$releases = array_values(array_unique($releases));
if ($releases === []) {
    fwrite(STDERR, "FAIL: no valid releases after parsing SURVEYTRACE_UBUNTU_ADVISORY_RELEASES\n");
    exit(1);
}

$limEnv = getenv('SURVEYTRACE_UBUNTU_ADVISORY_FETCH_LIMIT');
$limit = is_string($limEnv) && ctype_digit($limEnv) ? max(1, min(100_000, (int) $limEnv)) : 15_000;

$impEnv = getenv('SURVEYTRACE_UBUNTU_ADVISORY_IMPORT_MAX');
$importMax = is_string($impEnv) && ctype_digit($impEnv) ? max(1000, min(100_000, (int) $impEnv)) : max(30_000, $limit);

$php = PHP_BINARY;
if ($php === '' || $php === '0') {
    $php = 'php';
}
$convert = $install . '/scripts/convert_ubuntu_advisories.php';
if (! is_file($convert)) {
    fwrite(STDERR, "FAIL: missing {$convert}\n");
    exit(1);
}

$inbox = $install . '/data/ubuntu_advisory_inbox';
if (! $dry && ! is_dir($inbox) && ! @mkdir($inbox, 0750, true) && ! is_dir($inbox)) {
    fwrite(STDERR, "FAIL: could not create inbox directory: {$inbox}\n");
    exit(1);
}

if (! $dry && (! extension_loaded('xmlreader') || ! class_exists('XMLReader', false))) {
    fwrite(STDERR, "FAIL: PHP xmlreader extension required for OVAL fetch (--fetch). Install php-xml (e.g. apt install php-xml).\n");
    exit(1);
}
if (! $dry && ! extension_loaded('bz2')) {
    fwrite(STDERR, "FAIL: PHP bz2 extension required for Canonical OVAL (*.xml.bz2 via compress.bzip2://). Install php-bz2 (e.g. apt install php-bz2).\n");
    exit(1);
}

fwrite(STDOUT, "sync_ubuntu_distro_advisories install={$install} releases=" . implode(',', $releases) . " limit={$limit} import_max={$importMax} dry_run=" . ($dry ? '1' : '0') . " correlate=" . ($correlate ? '1' : '0') . "\n");

foreach ($releases as $rel) {
    $outPath = $inbox . '/ubuntu_' . $rel . '_cve_oval.json';
    if ($dry) {
        fwrite(STDOUT, "DRY-RUN would: fetch+convert+import release={$rel} output={$outPath}\n");
        continue;
    }
    $cmd = [
        $php,
        $convert,
        '--fetch',
        '--release=' . $rel,
        '--output=' . $outPath,
        '--limit=' . (string) $limit,
        '--import',
        '--import-max-advisories=' . (string) $importMax,
    ];
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $spec, $pipes, $install, null, ['bypass_shell' => true]);
    if (! is_resource($proc)) {
        fwrite(STDERR, "FAIL: proc_open for release={$rel}\n");
        exit(1);
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    if ($code !== 0) {
        fwrite(STDERR, "FAIL: convert/import exit={$code} release={$rel}\n");
        fwrite(STDERR, $stderr !== '' ? $stderr : $stdout);
        exit($code !== 0 ? $code : 1);
    }
    fwrite(STDOUT, "OK release={$rel} import complete\n");
}

if ($correlate && ! $dry) {
    $corr = $install . '/scripts/run_vulnerability_correlation.php';
    if (! is_file($corr)) {
        fwrite(STDERR, "FAIL: missing {$corr}\n");
        exit(1);
    }
    $cmd2 = [$php, $corr, '--batch=200', '--max-seconds=300'];
    $proc2 = proc_open($cmd2, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes2, $install, null, ['bypass_shell' => true]);
    if (! is_resource($proc2)) {
        fwrite(STDERR, "FAIL: proc_open correlation\n");
        exit(1);
    }
    fclose($pipes2[0]);
    $out2 = stream_get_contents($pipes2[1]);
    $err2 = stream_get_contents($pipes2[2]);
    fclose($pipes2[1]);
    fclose($pipes2[2]);
    $c2 = proc_close($proc2);
    fwrite(STDOUT, trim($out2) . "\n");
    if ($err2 !== '') {
        fwrite(STDERR, $err2);
    }
    if ($c2 !== 0) {
        exit($c2);
    }
}

fwrite(STDOUT, "OK sync_ubuntu_distro_advisories\n");
exit(0);
