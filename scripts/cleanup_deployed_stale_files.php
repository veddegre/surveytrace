#!/usr/bin/env php
<?php
/**
 * Remove application files under the install root that no longer belong to the shipped manifest.
 *
 * Default: dry-run (lists candidates only). Deletes only with --apply.
 *
 * Usage:
 *   php scripts/cleanup_deployed_stale_files.php --install-root=/opt/surveytrace [--manifest-path=/path/to/deploy_file_manifest.php] [--repo-src=/path/to/repo] [--apply]
 *
 * --manifest-path defaults to {install-root}/scripts/deploy_file_manifest.php (often use repo copy during deploy).
 * --repo-src enables docs/ comparison (files under install-root/docs not present in repo-src/docs are stale).
 *
 * Never scans or deletes: data/, backups/, venv/, .git/, SQLite/WAL/SHM, logs (heuristic), .env, surveytrace.env.
 * Does not delete unexpected files under public/ unless --apply-public-extras (operators may add assets).
 */
declare(strict_types=1);

/**
 * @return array{0: array<string, string>, 1: array<string, list<string>>}
 */
function st_cleanup_parse_argv(array $argv): array
{
    $opts = [
        'install-root'         => '',
        'manifest-path'        => '',
        'repo-src'             => '',
        'audit-log'            => '',
        'apply'                => false,
        'apply-public-extras'  => false,
        'verbose'              => false,
        'allow-nonstandard-root' => false,
    ];
    $rest = [];
    foreach (array_slice($argv, 1) as $a) {
        if ($a === '--apply') {
            $opts['apply'] = true;

            continue;
        }
        if ($a === '--apply-public-extras') {
            $opts['apply-public-extras'] = true;

            continue;
        }
        if ($a === '--verbose' || $a === '-v') {
            $opts['verbose'] = true;

            continue;
        }
        if ($a === '--allow-nonstandard-root') {
            $opts['allow-nonstandard-root'] = true;

            continue;
        }
        if (preg_match('/^--install-root=(.+)$/', $a, $m)) {
            $opts['install-root'] = $m[1];

            continue;
        }
        if (preg_match('/^--manifest-path=(.+)$/', $a, $m)) {
            $opts['manifest-path'] = $m[1];

            continue;
        }
        if (preg_match('/^--repo-src=(.+)$/', $a, $m)) {
            $opts['repo-src'] = $m[1];

            continue;
        }
        if (preg_match('/^--audit-log=(.+)$/', $a, $m)) {
            $opts['audit-log'] = $m[1];

            continue;
        }
        if ($a === '--help' || $a === '-h') {
            fwrite(STDOUT, <<<'TXT'
SurveyTrace — stale deployed file cleanup (manifest-driven)

  --install-root=PATH     Install root (e.g. /opt/surveytrace) [required]
  --manifest-path=PATH    deploy_file_manifest.php [default: {install-root}/scripts/deploy_file_manifest.php]
  --repo-src=PATH         Fresh repo checkout — enables docs/ stale detection vs docs/
  --audit-log=PATH        Append JSON audit lines on --apply [default: {install-root}/data/deploy_stale_cleanup_audit.log if writable]
  --apply                 Actually delete files (default: dry-run)
  --apply-public-extras   Also delete unexpected files under public/ (off by default)
  --allow-nonstandard-root   Skip heuristic check that the tree looks like SurveyTrace
  --verbose               More detail

TXT);
            exit(0);
        }
        $rest[] = $a;
    }
    if ($rest !== []) {
        fwrite(STDERR, 'Unknown arguments: ' . implode(' ', $rest) . "\n");

        exit(2);
    }

    return [$opts, $rest];
}

/** Old deployed paths (relative to install root) → short reason */
function st_cleanup_known_renamed(): array
{
    return [
        'scripts/st_recon_slice10_selftest.php'                    => 'renamed → st_recon_trusted_data_selftest.php',
        'scripts/st_software_inventory_slice2_selftest.php'       => 'renamed → st_software_inventory_summary_selftest.php',
        'scripts/st_software_inventory_slice3_selftest.php'     => 'renamed → st_software_inventory_evidence_selftest.php',
        'scripts/st_software_inventory_slice4_selftest.php'       => 'renamed → st_software_inventory_diagnostics_selftest.php',
        'scripts/st_cc_normalized_preview_slice8_selftest.php'    => 'renamed → st_cc_normalized_preview_selftest.php',
        'daemon/cred_check_slice7_selftest.py'                    => 'renamed → cred_check_os_release_selftest.py',
        'daemon/cred_check_slice8_pkg_selftest.py'                => 'renamed → cred_check_package_inventory_selftest.py',
        'daemon/cred_check_slice9_snmp_selftest.py'               => 'renamed → cred_check_snmp_identity_selftest.py',
        'daemon/st_software_obs_slice1_selftest.py'               => 'renamed → st_software_observation_selftest.py',
    ];
}

function st_cleanup_realpath_dir(string $path): ?string
{
    $rp = realpath($path);

    return ($rp !== false && is_dir($rp)) ? $rp : null;
}

function st_cleanup_realpath_file(string $path): ?string
{
    $rp = realpath($path);

    return ($rp !== false && is_file($rp)) ? $rp : null;
}

/**
 * @param array<string, list<string>> $manifest
 *
 * @return array<string, true>
 */
function st_cleanup_expected_paths(array $manifest): array
{
    $set = [];
    foreach ($manifest['api_files'] ?? [] as $bn) {
        $set['api/' . $bn] = true;
    }
    foreach ($manifest['daemon_core_py'] ?? [] as $bn) {
        $set['daemon/' . $bn] = true;
    }
    foreach ($manifest['daemon_optional_py'] ?? [] as $bn) {
        $set['daemon/' . $bn] = true;
    }
    foreach ($manifest['daemon_other_files'] ?? [] as $bn) {
        $set['daemon/' . $bn] = true;
    }
    foreach ($manifest['daemon_sources_py'] ?? [] as $bn) {
        $set['daemon/sources/' . $bn] = true;
    }
    foreach ($manifest['scripts_php'] ?? [] as $bn) {
        $set['scripts/' . $bn] = true;
    }
    foreach ($manifest['scripts_dev_only'] ?? [] as $bn) {
        $set['scripts/' . $bn] = true;
    }
    foreach ($manifest['public_files'] ?? [] as $rel) {
        $set[$rel] = true;
    }
    foreach ($manifest['sql_files'] ?? [] as $rel) {
        $set[$rel] = true;
    }
    foreach ($manifest['service_units'] ?? [] as $bn) {
        $set[$bn] = true;
    }
    // Operators may legitimately keep VERSION; always treat as expected if present.
    $set['VERSION'] = true;

    return $set;
}

/**
 * @return array<string, true>
 */
function st_cleanup_expected_docs_from_repo(string $repoDocs): array
{
    $set = [];
    $iter = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($repoDocs, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iter as $fi) {
        /** @var SplFileInfo $fi */
        if (! $fi->isFile()) {
            continue;
        }
        $full = $fi->getPathname();
        $rel = 'docs/' . ltrim(str_replace('\\', '/', substr($full, strlen(rtrim($repoDocs, '/')) + 1)), '/');
        $set[$rel] = true;
    }

    return $set;
}

function st_cleanup_forbidden_delete_segment(string $rel): bool
{
    $parts = explode('/', str_replace('\\', '/', $rel));
    $blocked = ['data', 'backups', 'venv', '.git'];
    foreach ($parts as $p) {
        if ($p !== '' && in_array($p, $blocked, true)) {
            return true;
        }
    }

    return false;
}

function st_cleanup_forbidden_basename(string $bn): bool
{
    if ($bn === '.env' || $bn === 'surveytrace.env' || $bn === 'config.local.php') {
        return true;
    }
    if (preg_match('/\.(db|sqlite|sqlite3)(-wal|-shm)?$/i', $bn)) {
        return true;
    }
    if (preg_match('/\.log$/i', $bn)) {
        return true;
    }

    return false;
}

/**
 * @param array<string, true> $expected
 *
 * @return list<array{rel:string,category:string,reason:string}>
 */
function st_cleanup_collect_candidates(string $root, array $expected, ?array $expectedDocs, array $knownRenamed, bool $scanDocs, bool $verbose): array
{
    $candidates = [];

    $tryAdd = function (string $rel, string $category, string $reason) use (&$candidates, $expected, $knownRenamed, $root): void {
        $rel = str_replace('\\', '/', $rel);
        if ($rel === '' || str_contains($rel, '..')) {
            return;
        }
        if (st_cleanup_forbidden_delete_segment($rel)) {
            return;
        }
        $bn = basename($rel);
        if (st_cleanup_forbidden_basename($bn)) {
            return;
        }
        if (isset($expected[$rel])) {
            return;
        }
        if (isset($knownRenamed[$rel])) {
            $reason = $knownRenamed[$rel];
            $category = 'renamed';
        }
        $full = $root . '/' . $rel;
        if (is_link($full)) {
            $rp = realpath($full);
            $unsafe = $rp === false || ($rp !== $root && ! str_starts_with($rp, $root . DIRECTORY_SEPARATOR));
            if ($unsafe) {
                if ($verbose) {
                    fwrite(STDERR, "[SKIP unsafe symlink] {$rel}\n");
                }

                return;
            }
        }
        $candidates[] = ['rel' => $rel, 'category' => $category, 'reason' => $reason];
    };

    // api/*.php
    $apiDir = $root . '/api';
    if (is_dir($apiDir)) {
        foreach (glob($apiDir . '/*.php', GLOB_NOSORT) ?: [] as $f) {
            $rel = 'api/' . basename((string) $f);
            $tryAdd($rel, 'obsolete', 'not listed in deploy manifest (api_files)');
        }
    }

    // daemon/*
    $daemonDir = $root . '/daemon';
    if (is_dir($daemonDir)) {
        foreach (scandir($daemonDir) ?: [] as $bn) {
            if ($bn === '.' || $bn === '..' || $bn === 'sources') {
                continue;
            }
            $full = $daemonDir . '/' . $bn;
            if (! is_file($full) && ! is_link($full)) {
                continue;
            }
            $rel = 'daemon/' . $bn;
            $tryAdd($rel, 'obsolete', 'not listed in deploy manifest (daemon)');
        }
        $srcDir = $daemonDir . '/sources';
        if (is_dir($srcDir)) {
            foreach (glob($srcDir . '/*.py', GLOB_NOSORT) ?: [] as $f) {
                $rel = 'daemon/sources/' . basename((string) $f);
                $tryAdd($rel, 'obsolete', 'not listed in deploy manifest (daemon/sources)');
            }
        }
    }

    // scripts/*.php
    $scrDir = $root . '/scripts';
    if (is_dir($scrDir)) {
        foreach (glob($scrDir . '/*.php', GLOB_NOSORT) ?: [] as $f) {
            $rel = 'scripts/' . basename((string) $f);
            $tryAdd($rel, 'obsolete', 'not listed in deploy manifest (scripts)');
        }
    }

    // sql/*
    $sqlDir = $root . '/sql';
    if (is_dir($sqlDir)) {
        foreach (glob($sqlDir . '/*', GLOB_NOSORT) ?: [] as $f) {
            if (! is_file((string) $f)) {
                continue;
            }
            $rel = 'sql/' . basename((string) $f);
            $tryAdd($rel, 'obsolete', 'not listed in deploy manifest (sql)');
        }
    }

    // public/** — default category public_extra (needs flag to delete)
    $pubRoot = $root . '/public';
    if (is_dir($pubRoot)) {
        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($pubRoot, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iter as $fi) {
            /** @var SplFileInfo $fi */
            if (! $fi->isFile()) {
                continue;
            }
            $full = $fi->getPathname();
            if (is_link($full)) {
                continue;
            }
            $rpFile = st_cleanup_realpath_file($full);
            if ($rpFile === null) {
                continue;
            }
            if ($rpFile !== $root && ! str_starts_with($rpFile, $root . DIRECTORY_SEPARATOR)) {
                continue;
            }
            $rel = ltrim(str_replace('\\', '/', substr($rpFile, strlen($root) + 1)), '/');
            if (isset($expected[$rel])) {
                continue;
            }
            if (st_cleanup_forbidden_delete_segment($rel)) {
                continue;
            }
            $tryAdd($rel, 'public_extra', 'not in manifest public_files (use --apply-public-extras to remove)');
        }
    }

    // docs/** — only when expectedDocs provided
    if ($scanDocs && $expectedDocs !== null && is_dir($root . '/docs')) {
        $docRoot = $root . '/docs';
        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($docRoot, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iter as $fi) {
            /** @var SplFileInfo $fi */
            if (! $fi->isFile()) {
                continue;
            }
            $full = $fi->getPathname();
            if (is_link($full)) {
                continue;
            }
            $rpFile = st_cleanup_realpath_file($full);
            if ($rpFile === null) {
                continue;
            }
            if ($rpFile !== $root && ! str_starts_with($rpFile, $root . DIRECTORY_SEPARATOR)) {
                continue;
            }
            $rel = ltrim(str_replace('\\', '/', substr($rpFile, strlen($root) + 1)), '/');
            if (str_starts_with($rel, 'docs/data/')) {
                continue;
            }
            if (! isset($expectedDocs[$rel])) {
                $tryAdd($rel, 'docs_obsolete', 'absent from --repo-src docs tree');
            }
        }
    }

    // Root *.service only
    foreach (glob($root . '/*.service', GLOB_NOSORT) ?: [] as $f) {
        if (! is_file((string) $f) && ! is_link((string) $f)) {
            continue;
        }
        $bn = basename((string) $f);
        $rel = $bn;
        $tryAdd($rel, 'service_obsolete', 'not listed in manifest service_units');
    }

    // Dedupe by rel (public iter might overlap — shouldn't)
    $uniq = [];
    foreach ($candidates as $c) {
        $uniq[$c['rel']] = $c;
    }

    return array_values($uniq);
}

/**
 * @param list<array{rel:string,category:string,reason:string}> $candidates
 */
function st_cleanup_filter_deletable(array $candidates, bool $applyPublicExtras): array
{
    $out = [];
    foreach ($candidates as $c) {
        if ($c['category'] === 'public_extra' && ! $applyPublicExtras) {
            continue;
        }
        $out[] = $c;
    }

    return $out;
}

function st_cleanup_append_audit(string $path, array $entry): void
{
    $dir = dirname($path);
    if (! is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }
    $line = json_encode($entry, JSON_UNESCAPED_SLASHES) . "\n";
    @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
}

[$opts] = st_cleanup_parse_argv($argv);

if ($opts['install-root'] === '') {
    fwrite(STDERR, "cleanup_deployed_stale_files: --install-root required\n");

    exit(2);
}

$rootRp = st_cleanup_realpath_dir($opts['install-root']);
if ($rootRp === null) {
    fwrite(STDERR, "cleanup_deployed_stale_files: install root not found or not a directory: {$opts['install-root']}\n");

    exit(2);
}

$rootParent = dirname($rootRp);
if ($rootRp === '/' || $rootRp === $rootParent || preg_match('#^/(bin|boot|dev|etc|lib|proc|run|sys|usr)(/|$)#', $rootRp)) {
    fwrite(STDERR, "cleanup_deployed_stale_files: refusing unsafe install root: {$rootRp}\n");

    exit(2);
}

if (! $opts['allow-nonstandard-root']) {
    $looks = is_file($rootRp . '/api/st_version.php') || is_file($rootRp . '/api/db.php');
    if (! $looks) {
        fwrite(STDERR, "cleanup_deployed_stale_files: install root does not look like SurveyTrace (missing api/st_version.php and api/db.php). Use --allow-nonstandard-root to override.\n");

        exit(2);
    }
}

$mPath = $opts['manifest-path'] !== '' ? $opts['manifest-path'] : ($rootRp . '/scripts/deploy_file_manifest.php');
$mRp = st_cleanup_realpath_file($mPath);
if ($mRp === null || ! is_readable($mRp)) {
    fwrite(STDERR, "cleanup_deployed_stale_files: manifest not readable: {$mPath}\n");

    exit(2);
}
/** @var array<string, list<string>> $manifest */
$manifest = require $mRp;
$expected = st_cleanup_expected_paths($manifest);
$knownRenamed = st_cleanup_known_renamed();

$repoSrc = $opts['repo-src'];
$expectedDocs = null;
$scanDocs = false;
if ($repoSrc !== '') {
    $docsRp = st_cleanup_realpath_dir(rtrim($repoSrc, '/') . '/docs');
    if ($docsRp === null) {
        fwrite(STDERR, "cleanup_deployed_stale_files: --repo-src has no readable docs/ directory\n");

        exit(2);
    }
    $expectedDocs = st_cleanup_expected_docs_from_repo($docsRp);
    $scanDocs = true;
}

$candidates = st_cleanup_collect_candidates($rootRp, $expected, $expectedDocs, $knownRenamed, $scanDocs, $opts['verbose']);
$toDelete = st_cleanup_filter_deletable($candidates, $opts['apply-public-extras']);

if ($candidates === []) {
    fwrite(STDOUT, "cleanup_deployed_stale_files: no stale paths detected under {$rootRp}\n");

    exit(0);
}

fwrite(STDOUT, 'cleanup_deployed_stale_files: ' . ($opts['apply'] ? 'APPLY' : 'DRY-RUN') . " — install root {$rootRp}\n");
foreach ($candidates as $c) {
    $will = '';
    if ($c['category'] === 'public_extra' && ! $opts['apply-public-extras']) {
        $will = ' [listed only — needs --apply-public-extras to delete]';
    }
    fwrite(STDOUT, sprintf(
        "  %-18s  %-22s  %s%s\n",
        $c['category'],
        $c['rel'],
        $c['reason'],
        $will
    ));
}

if (! $opts['apply']) {
    fwrite(STDOUT, "\nNo files deleted (dry-run). Re-run with --apply after backup to remove deletable rows above (plus --apply-public-extras for public_extra).\n");

    exit(0);
}

$auditPath = $opts['audit-log'];
if ($auditPath === '') {
    $auditPath = $rootRp . '/data/deploy_stale_cleanup_audit.log';
}

$ts = gmdate('c');
$deleted = 0;
$failed = 0;

foreach ($toDelete as $c) {
    $full = $rootRp . '/' . $c['rel'];
    if (st_cleanup_forbidden_delete_segment($c['rel']) || st_cleanup_forbidden_basename(basename($c['rel']))) {
        fwrite(STDERR, "[SKIP forbidden] {$c['rel']}\n");
        ++$failed;

        continue;
    }

    $removed = false;
    if (is_link($full)) {
        $tgt = realpath($full);
        if ($tgt !== false && $tgt !== $rootRp && ! str_starts_with($tgt, $rootRp . DIRECTORY_SEPARATOR)) {
            fwrite(STDERR, "[SKIP unsafe symlink] {$c['rel']}\n");
            ++$failed;

            continue;
        }
        $removed = @unlink($full);
    } else {
        $rp = st_cleanup_realpath_file($full);
        if ($rp === null || ($rp !== $rootRp && ! str_starts_with($rp, $rootRp . DIRECTORY_SEPARATOR))) {
            fwrite(STDERR, "[SKIP] outside root or missing: {$c['rel']}\n");
            ++$failed;

            continue;
        }
        $removed = @unlink($rp);
    }

    if ($removed) {
        ++$deleted;
        st_cleanup_append_audit($auditPath, [
            'ts_utc'   => $ts,
            'action'   => 'deleted_stale_deploy_file',
            'path'     => $c['rel'],
            'category' => $c['category'],
            'reason'   => $c['reason'],
        ]);
    } else {
        fwrite(STDERR, "[FAIL unlink] {$c['rel']}\n");
        ++$failed;
    }
}

fwrite(STDOUT, "\ncleanup_deployed_stale_files: deleted {$deleted} file(s); failures {$failed}; audit " . ($auditPath) . "\n");

exit($failed > 0 ? 1 : 0);
