<?php
/**
 * Convert local Ubuntu advisory sources (intermediate JSON, import-shaped JSON, or OVAL XML)
 * into the JSON format consumed by scripts/import_distro_advisories.php.
 *
 * No network I/O unless --fetch is passed. No database writes unless --import is passed.
 *
 * Usage:
 *   php scripts/convert_ubuntu_advisories.php --input=PATH --output=PATH [--release=jammy] [--limit=5000] [--format=auto|json|intermediate|oval]
 *   php scripts/convert_ubuntu_advisories.php --input=PATH --output=PATH --dry-run
 *   php scripts/convert_ubuntu_advisories.php --fetch --release=noble --output=/tmp/ubuntu_noble.json [--limit=2000]
 *   php scripts/convert_ubuntu_advisories.php ... --import
 *
 * Options:
 *   --input=PATH       Local file (.json or .xml / .xml.bz2 when bz2 extension + compress wrapper available)
 *   --output=PATH      Write normalized JSON (use "-" for stdout)
 *   --release=CODENAME Required for --fetch; optional filter for JSON pass-through / OVAL package comments
 *   --limit=N          Max advisories in output (default 5000)
 *   --format=auto      auto | json | intermediate | oval
 *   --max-size=N       Max input file size for JSON path (MB, default 64)
 *   --max-def-bytes=N  Max bytes per OVAL <definition> outer XML (default 262144)
 *   --max-download=N   Max download MB for --fetch (default 256)
 *   --dry-run          Print counts JSON to stderr; do not write --output
 *   --fetch            Download Canonical Ubuntu CVE OVAL (bz2) for --release (requires network)
 *   --import           After successful write, run import_distro_advisories.php on output (mutates DB)
 *   --import-max-advisories=N  When using --import, pass --max-advisories to import_distro_advisories.php (default: max(25000, --limit))
 *   --import-max-package-rows=N  When using --import, pass --max-package-rows to import_distro_advisories.php (default: 250000)
 *   --import-max-size-mb=N  When using --import, pass --max-size to import_distro_advisories.php (MB, default: 256; full jammy OVAL JSON can exceed 64MB)
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

require_once dirname(__DIR__) . '/api/lib_ubuntu_advisory_convert.php';
require_once dirname(__DIR__) . '/api/lib_vulnerability_correlation.php';

/**
 * @return array{input: ?string, output: ?string, release: string, limit: int, format: string, dry_run: bool, fetch: bool, import: bool, import_max_advisories: ?int, import_max_package_rows: ?int, import_max_size_mb: ?int, max_size_mb: int, max_def_bytes: int, max_download_mb: int}
 */
function st_convert_ubuntu_parse_args(array $argv): array
{
    $o = [
        'input' => null,
        'output' => null,
        'release' => '',
        'limit' => 5000,
        'format' => 'auto',
        'dry_run' => false,
        'fetch' => false,
        'import' => false,
        'import_max_advisories' => null,
        'import_max_package_rows' => null,
        'import_max_size_mb' => null,
        'max_size_mb' => 64,
        'max_def_bytes' => 262_144,
        'max_download_mb' => 256,
    ];
    foreach (array_slice($argv, 1) as $a) {
        if ($a === '--help' || $a === '-h') {
            fwrite(STDOUT, "Usage: php scripts/convert_ubuntu_advisories.php --input=FILE --output=FILE [options]\n"
                . "  --fetch --release=codename  (network)  --import  [--import-max-advisories=N] [--import-max-package-rows=N] [--import-max-size-mb=N]\n");
            exit(0);
        }
        if ($a === '--dry-run') {
            $o['dry_run'] = true;
        } elseif ($a === '--fetch') {
            $o['fetch'] = true;
        } elseif ($a === '--import') {
            $o['import'] = true;
        } elseif (str_starts_with($a, '--input=')) {
            $o['input'] = substr($a, 8);
        } elseif (str_starts_with($a, '--output=')) {
            $o['output'] = substr($a, 9);
        } elseif (str_starts_with($a, '--release=')) {
            $o['release'] = strtolower(trim(substr($a, 10)));
        } elseif (str_starts_with($a, '--limit=')) {
            $o['limit'] = max(1, min(100_000, (int) substr($a, 8)));
        } elseif (str_starts_with($a, '--format=')) {
            $o['format'] = strtolower(trim(substr($a, 9)));
        } elseif (str_starts_with($a, '--max-size=')) {
            $o['max_size_mb'] = max(1, min(2048, (int) substr($a, 11)));
        } elseif (str_starts_with($a, '--max-def-bytes=')) {
            $o['max_def_bytes'] = max(4096, min(2_097_152, (int) substr($a, 18)));
        } elseif (str_starts_with($a, '--max-download=')) {
            $o['max_download_mb'] = max(1, min(2048, (int) substr($a, 15)));
        } elseif (str_starts_with($a, '--import-max-advisories=')) {
            $o['import_max_advisories'] = max(1000, min(100_000, (int) substr($a, strlen('--import-max-advisories='))));
        } elseif (str_starts_with($a, '--import-max-package-rows=')) {
            $o['import_max_package_rows'] = max(5_000, min(500_000, (int) substr($a, strlen('--import-max-package-rows='))));
        } elseif (str_starts_with($a, '--import-max-size-mb=')) {
            $o['import_max_size_mb'] = max(64, min(2048, (int) substr($a, strlen('--import-max-size-mb='))));
        } else {
            fwrite(STDERR, "Unknown option: {$a}\n");
            exit(1);
        }
    }

    return $o;
}

/**
 * @param array<string, int> $stats
 */
function st_convert_ubuntu_emit_stats(array $stats, bool $json): void
{
    if ($json) {
        fwrite(STDERR, json_encode($stats, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
    } else {
        fwrite(STDERR, '[convert_ubuntu] advisories_out=' . ($stats['advisories_out'] ?? 0)
            . ' packages_out=' . ($stats['packages_out'] ?? 0)
            . ' definitions_seen=' . ($stats['definitions_seen'] ?? 0)
            . ' definitions_skipped=' . ($stats['definitions_skipped'] ?? 0) . "\n");
    }
}

function st_convert_ubuntu_fetch_oval_bz2(string $release, int $maxDownloadBytes): string
{
    $url = 'https://security-metadata.canonical.com/oval/com.ubuntu.' . rawurlencode($release) . '.cve.oval.xml.bz2';
    $tmp = sys_get_temp_dir() . '/surveytrace_ubuntu_oval_' . $release . '_' . bin2hex(random_bytes(6)) . '.xml.bz2';
    $fh = @fopen($url, 'rb');
    if ($fh === false) {
        throw new RuntimeException('fetch_open_failed');
    }
    $out = @fopen($tmp, 'wb');
    if ($out === false) {
        fclose($fh);
        throw new RuntimeException('fetch_tmp_open_failed');
    }
    $got = 0;
    while (! feof($fh)) {
        $chunk = fread($fh, 1_048_576);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $got += strlen($chunk);
        if ($got > $maxDownloadBytes) {
            fclose($fh);
            fclose($out);
            @unlink($tmp);
            throw new RuntimeException('fetch_size_cap_exceeded');
        }
        fwrite($out, $chunk);
    }
    fclose($fh);
    fclose($out);

    return $tmp;
}

/**
 * @param array<string, int> $stats
 * @return array{distro_source: string, advisories: list<array<string, mixed>>}
 */
function st_convert_ubuntu_from_oval(string $path, string $releaseFilter, int $limit, int $maxDefBytes, array &$stats): array
{
    $stats['definitions_seen'] = 0;
    $stats['definitions_skipped'] = 0;
    $stats['definitions_oversized'] = 0;
    $stats['definitions_no_cve'] = 0;
    $stats['definitions_no_packages'] = 0;

    $uri = $path;
    $lower = strtolower($path);
    if (str_ends_with($lower, '.bz2') || str_ends_with($lower, '.bzip2')) {
        if (! extension_loaded('bz2')) {
            throw new RuntimeException(
                'oval_bz2_requires_php_bz2: Canonical OVAL is bzip2-compressed; PHP needs the bz2 extension for compress.bzip2:// (e.g. apt install php-bz2).'
            );
        }
        $rp = realpath($path);
        if ($rp === false) {
            throw new RuntimeException('oval_path_unreadable');
        }
        $uri = 'compress.bzip2://' . $rp;
    }

    $r = new XMLReader();
    if (@$r->open($uri) !== true) {
        $err = libxml_get_last_error();
        $tail = is_object($err) && isset($err->message) ? ' libxml: ' . trim((string) $err->message) : '';
        throw new RuntimeException('oval_xml_open_failed' . $tail);
    }
    if (function_exists('libxml_disable_entity_loader')) {
        @libxml_disable_entity_loader(true);
    }

    $advisories = [];
    while ($r->read()) {
        if ($r->nodeType !== XMLReader::ELEMENT || $r->localName !== 'definition') {
            continue;
        }
        if ($r->getAttribute('class') !== 'vulnerability') {
            continue;
        }
        ++$stats['definitions_seen'];
        $outer = $r->readOuterXML();
        if (! is_string($outer) || $outer === '') {
            ++$stats['definitions_skipped'];
            continue;
        }
        if (strlen($outer) > $maxDefBytes) {
            ++$stats['definitions_oversized'];
            ++$stats['definitions_skipped'];
            continue;
        }
        $adv = st_convert_ubuntu_parse_oval_definition_xml($outer, $releaseFilter);
        if ($adv === null) {
            ++$stats['definitions_no_cve'];
            ++$stats['definitions_skipped'];
            continue;
        }
        if (($adv['packages'] ?? []) === []) {
            ++$stats['definitions_no_packages'];
            ++$stats['definitions_skipped'];
            continue;
        }
        $advisories[] = $adv;
        if (count($advisories) >= $limit) {
            break;
        }
    }
    $r->close();

    return ['distro_source' => 'ubuntu', 'advisories' => $advisories];
}

/**
 * @return array<string, mixed>|null
 */
function st_convert_ubuntu_parse_oval_definition_xml(string $xml, string $releaseCodename): ?array
{
    $cve = null;
    if (preg_match('/<reference[^>]*\bsource="CVE"[^>]*\bref_id="(CVE-\d{4}-\d{4,12})"/i', $xml, $m)) {
        $cve = $m[1];
    } elseif (preg_match('/<reference[^>]*\bref_id="(CVE-\d{4}-\d{4,12})"[^>]*\bsource="CVE"/i', $xml, $m)) {
        $cve = $m[1];
    }
    if ($cve === null || ! st_vuln_validate_advisory_key($cve)) {
        return null;
    }

    $sev = 'unknown';
    if (preg_match('/<severity>\s*([^<]+?)\s*<\/severity>/i', $xml, $ms)) {
        $sev = strtolower(trim($ms[1]));
    } elseif (preg_match('/\s-\s(low|medium|high|critical)\s*<\/title>/i', $xml, $mt)) {
        $sev = strtolower($mt[1]);
    }
    $allowed = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
    if (! in_array($sev, $allowed, true)) {
        $sev = 'unknown';
    }

    $cvss = null;
    if (preg_match('/\bcvss_score="([0-9.]+)"/', $xml, $mc)) {
        $cvss = (float) $mc[1];
        if ($cvss < 0.0 || $cvss > 10.0) {
            $cvss = null;
        }
    }

    $pub = null;
    if (preg_match('/<public_date>\s*([^<]+?)\s*<\/public_date>/i', $xml, $mp)) {
        $pub = substr(preg_replace('/[^0-9T:\\-\\.Z+ ]/', '', trim($mp[1])), 0, 40);
        if ($pub === '') {
            $pub = null;
        }
    }

    $desc = null;
    if (preg_match('/<description>\s*([\s\S]*?)<\/description>/i', $xml, $md)) {
        $desc = st_ubuntu_strip_html($md[1]);
        if ($desc === '') {
            $desc = null;
        }
    }

    $refs = [];
    if (preg_match_all('/<reference[^>]*\bref_url="([^"]+)"/', $xml, $mr, PREG_SET_ORDER)) {
        foreach ($mr as $row) {
            if (count($refs) >= 24) {
                break;
            }
            $u = trim($row[1]);
            if (str_starts_with($u, 'http') && strlen($u) <= 2000) {
                $refs[] = ['url' => $u];
            }
        }
    }
    if (preg_match_all('/<(?:ref|bug)>(https?:\/\/[^<]+)<\/(?:ref|bug)>/i', $xml, $mr2, PREG_SET_ORDER)) {
        foreach ($mr2 as $row) {
            if (count($refs) >= 24) {
                break;
            }
            $u = trim($row[1]);
            if (strlen($u) <= 2000) {
                $refs[] = ['url' => $u];
            }
        }
    }

    $pattern = '/<criterion[^>]*comment="(?<bin>[a-z0-9][a-z0-9+._-]*) package in (?<rel>[a-z]+) was vulnerable but has been fixed \(note: \'(?<fv>[^\']+)\'\)\."/i';
    $pkgs = [];
    if (preg_match_all($pattern, $xml, $mm, PREG_SET_ORDER)) {
        foreach ($mm as $mrow) {
            if (count($pkgs) >= 200) {
                break;
            }
            $rel = strtolower($mrow['rel']);
            if (strcasecmp($rel, $releaseCodename) !== 0) {
                continue;
            }
            $np = st_ubuntu_normalize_package_row([
                'binary_package' => $mrow['bin'],
                'fixed_version' => $mrow['fv'],
                'status' => 'released',
            ]);
            if ($np === null) {
                continue;
            }
            $k = $np['binary_package'] . "\0" . $np['fixed_version'] . "\0" . $rel;
            $pkgs[$k] = array_merge($np, []); // dedupe
        }
    }
    $pkgs = array_values($pkgs);
    if ($pkgs === []) {
        return null;
    }

    if (! st_ubuntu_validate_release($releaseCodename)) {
        return null;
    }

    $adv = [
        'cve_id' => $cve,
        'description' => $desc,
        'severity' => $sev,
        'cvss_score' => $cvss,
        'published_at' => $pub,
        'modified_at' => $pub,
        'distro_release' => $releaseCodename,
        'withdrawn' => false,
        'packages' => $pkgs,
    ];
    if ($refs !== []) {
        $adv['references'] = $refs;
    }

    return $adv;
}

$opt = st_convert_ubuntu_parse_args($argv);

if ($opt['fetch']) {
    if ($opt['release'] === '' || ! st_ubuntu_validate_release($opt['release'])) {
        fwrite(STDERR, "--fetch requires --release=noble|jammy|focal|...\n");
        exit(1);
    }
    $maxDl = $opt['max_download_mb'] * 1024 * 1024;
    try {
        $opt['input'] = st_convert_ubuntu_fetch_oval_bz2($opt['release'], $maxDl);
    } catch (Throwable $e) {
        fwrite(STDERR, 'Fetch failed: ' . $e->getMessage() . "\n");
        exit(1);
    }
    $opt['format'] = 'oval';
}

if ($opt['input'] === null || $opt['input'] === '' || ! is_readable($opt['input'])) {
    fwrite(STDERR, "Missing or unreadable --input=PATH\n");
    exit(1);
}
if ($opt['output'] === null || $opt['output'] === '') {
    fwrite(STDERR, "Missing --output=PATH (use '-' for stdout)\n");
    exit(1);
}

$fmt = $opt['format'];
if (! in_array($fmt, ['auto', 'json', 'intermediate', 'oval'], true)) {
    fwrite(STDERR, "Invalid --format\n");
    exit(1);
}

$stats = [
    'advisories_out' => 0,
    'packages_out' => 0,
    'definitions_seen' => 0,
    'definitions_skipped' => 0,
    'definitions_oversized' => 0,
    'definitions_no_cve' => 0,
    'definitions_no_packages' => 0,
];

$maxBytes = $opt['max_size_mb'] * 1024 * 1024;
$lowerIn = strtolower($opt['input']);
$isXml = str_ends_with($lowerIn, '.xml') || str_ends_with($lowerIn, '.xml.bz2') || str_ends_with($lowerIn, '.bz2');
$isBz2 = str_ends_with($lowerIn, '.bz2') || str_ends_with($lowerIn, '.bzip2');

$autoJson = null;
if ($fmt === 'auto') {
    if ($isXml || $isBz2) {
        $fmt = 'oval';
    } else {
        $sz = @filesize($opt['input']);
        if ($sz !== false && $sz > $maxBytes) {
            fwrite(STDERR, "Input file exceeds --max-size={$opt['max_size_mb']}MB; raise cap or decompress.\n");
            exit(1);
        }
        $raw = @file_get_contents($opt['input']);
        if ($raw === false) {
            fwrite(STDERR, "Could not read input.\n");
            exit(1);
        }
        if (strlen($raw) > $maxBytes) {
            fwrite(STDERR, "Input file exceeds max size.\n");
            exit(1);
        }
        $j = json_decode($raw, true);
        if (! is_array($j)) {
            fwrite(STDERR, "Invalid JSON in input.\n");
            exit(1);
        }
        $autoJson = $j;
        if (! empty($j['surveytrace_ubuntu_intermediate_v1']) || (($j['format'] ?? '') === 'surveytrace_ubuntu_intermediate_v1')) {
            $fmt = 'intermediate';
        } else {
            $fmt = 'json';
        }
    }
}

$outDoc = null;

if ($fmt === 'oval') {
    if (! extension_loaded('xmlreader') || ! class_exists('XMLReader', false)) {
        fwrite(STDERR, "OVAL input requires the PHP xmlreader extension (on Debian/Ubuntu: apt install php-xml).\n");
        exit(1);
    }
    if ($opt['release'] === '' || ! st_ubuntu_validate_release($opt['release'])) {
        fwrite(STDERR, "OVAL conversion requires --release=noble|jammy|... (codename matching criterion comments)\n");
        exit(1);
    }
    $outDoc = st_convert_ubuntu_from_oval($opt['input'], $opt['release'], $opt['limit'], $opt['max_def_bytes'], $stats);
} elseif ($fmt === 'intermediate') {
    $j = is_array($autoJson) ? $autoJson : null;
    if (! is_array($j)) {
        $sz = @filesize($opt['input']);
        if ($sz !== false && $sz > $maxBytes) {
            fwrite(STDERR, "Input file exceeds --max-size={$opt['max_size_mb']}MB.\n");
            exit(1);
        }
        $raw = @file_get_contents($opt['input']);
        if ($raw === false || strlen($raw) > $maxBytes) {
            fwrite(STDERR, "Could not read input.\n");
            exit(1);
        }
        $j = json_decode($raw, true);
        if (! is_array($j)) {
            fwrite(STDERR, "Invalid JSON.\n");
            exit(1);
        }
    }
    $outDoc = st_ubuntu_intermediate_v1_to_import($j);
} else {
    $j = is_array($autoJson) ? $autoJson : null;
    if (! is_array($j)) {
        $sz = @filesize($opt['input']);
        if ($sz !== false && $sz > $maxBytes) {
            fwrite(STDERR, "Input file exceeds --max-size={$opt['max_size_mb']}MB.\n");
            exit(1);
        }
        $raw = @file_get_contents($opt['input']);
        if ($raw === false || strlen($raw) > $maxBytes) {
            fwrite(STDERR, "Could not read input.\n");
            exit(1);
        }
        $j = json_decode($raw, true);
        if (! is_array($j)) {
            fwrite(STDERR, "Invalid JSON.\n");
            exit(1);
        }
    }
    $relF = $opt['release'] !== '' ? $opt['release'] : null;
    $outDoc = st_ubuntu_normalize_pass_through($j, $relF, $opt['limit']);
}

$outDoc['advisories'] = array_slice($outDoc['advisories'] ?? [], 0, $opt['limit']);
$stats['advisories_out'] = count($outDoc['advisories']);
$stats['packages_out'] = 0;
foreach ($outDoc['advisories'] as $a) {
    $stats['packages_out'] += count($a['packages'] ?? []);
}

$flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT;
if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
    $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
}
$jsonOut = json_encode($outDoc, $flags);
if ($jsonOut === false) {
    fwrite(STDERR, "JSON encode failed.\n");
    exit(1);
}

st_convert_ubuntu_emit_stats($stats, false);

if (! $opt['dry_run']) {
    if ($opt['output'] === '-') {
        fwrite(STDOUT, $jsonOut . "\n");
    } else {
        $written = @file_put_contents($opt['output'], $jsonOut . "\n", LOCK_EX);
        if ($written === false) {
            $written = @file_put_contents($opt['output'], $jsonOut . "\n");
        }
        if ($written === false) {
            fwrite(STDERR, "Failed to write output file.\n");
            exit(1);
        }
    }
}

if ($opt['import'] && ! $opt['dry_run']) {
    if ($opt['output'] === '-') {
        fwrite(STDERR, "--import requires a real output file path.\n");
        exit(1);
    }
    $root = realpath(dirname(__DIR__));
    $php = PHP_BINARY;
    $imp = $root . '/scripts/import_distro_advisories.php';
    $impMax = $opt['import_max_advisories'] ?? null;
    if ($impMax === null) {
        $impMax = max(25_000, (int) $opt['limit']);
    }
    $impMax = max(1000, min(100_000, (int) $impMax));
    $pkgMax = $opt['import_max_package_rows'] ?? null;
    if ($pkgMax === null) {
        $pkgMax = 250_000;
    }
    $pkgMax = max(5_000, min(500_000, (int) $pkgMax));
    $sizeMb = $opt['import_max_size_mb'] ?? null;
    if ($sizeMb === null) {
        $sizeMb = 256;
    }
    $sizeMb = max(64, min(2048, (int) $sizeMb));
    $cmd = escapeshellarg($php) . ' ' . escapeshellarg($imp) . ' ' . escapeshellarg($opt['output'])
        . ' --max-advisories=' . (string) $impMax
        . ' --max-package-rows=' . (string) $pkgMax
        . ' --max-size=' . (string) $sizeMb;
    passthru($cmd, $code);
    if ($code !== 0) {
        exit($code);
    }
}

if ($opt['fetch'] && isset($opt['input']) && is_string($opt['input']) && str_contains($opt['input'], 'surveytrace_ubuntu_oval_')) {
    @unlink($opt['input']);
}

exit(0);
