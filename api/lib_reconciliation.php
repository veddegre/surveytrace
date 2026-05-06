<?php
/**
 * SurveyTrace — reconciliation primitives (Milestone 1: trusted data model foundations).
 *
 * Read-path lazy reconciliation for OS/platform from existing asset + cached Zabbix inventory.
 * Write-path hooks for scanners/connectors are intentionally deferred.
 */

declare(strict_types=1);

/**
 * @return array<string, mixed>
 */
function st_recon_empty_bundle(): array
{
    return [
        'assertions'              => [],
        'evidence_summary'        => ['observation_count' => 0, 'sources' => []],
        'os_platform_assertion'   => null,
        'os_platform_confidence'  => null,
        'os_platform_sources'     => [],
        'os_platform_explanation' => null,
    ];
}

function st_recon_tables_ready(PDO $pdo): bool
{
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    try {
        $t = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='recon_sources' LIMIT 1")->fetchColumn();
        $cache = ($t === 'recon_sources');
    } catch (Throwable $e) {
        $cache = false;
    }

    return $cache;
}

function st_recon_seed_sources(PDO $pdo): void
{
    if (! st_recon_tables_ready($pdo)) {
        return;
    }
    $rows = [
        ['surveytrace_scan', 'default', 'SurveyTrace scan', 'high'],
        ['zabbix_inventory', 'default', 'Zabbix inventory', 'high'],
        ['surveytrace_enrichment', 'default', 'SurveyTrace enrichment', 'medium'],
    ];
    $ins = $pdo->prepare(
        "INSERT OR IGNORE INTO recon_sources (source_type, source_instance_key, display_name, trust_level, enabled, updated_at)
         VALUES (?, 'default', ?, ?, 1, datetime('now'))"
    );
    foreach ($rows as [$stype, $disp, $trust]) {
        $ins->execute([$stype, $disp, $trust]);
    }
}

function st_recon_source_id(PDO $pdo, string $sourceType): ?int
{
    $st = $pdo->prepare(
        'SELECT id FROM recon_sources WHERE source_type = ? AND source_instance_key = ? LIMIT 1'
    );
    $st->execute([$sourceType, 'default']);
    $id = $st->fetchColumn();

    return ($id !== false) ? (int) $id : null;
}

function st_recon_confidence_rank(string $level): int
{
    $level = strtolower(trim($level));

    return match ($level) {
        'authoritative' => 4,
        'high'          => 3,
        'medium'        => 2,
        'low'           => 1,
        default         => 2,
    };
}

function st_recon_confidence_max(string $a, string $b): string
{
    return st_recon_confidence_rank($a) >= st_recon_confidence_rank($b) ? $a : $b;
}

function st_recon_confidence_min(string $a, string $b): string
{
    return st_recon_confidence_rank($a) <= st_recon_confidence_rank($b) ? $a : $b;
}

/**
 * Normalize free-text / vendor OS hints into a bucket slug + short human label.
 *
 * @return array{slug:string,label:string}|null
 */
function st_recon_normalize_os_text(string $raw): ?array
{
    $s = strtolower(trim($raw));
    if ($s === '') {
        return null;
    }

    // Windows
    if (preg_match('/windows\s*server\s*2025/i', $raw)) {
        return ['slug' => 'windows_server_2025', 'label' => 'Windows Server 2025'];
    }
    if (preg_match('/windows\s*server\s*2022/i', $raw)) {
        return ['slug' => 'windows_server_2022', 'label' => 'Windows Server 2022'];
    }
    if (preg_match('/windows\s*server\s*2019/i', $raw)) {
        return ['slug' => 'windows_server_2019', 'label' => 'Windows Server 2019'];
    }
    if (preg_match('/windows\s*server\s*2016/i', $raw)) {
        return ['slug' => 'windows_server_2016', 'label' => 'Windows Server 2016'];
    }
    if (preg_match('/windows\s*11/i', $raw)) {
        return ['slug' => 'windows_11', 'label' => 'Windows 11'];
    }
    if (preg_match('/windows\s*10/i', $raw)) {
        return ['slug' => 'windows_10', 'label' => 'Windows 10'];
    }
    if (str_contains($s, 'windows')) {
        return ['slug' => 'windows_unknown', 'label' => 'Windows'];
    }

    // Ubuntu / Debian
    if (preg_match('/ubuntu[^\d]*(\d+)\.(\d+)/i', $raw, $m)) {
        $maj = (int) $m[1];
        $min = (int) $m[2];

        return ['slug' => 'ubuntu_' . $maj . '_' . $min . '_x', 'label' => 'Ubuntu ' . $maj . '.' . $min . '.x'];
    }
    if (preg_match('/ubuntu[^\d]*(\d+)/i', $raw, $m)) {
        $maj = (int) $m[1];

        return ['slug' => 'ubuntu_' . $maj . '_x', 'label' => 'Ubuntu ' . $maj . '.x'];
    }
    if (str_contains($s, 'ubuntu')) {
        return ['slug' => 'ubuntu_unknown', 'label' => 'Ubuntu'];
    }
    if (preg_match('/debian[^\d]*(\d+)/i', $raw, $m)) {
        return ['slug' => 'debian_' . (int) $m[1] . '_x', 'label' => 'Debian ' . (int) $m[1] . '.x'];
    }
    if (str_contains($s, 'debian')) {
        return ['slug' => 'debian_unknown', 'label' => 'Debian'];
    }

    // RHEL family
    if (preg_match('/red\s*hat[^\d]*(\d+)/i', $raw, $m) || preg_match('/\brhel[^\d]*(\d+)/i', $raw, $m)) {
        return ['slug' => 'rhel_' . (int) $m[1] . '_x', 'label' => 'RHEL ' . (int) $m[1] . '.x'];
    }
    if (preg_match('/centos[^\d]*(\d+)/i', $raw, $m)) {
        return ['slug' => 'centos_' . (int) $m[1] . '_x', 'label' => 'CentOS ' . (int) $m[1] . '.x'];
    }
    if (str_contains($s, 'rocky') || str_contains($s, 'alma')) {
        return ['slug' => 'enterprise_linux_unknown', 'label' => 'Enterprise Linux'];
    }

    // Generic Linux
    if (str_contains($s, 'linux')) {
        return ['slug' => 'linux_unknown', 'label' => 'Linux'];
    }

    // VMware ESXi
    if (str_contains($s, 'esxi') || str_contains($s, 'vmware')) {
        return ['slug' => 'vmware_esxi_unknown', 'label' => 'VMware ESXi'];
    }

    return ['slug' => 'os_unknown', 'label' => trim($raw)];
}

/**
 * Parse CPE 2.3 os binding when present.
 *
 * @return array{slug:string,label:string}|null
 */
function st_recon_normalize_os_cpe(?string $cpe): ?array
{
    if ($cpe === null || trim($cpe) === '') {
        return null;
    }
    $c = trim($cpe);
    if (! preg_match('/^cpe:2\\.3:o:([^:]+):([^:]+):([^:]*)/i', $c, $m)) {
        return null;
    }
    $vendor = strtolower((string) $m[1]);
    $product = strtolower((string) $m[2]);
    $ver = strtolower((string) $m[3]);
    if ($ver === '*' || $ver === '-') {
        $ver = '';
    }

    // Canonical Ubuntu CPE often uses ubuntu_linux + numeric version
    if (($vendor === 'canonical' || str_contains($product, 'ubuntu')) && $ver !== '') {
        if (preg_match('/^(\d+)\\.(\d+)/', $ver, $vm)) {
            $maj = (int) $vm[1];
            $min = (int) $vm[2];

            return ['slug' => 'ubuntu_' . $maj . '_' . $min . '_x', 'label' => 'Ubuntu ' . $maj . '.' . $min . '.x'];
        }
    }

    if ($vendor === 'microsoft') {
        $prodLabel = str_replace('_', ' ', $product);
        $slug = 'windows_unknown';
        if (str_contains($product, 'windows_server')) {
            $slug = preg_replace('/[^a-z0-9]+/', '_', 'windows_' . $product) ?: 'windows_unknown';
        } elseif (str_contains($product, 'windows')) {
            $slug = preg_replace('/[^a-z0-9]+/', '_', $product) ?: 'windows_unknown';
        }
        if ($ver !== '') {
            return ['slug' => $slug . '_' . preg_replace('/[^0-9a-z\\.]+/i', '_', $ver), 'label' => ucwords($prodLabel) . ' ' . $ver];
        }

        return ['slug' => $slug, 'label' => ucwords($prodLabel)];
    }

    // Fallback: vendor_product_version slug
    $slug = preg_replace('/[^a-z0-9]+/', '_', $vendor . '_' . $product . ($ver !== '_' ? '_' . $ver : ''));
    $slug = trim((string) $slug, '_');
    if ($slug === '') {
        return null;
    }
    $label = ucwords(str_replace('_', ' ', $vendor . ' ' . str_replace('_', ' ', $product)));
    if ($ver !== '') {
        $label .= ' ' . $ver;
    }

    return ['slug' => $slug, 'label' => $label];
}

/**
 * Zabbix-linked inventory OS hints (read-only).
 *
 * @return array{hostid:string,parts:array<string,string>,synced_at:?string,raw_json:string}|null
 */
function st_recon_zabbix_os_context(PDO $pdo, int $assetId): ?array
{
    if ($assetId <= 0 || ! function_exists('st_zabbix_table_ready') || ! st_zabbix_table_ready($pdo)) {
        return null;
    }
    try {
        $st = $pdo->prepare(
            'SELECT h.hostid, h.inventory_json, h.synced_at
             FROM zabbix_asset_links l
             JOIN zabbix_hosts h ON h.hostid = l.zabbix_hostid
             WHERE l.asset_id = ?
             LIMIT 1'
        );
        $st->execute([$assetId]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if (! is_array($row)) {
            return null;
        }
        $hid = (string) ($row['hostid'] ?? '');
        if ($hid === '') {
            return null;
        }
        $inv = json_decode((string) ($row['inventory_json'] ?? '{}'), true);
        if (! is_array($inv)) {
            $inv = [];
        }
        $keys = ['os_full', 'os_short', 'type', 'name', 'hardware', 'hardware_full'];
        $parts = [];
        foreach ($keys as $k) {
            $v = isset($inv[$k]) ? trim((string) $inv[$k]) : '';
            if ($v !== '') {
                $parts[$k] = $v;
            }
        }
        if ($parts === []) {
            return null;
        }

        return [
            'hostid'    => $hid,
            'parts'     => $parts,
            'synced_at' => isset($row['synced_at']) ? (string) $row['synced_at'] : null,
            'raw_json'  => json_encode($parts, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}',
        ];
    } catch (Throwable $e) {
        return null;
    }
}

/**
 * Whether scan/enrichment activity should trigger a refresh vs cached assertion.
 */
function st_recon_should_refresh_os_assertion(?array $existingRow, ?string $assetLastSeen): bool
{
    if ($existingRow === null || $existingRow === []) {
        return true;
    }
    $rec = (string) ($existingRow['reconciled_at'] ?? '');
    $ls = $assetLastSeen !== null ? trim($assetLastSeen) : '';
    if ($ls !== '' && $rec !== '' && strcmp($ls, $rec) > 0) {
        return true;
    }
    $ts = strtotime($rec !== '' ? $rec : 'now');
    if ($ts !== false && (time() - $ts) > 900) {
        return true;
    }

    return false;
}

/**
 * @param array<int, array<string, mixed>> $obsDefs
 * @return array<int, array<string, mixed>>
 */
function st_recon_resolve_os_platform(array $obsDefs): array
{
    $normalizedRows = [];
    foreach ($obsDefs as $def) {
        $slug = (string) ($def['normalized_slug'] ?? '');
        if ($slug === '' || $slug === 'os_unknown') {
            continue;
        }
        $normalizedRows[] = $def;
    }
    if ($normalizedRows === []) {
        return ['skip' => true, 'reason' => 'no_normalized_signals'];
    }

    // Prefer structured CPE-derived slug when present
    $cpeRow = null;
    foreach ($normalizedRows as $r) {
        if (($r['observation_type'] ?? '') === 'os_fingerprint_cpe') {
            $cpeRow = $r;
            break;
        }
    }

    $scanRow = null;
    foreach ($normalizedRows as $r) {
        if (($r['observation_type'] ?? '') === 'os_fingerprint_scan') {
            $scanRow = $r;
            break;
        }
    }

    $zbxRow = null;
    foreach ($normalizedRows as $r) {
        if (($r['observation_type'] ?? '') === 'os_inventory_zabbix') {
            $zbxRow = $r;
            break;
        }
    }

    $scanSlug = null;
    $scanLabel = null;
    if ($cpeRow) {
        $scanSlug = (string) $cpeRow['normalized_slug'];
        $scanLabel = (string) $cpeRow['normalized_label'];
    } elseif ($scanRow) {
        $scanSlug = (string) $scanRow['normalized_slug'];
        $scanLabel = (string) $scanRow['normalized_label'];
    }

    $zslug = $zbxRow ? (string) $zbxRow['normalized_slug'] : null;
    $zlabel = $zbxRow ? (string) $zbxRow['normalized_label'] : null;

    $explanationParts = [];

    // Independent corroboration: SurveyTrace scan vs Zabbix
    if ($scanSlug !== null && $zslug !== null) {
        if ($scanSlug === $zslug) {
            $explanationParts[] = 'SurveyTrace scan and Zabbix inventory agree on ' . $scanLabel . '.';

            return [
                'skip'              => false,
                'slug'              => $scanSlug,
                'label'             => $scanLabel,
                'confidence'        => 'high',
                'explanation'       => implode(' ', $explanationParts),
                'primary_type'      => $cpeRow ? 'os_fingerprint_cpe' : 'os_fingerprint_scan',
                'tie_order'         => array_values(array_filter([$cpeRow, $scanRow, $zbxRow])),
            ];
        }

        // Generic Linux in Zabbix + specific distro from scan
        if (($zslug === 'linux_unknown' || str_contains((string) $zslug, 'linux'))
            && str_contains((string) $scanSlug, 'ubuntu')) {
            $explanationParts[] = 'Zabbix reports generic Linux; SurveyTrace fingerprint narrows to ' . $scanLabel . '.';

            return [
                'skip'              => false,
                'slug'              => $scanSlug,
                'label'             => $scanLabel,
                'confidence'        => 'high',
                'explanation'       => implode(' ', $explanationParts),
                'primary_type'      => $cpeRow ? 'os_fingerprint_cpe' : 'os_fingerprint_scan',
                'tie_order'         => array_values(array_filter([$cpeRow, $scanRow, $zbxRow])),
            ];
        }

        $explanationParts[] = 'SurveyTrace suggests ' . ($scanLabel ?? $scanSlug) . '; Zabbix suggests ' . ($zlabel ?? $zslug) . '. Using SurveyTrace scan signal with reduced confidence.';

        return [
            'skip'              => false,
            'slug'              => $scanSlug,
            'label'             => $scanLabel ?? $scanSlug,
            'confidence'        => 'low',
            'explanation'       => implode(' ', $explanationParts),
            'primary_type'      => $cpeRow ? 'os_fingerprint_cpe' : 'os_fingerprint_scan',
            'tie_order'         => array_values(array_filter([$cpeRow, $scanRow, $zbxRow])),
        ];
    }

    if ($scanSlug !== null) {
        $src = $cpeRow ? 'parsed host CPE' : 'scan fingerprint (os_guess)';
        $explanationParts[] = 'Based on ' . $src . '.' . ($zbxRow ? ' Zabbix did not yield a stronger inventory OS string.' : '');

        return [
            'skip'              => false,
            'slug'              => $scanSlug,
            'label'             => $scanLabel ?? $scanSlug,
            'confidence'        => $cpeRow ? 'high' : 'medium',
            'explanation'       => trim(implode(' ', $explanationParts)),
            'primary_type'      => $cpeRow ? 'os_fingerprint_cpe' : 'os_fingerprint_scan',
            'tie_order'         => array_values(array_filter([$cpeRow, $scanRow, $zbxRow])),
        ];
    }

    if ($zslug !== null) {
        $explanationParts[] = 'Based on Zabbix host inventory only (SurveyTrace has no OS fingerprint yet).';

        return [
            'skip'              => false,
            'slug'              => $zslug,
            'label'             => $zlabel ?? $zslug,
            'confidence'        => 'medium',
            'explanation'       => implode(' ', $explanationParts),
            'primary_type'      => 'os_inventory_zabbix',
            'tie_order'         => [$zbxRow],
        ];
    }

    return ['skip' => true, 'reason' => 'no_resolution'];
}

/**
 * Build API-facing bundle from DB state.
 *
 * @return array<string, mixed>
 */
function st_recon_build_os_bundle_from_db(PDO $pdo, int $assetId): array
{
    $empty = st_recon_empty_bundle();
    if (! st_recon_tables_ready($pdo) || $assetId <= 0) {
        return $empty;
    }

    $ast = $pdo->prepare(
        "SELECT id, assertion_type, asserted_value, confidence_level, explanation, reconciled_at, version
         FROM asset_assertions WHERE asset_id = ? AND assertion_type = 'os_platform' LIMIT 1"
    );
    $ast->execute([$assetId]);
    $assert = $ast->fetch(PDO::FETCH_ASSOC);
    if (! is_array($assert)) {
        return $empty;
    }

    $slug = (string) ($assert['asserted_value'] ?? '');
    $label = st_recon_os_display_label_for_slug($slug);

    $obsSt = $pdo->prepare(
        "SELECT o.id, o.observation_type, o.raw_value, o.normalized_value, o.source_object_ref, s.display_name, s.source_type
         FROM asset_observations o
         JOIN recon_sources s ON s.id = o.source_id
         WHERE o.asset_id = ? AND o.observation_type IN ('os_fingerprint_scan','os_fingerprint_cpe','os_inventory_zabbix','os_hint_enrichment')
         ORDER BY o.id ASC"
    );
    $obsSt->execute([$assetId]);
    $obsRows = $obsSt->fetchAll(PDO::FETCH_ASSOC) ?: [];

    $srcLabels = [];
    foreach ($obsRows as $or) {
        $dn = trim((string) ($or['display_name'] ?? ''));
        if ($dn !== '') {
            $srcLabels[$dn] = true;
        }
    }

    $empty['assertions'] = [[
        'type'           => 'os_platform',
        'value_slug'     => $slug,
        'value_label'    => $label,
        'confidence'     => (string) ($assert['confidence_level'] ?? 'medium'),
        'explanation'    => (string) ($assert['explanation'] ?? ''),
        'reconciled_at'  => $assert['reconciled_at'] ?? null,
        'version'        => (int) ($assert['version'] ?? 1),
    ]];
    $empty['evidence_summary'] = [
        'observation_count' => count($obsRows),
        'sources'           => array_keys($srcLabels),
    ];
    $empty['os_platform_assertion'] = $label;
    $empty['os_platform_confidence'] = (string) ($assert['confidence_level'] ?? 'medium');
    $empty['os_platform_sources'] = array_keys($srcLabels);
    $empty['os_platform_explanation'] = (string) ($assert['explanation'] ?? '');

    return $empty;
}

function st_recon_os_display_label_for_slug(string $slug): string
{
    $slug = trim($slug);
    if ($slug === '') {
        return '';
    }
    // Prefer readable spacing for common buckets
    $map = [
        'linux_unknown'            => 'Linux',
        'ubuntu_unknown'           => 'Ubuntu',
        'debian_unknown'           => 'Debian',
        'windows_unknown'          => 'Windows',
        'enterprise_linux_unknown' => 'Enterprise Linux',
        'vmware_esxi_unknown'      => 'VMware ESXi',
        'os_unknown'               => 'Unknown OS',
    ];
    if (isset($map[$slug])) {
        return $map[$slug];
    }

    return ucwords(str_replace('_', ' ', $slug));
}

/**
 * Lazy OS reconciliation for one asset (single-asset GET path).
 *
 * @param array<string,mixed> $assetRowDecoded decode_asset output or compatible
 *
 * @return array<string,mixed>
 */
function st_recon_lazy_reconcile_os_platform(PDO $pdo, int $assetId, array $assetRowDecoded): array
{
    if (! st_recon_tables_ready($pdo) || $assetId <= 0) {
        return st_recon_empty_bundle();
    }

    st_recon_seed_sources($pdo);
    $sidScan = st_recon_source_id($pdo, 'surveytrace_scan');
    $sidZbx = st_recon_source_id($pdo, 'zabbix_inventory');
    $sidEnr = st_recon_source_id($pdo, 'surveytrace_enrichment');
    if ($sidScan === null || $sidZbx === null || $sidEnr === null) {
        return st_recon_empty_bundle();
    }

    $existingStmt = $pdo->prepare(
        "SELECT id, reconciled_at, asserted_value, confidence_level, explanation, version
         FROM asset_assertions WHERE asset_id = ? AND assertion_type = 'os_platform' LIMIT 1"
    );
    $existingStmt->execute([$assetId]);
    $existing = $existingStmt->fetch(PDO::FETCH_ASSOC);

    $lastSeen = isset($assetRowDecoded['last_seen']) ? (string) $assetRowDecoded['last_seen'] : null;
    if (! st_recon_should_refresh_os_assertion(is_array($existing) ? $existing : null, $lastSeen)) {
        return st_recon_build_os_bundle_from_db($pdo, $assetId);
    }

    $runStarted = date('Y-m-d H:i:s');
    $summary = ['slice' => 'os_platform', 'observations' => 0, 'result' => 'pending'];

    /** @var array<int, array<string, mixed>> $obsDefs */
    $obsDefs = [];

    $osGuess = trim((string) ($assetRowDecoded['os_guess'] ?? ''));
    if ($osGuess !== '') {
        $norm = st_recon_normalize_os_text($osGuess);
        if ($norm !== null && ($norm['slug'] ?? '') !== '' && ($norm['slug'] ?? '') !== 'os_unknown') {
            $obsDefs[] = [
                'observation_type'   => 'os_fingerprint_scan',
                'raw_value'          => $osGuess,
                'normalized_slug'    => $norm['slug'],
                'normalized_label'   => $norm['label'],
                'source_id'          => $sidScan,
                'source_object_ref'  => '',
                'confidence_level'   => 'medium',
                'provenance_json'    => json_encode(['field' => 'os_guess'], JSON_UNESCAPED_SLASHES) ?: '{}',
            ];
        }
    }

    $cpe = trim((string) ($assetRowDecoded['cpe'] ?? ''));
    if ($cpe !== '') {
        $cn = st_recon_normalize_os_cpe($cpe);
        if ($cn !== null) {
            $obsDefs[] = [
                'observation_type'   => 'os_fingerprint_cpe',
                'raw_value'          => $cpe,
                'normalized_slug'    => $cn['slug'],
                'normalized_label'   => $cn['label'],
                'source_id'          => $sidScan,
                'source_object_ref'  => '',
                'confidence_level'   => 'high',
                'provenance_json'    => json_encode(['field' => 'cpe'], JSON_UNESCAPED_SLASHES) ?: '{}',
            ];
        }
    }

    $zctx = st_recon_zabbix_os_context($pdo, $assetId);
    if ($zctx !== null) {
        $combined = implode(' · ', $zctx['parts']);
        $zn = st_recon_normalize_os_text($combined);
        if ($zn !== null && ($zn['slug'] ?? '') !== '' && ($zn['slug'] ?? '') !== 'os_unknown') {
            $prov = ['zabbix_hostid' => $zctx['hostid'], 'inventory_keys' => array_keys($zctx['parts'])];
            if (($zctx['synced_at'] ?? '') !== '') {
                $prov['zabbix_inventory_synced_at'] = $zctx['synced_at'];
            }
            $obsDefs[] = [
                'observation_type'   => 'os_inventory_zabbix',
                'raw_value'          => $zctx['raw_json'],
                'normalized_slug'    => $zn['slug'],
                'normalized_label'   => $zn['label'],
                'source_id'          => $sidZbx,
                'source_object_ref'  => (string) $zctx['hostid'],
                'confidence_level'   => 'medium',
                'provenance_json'    => json_encode($prov, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}',
            ];
        }
    }

    $disc = $assetRowDecoded['discovery_sources'] ?? [];
    if (is_array($disc) && $disc !== []) {
        $flat = [];
        foreach ($disc as $d) {
            $flat[] = (string) $d;
        }
        $flat = array_values(array_filter(array_map('trim', $flat)));
        if ($flat !== []) {
            $obsDefs[] = [
                'observation_type'   => 'os_hint_enrichment',
                'raw_value'          => json_encode($flat, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '[]',
                'normalized_slug'    => '',
                'normalized_label'   => '',
                'source_id'          => $sidEnr,
                'source_object_ref'  => '',
                'confidence_level'   => 'low',
                'provenance_json'    => json_encode(['discovery_sources' => $flat], JSON_UNESCAPED_SLASHES) ?: '{}',
            ];
        }
    }

    $summary['observations'] = count($obsDefs);

    try {
        $pdo->beginTransaction();

        $oldAssertId = is_array($existing) ? (int) ($existing['id'] ?? 0) : 0;
        if ($oldAssertId > 0) {
            $pdo->prepare('DELETE FROM assertion_sources WHERE assertion_id = ?')->execute([$oldAssertId]);
        }

        $pdo->prepare(
            "DELETE FROM asset_observations WHERE asset_id = ?
             AND observation_type IN ('os_fingerprint_scan','os_fingerprint_cpe','os_inventory_zabbix','os_hint_enrichment')"
        )->execute([$assetId]);

        $insObs = $pdo->prepare(
            "INSERT INTO asset_observations (asset_id, observation_type, raw_value, normalized_value, source_id,
                source_object_ref, observed_at, confidence_level, provenance_json)
             VALUES (?,?,?,?,?,?,datetime('now'),?,?)"
        );
        $obsIdByType = [];
        foreach ($obsDefs as $def) {
            $insObs->execute([
                $assetId,
                $def['observation_type'],
                $def['raw_value'],
                (string) ($def['normalized_slug'] ?? ''),
                (int) $def['source_id'],
                (string) ($def['source_object_ref'] ?? ''),
                (string) ($def['confidence_level'] ?? 'medium'),
                (string) ($def['provenance_json'] ?? '{}'),
            ]);
            $obsIdByType[(string) $def['observation_type']] = (int) $pdo->lastInsertId();
        }

        $resolved = st_recon_resolve_os_platform($obsDefs);
        if (($resolved['skip'] ?? false) === true) {
            if ($oldAssertId > 0) {
                $pdo->prepare('DELETE FROM asset_assertions WHERE id = ?')->execute([$oldAssertId]);
            }
            $pdo->commit();

            $summary['result'] = 'skipped';

            $insRun = $pdo->prepare(
                "INSERT INTO reconciliation_runs (started_at, finished_at, entity_type, entity_id, slice_key, status, result_summary_json, error)
                 VALUES (?, datetime('now'), 'asset', ?, 'os_platform', 'skipped', ?, NULL)"
            );
            $insRun->execute([$runStarted, $assetId, json_encode($summary, JSON_UNESCAPED_SLASHES) ?: '{}']);

            return st_recon_empty_bundle();
        }

        $slug = (string) $resolved['slug'];
        $label = (string) $resolved['label'];
        $confidence = (string) ($resolved['confidence'] ?? 'medium');
        $explanation = (string) ($resolved['explanation'] ?? '');

        $existingAssertId = is_array($existing) ? (int) ($existing['id'] ?? 0) : 0;
        if ($existingAssertId > 0) {
            $pdo->prepare(
                'UPDATE asset_assertions SET asserted_value = ?, confidence_level = ?, reconciled_at = datetime(\'now\'),
                    explanation = ?, version = version + 1, updated_at = datetime(\'now\')
                 WHERE id = ?'
            )->execute([$slug, $confidence, $explanation, $existingAssertId]);
            $aid = $existingAssertId;
        } else {
            $pdo->prepare(
                "INSERT INTO asset_assertions (asset_id, assertion_type, asserted_value, confidence_level, status, reconciled_at, explanation, version, created_at, updated_at)
                 VALUES (?, 'os_platform', ?, ?, 'active', datetime('now'), ?, 1, datetime('now'), datetime('now'))"
            )->execute([$assetId, $slug, $confidence, $explanation]);
            $aid = (int) $pdo->lastInsertId();
        }

        $tie = isset($resolved['tie_order']) && is_array($resolved['tie_order']) ? $resolved['tie_order'] : [];
        $primaryType = (string) ($resolved['primary_type'] ?? '');

        $link = $pdo->prepare(
            'INSERT INTO assertion_sources (assertion_id, observation_id, source_id, contribution, weight_note)
             VALUES (?,?,?,?,?)'
        );
        foreach ($tie as $row) {
            $otyp = (string) ($row['observation_type'] ?? '');
            if ($otyp === '' || ! isset($obsIdByType[$otyp])) {
                continue;
            }
            $oid = (int) $obsIdByType[$otyp];
            $sid = (int) $row['source_id'];
            $contrib = ($otyp === $primaryType) ? 'primary' : 'corroborates';
            $link->execute([$aid, $oid, $sid, $contrib, null]);
        }

        // Include enrichment hint observation when present (always corroborates context)
        if (isset($obsIdByType['os_hint_enrichment'])) {
            $link->execute([$aid, (int) $obsIdByType['os_hint_enrichment'], $sidEnr, 'corroborates', 'discovery_sources metadata']);
        }

        $pdo->commit();

        $summary['result'] = 'ok';
        $summary['asserted_slug'] = $slug;

        $insRun = $pdo->prepare(
            "INSERT INTO reconciliation_runs (started_at, finished_at, entity_type, entity_id, slice_key, status, result_summary_json, error)
             VALUES (?, datetime('now'), 'asset', ?, 'os_platform', 'ok', ?, NULL)"
        );
        $insRun->execute([$runStarted, $assetId, json_encode($summary, JSON_UNESCAPED_SLASHES) ?: '{}']);

        $bundle = st_recon_build_os_bundle_from_db($pdo, $assetId);
        // Prefer resolver human label for display consistency
        $bundle['os_platform_assertion'] = $label;
        if (! empty($bundle['assertions']) && isset($bundle['assertions'][0]) && is_array($bundle['assertions'][0])) {
            $bundle['assertions'][0]['value_label'] = $label;
        }

        return $bundle;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        @error_log('SurveyTrace reconciliation OS lazy: ' . $e->getMessage());

        $insRun = $pdo->prepare(
            "INSERT INTO reconciliation_runs (started_at, finished_at, entity_type, entity_id, slice_key, status, result_summary_json, error)
             VALUES (?, datetime('now'), 'asset', ?, 'os_platform', 'error', NULL, ?)"
        );
        $insRun->execute([$runStarted, $assetId, $e->getMessage()]);

        return st_recon_empty_bundle();
    }
}
