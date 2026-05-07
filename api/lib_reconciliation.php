<?php
/**
 * SurveyTrace — reconciliation primitives (Milestone 1: trusted data model foundations).
 *
 * Read-path lazy reconciliation for OS/platform from existing asset + cached Zabbix inventory.
 * Write-path observation capture (slice 2): scan / Zabbix / operator hooks call upsert helpers here.
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
        ['credentialed_check', 'default', 'Credentialed check worker', 'high'],
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

/**
 * Upsert one OS-related observation (idempotent on UNIQUE(asset_id, observation_type, source_id, source_object_ref)).
 * Updates observed_at only when raw_value or normalized_value changed.
 *
 * @return int observation row id
 */
function st_recon_upsert_asset_observation(
    PDO $pdo,
    int $assetId,
    string $observationType,
    string $rawValue,
    string $normalizedValue,
    int $sourceId,
    string $sourceObjectRef,
    string $confidenceLevel,
    string $provenanceJson
): int {
    $sql = "INSERT INTO asset_observations (asset_id, observation_type, raw_value, normalized_value, source_id,
            source_object_ref, observed_at, confidence_level, provenance_json)
            VALUES (?,?,?,?,?,?,datetime('now'),?,?)
            ON CONFLICT(asset_id, observation_type, source_id, source_object_ref) DO UPDATE SET
                raw_value = excluded.raw_value,
                normalized_value = excluded.normalized_value,
                confidence_level = excluded.confidence_level,
                provenance_json = excluded.provenance_json,
                observed_at = CASE
                    WHEN asset_observations.raw_value = excluded.raw_value
                     AND asset_observations.normalized_value = excluded.normalized_value
                    THEN asset_observations.observed_at
                    ELSE datetime('now')
                END";
    $pdo->prepare($sql)->execute([
        $assetId,
        $observationType,
        $rawValue,
        $normalizedValue,
        $sourceId,
        $sourceObjectRef,
        $confidenceLevel,
        $provenanceJson,
    ]);

    $lk = $pdo->prepare(
        'SELECT id FROM asset_observations WHERE asset_id = ? AND observation_type = ? AND source_id = ? AND source_object_ref = ? LIMIT 1'
    );
    $lk->execute([$assetId, $observationType, $sourceId, $sourceObjectRef]);
    $rid = $lk->fetchColumn();

    return ($rid !== false) ? (int) $rid : 0;
}

/**
 * @param list<int> $keepIds
 */
function st_recon_prune_os_observation_rows(PDO $pdo, int $assetId, array $keepIds): void
{
    $types = ['os_fingerprint_scan', 'os_fingerprint_cpe', 'os_inventory_zabbix', 'os_hint_enrichment'];
    $inTypes = implode(',', array_fill(0, count($types), '?'));
    $params = array_merge([$assetId], $types);
    $preserveOpHint = " AND NOT (observation_type = 'os_hint_enrichment' AND source_object_ref = 'operator_os_guess')";
    if ($keepIds !== []) {
        $inIds = implode(',', array_fill(0, count($keepIds), '?'));
        $sql = "DELETE FROM asset_observations WHERE asset_id = ? AND observation_type IN ($inTypes) AND id NOT IN ($inIds)" . $preserveOpHint;
        $params = array_merge($params, $keepIds);
    } else {
        $sql = "DELETE FROM asset_observations WHERE asset_id = ? AND observation_type IN ($inTypes)" . $preserveOpHint;
    }
    $pdo->prepare($sql)->execute($params);
}

/**
 * Delete Zabbix inventory observations for assets no longer linked (unlink / rematch).
 */
function st_recon_delete_orphan_zabbix_inventory_observations(PDO $pdo, int $zabbixSourceId): void
{
    $pdo->prepare(
        "DELETE FROM asset_observations WHERE observation_type = 'os_inventory_zabbix' AND source_id = ?
         AND asset_id NOT IN (SELECT asset_id FROM zabbix_asset_links)"
    )->execute([$zabbixSourceId]);
}

/**
 * After Zabbix denorm refresh: upsert inventory OS observations for all linked assets (best-effort).
 */
function st_recon_sync_zabbix_inventory_observations_globally(PDO $pdo): void
{
    if (! st_recon_tables_ready($pdo) || ! function_exists('st_zabbix_table_ready') || ! st_zabbix_table_ready($pdo)) {
        return;
    }
    try {
        st_recon_seed_sources($pdo);
        $sidZbx = st_recon_source_id($pdo, 'zabbix_inventory');
        if ($sidZbx === null) {
            return;
        }
        st_recon_delete_orphan_zabbix_inventory_observations($pdo, $sidZbx);
        $q = $pdo->query(
            'SELECT DISTINCT l.asset_id FROM zabbix_asset_links l'
        );
        foreach ($q ? $q->fetchAll(PDO::FETCH_COLUMN) : [] as $aid) {
            $assetId = (int) $aid;
            if ($assetId <= 0) {
                continue;
            }
            $zctx = st_recon_zabbix_os_context($pdo, $assetId);
            if ($zctx === null) {
                $pdo->prepare(
                    "DELETE FROM asset_observations WHERE asset_id = ? AND observation_type = 'os_inventory_zabbix' AND source_id = ?"
                )->execute([$assetId, $sidZbx]);

                continue;
            }
            $combined = implode(' · ', $zctx['parts']);
            $zn = st_recon_normalize_os_text($combined);
            if ($zn === null || ($zn['slug'] ?? '') === '' || ($zn['slug'] ?? '') === 'os_unknown') {
                $pdo->prepare(
                    "DELETE FROM asset_observations WHERE asset_id = ? AND observation_type = 'os_inventory_zabbix' AND source_id = ?"
                )->execute([$assetId, $sidZbx]);

                continue;
            }
            $prov = ['zabbix_hostid' => $zctx['hostid'], 'inventory_keys' => array_keys($zctx['parts'])];
            if (($zctx['synced_at'] ?? '') !== '') {
                $prov['zabbix_inventory_synced_at'] = $zctx['synced_at'];
            }
            st_recon_upsert_asset_observation(
                $pdo,
                $assetId,
                'os_inventory_zabbix',
                $zctx['raw_json'],
                $zn['slug'],
                $sidZbx,
                (string) $zctx['hostid'],
                'medium',
                json_encode($prov, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}'
            );
        }
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_recon_sync_zabbix_inventory_observations_globally: ' . $e->getMessage());
    }
}

/**
 * Record operator-edited OS guess from asset PUT (surveytrace_enrichment source).
 */
function st_recon_record_operator_os_guess_put(PDO $pdo, int $assetId, string $osGuess): void
{
    if (! st_recon_tables_ready($pdo) || $assetId <= 0) {
        return;
    }
    $osGuess = trim($osGuess);
    if ($osGuess === '') {
        return;
    }
    try {
        st_recon_seed_sources($pdo);
        $sid = st_recon_source_id($pdo, 'surveytrace_scan');
        if ($sid === null) {
            return;
        }
        $norm = st_recon_normalize_os_text($osGuess);
        if ($norm === null || ($norm['slug'] ?? '') === '' || ($norm['slug'] ?? '') === 'os_unknown') {
            return;
        }
        // Same observation key as scanner-written os_fingerprint_scan (stable idempotency).
        st_recon_upsert_asset_observation(
            $pdo,
            $assetId,
            'os_fingerprint_scan',
            $osGuess,
            $norm['slug'],
            $sid,
            '',
            'high',
            json_encode(['field' => 'os_guess', 'origin' => 'operator_asset_put'], JSON_UNESCAPED_SLASHES) ?: '{}'
        );
        $sidEnr = st_recon_source_id($pdo, 'surveytrace_enrichment');
        if ($sidEnr !== null) {
            st_recon_upsert_asset_observation(
                $pdo,
                $assetId,
                'os_hint_enrichment',
                json_encode(['os_guess' => $osGuess], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}',
                '',
                $sidEnr,
                'operator_os_guess',
                'medium',
                json_encode(['origin' => 'api_assets_put', 'field' => 'os_guess'], JSON_UNESCAPED_SLASHES) ?: '{}'
            );
        }
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_recon_record_operator_os_guess_put: ' . $e->getMessage());
    }
}

// ---------------------------------------------------------------------------
// Identity (Milestone 1 slice 4) — observations + canonical_hostname assertion
// ---------------------------------------------------------------------------

/**
 * Identity observation_type values (additive; no migration DDL required).
 *
 * @return list<string>
 */
function st_recon_identity_observation_types(): array
{
    return [
        'hostname_observed',
        'fqdn_observed',
        'ipv4_observed',
        'mac_observed',
        'monitoring_hostid',
        'device_link',
        'device_identity_observed',
    ];
}

/** TTL for credentialed OS-release observations dominating reconciliation (matches hostname stale window). */
function st_recon_cred_os_evidence_ttl_seconds(): int
{
    return 90 * 86400;
}

/**
 * Whether SNMP sysName-derived hostname/FQDN rows should be scored as “SNMP-only” signals.
 *
 * @param array<string,mixed> $r Observation row (needs provenance_json when present).
 */
function st_recon_identity_obs_row_is_cred_sysname(array $r): bool
{
    $t = (string) ($r['observation_type'] ?? '');
    if ($t !== 'hostname_observed' && $t !== 'fqdn_observed') {
        return false;
    }
    $prov = json_decode((string) ($r['provenance_json'] ?? '{}'), true);

    return is_array($prov)
        && ($prov['origin'] ?? '') === 'credentialed_check'
        && ($prov['field'] ?? '') === 'sysName';
}

/**
 * Latest persisted os_version_observed from credentialed_check (worker-owned row; reconciler links by id, no upsert).
 *
 * @return array<string,mixed>|null
 */
function st_recon_fetch_latest_cred_os_version_obs_def(PDO $pdo, int $assetId): ?array
{
    if (! st_recon_tables_ready($pdo) || $assetId <= 0) {
        return null;
    }
    st_recon_seed_sources($pdo);
    $sidCred = st_recon_source_id($pdo, 'credentialed_check');
    if ($sidCred === null) {
        return null;
    }
    try {
        $st = $pdo->prepare(
            "SELECT id, raw_value, normalized_value, source_id, source_object_ref, confidence_level, provenance_json, observed_at
             FROM asset_observations
             WHERE asset_id = ? AND observation_type = 'os_version_observed' AND source_id = ?
             ORDER BY datetime(observed_at) DESC, id DESC
             LIMIT 1"
        );
        $st->execute([$assetId, $sidCred]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if (! is_array($row)) {
            return null;
        }
        $slug = strtolower(trim((string) ($row['normalized_value'] ?? '')));
        if ($slug === '' || $slug === 'os_unknown') {
            return null;
        }
        $label = st_recon_os_display_label_for_slug($slug);

        return [
            'observation_type'         => 'os_version_observed',
            'raw_value'                => (string) ($row['raw_value'] ?? ''),
            'normalized_slug'          => $slug,
            'normalized_label'         => $label,
            'source_id'                => (int) ($row['source_id'] ?? $sidCred),
            'source_object_ref'        => (string) ($row['source_object_ref'] ?? ''),
            'confidence_level'         => (string) ($row['confidence_level'] ?? 'high'),
            'provenance_json'          => (string) ($row['provenance_json'] ?? '{}'),
            'observed_at'              => isset($row['observed_at']) ? (string) $row['observed_at'] : '',
            '_existing_observation_id' => (int) ($row['id'] ?? 0),
        ];
    } catch (Throwable $e) {
        return null;
    }
}

function st_recon_cred_os_obs_def_is_stale(array $def): bool
{
    $oa = trim((string) ($def['observed_at'] ?? ''));
    if ($oa === '') {
        // Missing timestamp cannot justify dominance vs fresher scan/Zabbix — treat as stale for reconciliation.
        return true;
    }
    $ts = strtotime($oa);

    return $ts !== false && (time() - $ts) > st_recon_cred_os_evidence_ttl_seconds();
}

/**
 * @return array<string, mixed>
 */
function st_recon_empty_identity_bundle(): array
{
    return [
        'canonical_hostname_assertion'   => null,
        'canonical_hostname_confidence'  => null,
        'canonical_hostname_sources'     => [],
        'canonical_hostname_explanation' => null,
        'identity_assertions'            => [],
    ];
}

function st_recon_normalize_mac_identity_string(?string $mac): string
{
    $m = strtolower(trim((string) ($mac ?? '')));
    if ($m === '') {
        return '';
    }
    $m = str_replace(['-', '.'], ':', $m);
    $m = preg_replace('/[^a-f0-9:]+/i', '', $m) ?? '';

    return trim((string) $m);
}

/**
 * @return array{0:string,1:string}|null [shortLower, fqdnLower] fqdn may equal short
 */
function st_recon_identity_split_hostname_string(string $raw): ?array
{
    $s = strtolower(rtrim(trim($raw), '.'));
    if ($s === '' || strlen($s) > 512) {
        return null;
    }
    if (! str_contains($s, '.')) {
        return [$s, $s];
    }
    $short = strstr($s, '.', true);
    if ($short === false || $short === '') {
        return null;
    }

    return [$short, $s];
}

/**
 * @return list<array<string,mixed>>
 */
function st_recon_identity_hostname_defs_from_string(
    string $raw,
    int $sourceId,
    string $refPrefix,
    string $provenanceField,
    string $confidence = 'medium'
): array {
    $pair = st_recon_identity_split_hostname_string($raw);
    if ($pair === null) {
        return [];
    }
    [$short, $fqdnish] = $pair;
    $defs = [];
    $pfx = $refPrefix !== '' ? $refPrefix . ':' : 'h:';
    if ($short !== $fqdnish) {
        $defs[] = [
            'observation_type'   => 'fqdn_observed',
            'raw_value'          => trim($raw),
            'normalized_value'   => $fqdnish,
            'source_id'          => $sourceId,
            'source_object_ref'  => $pfx . 'fqdn',
            'confidence_level'   => $confidence,
            'provenance_json'    => json_encode(['field' => $provenanceField, 'origin' => 'identity_snapshot'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}',
        ];
        $defs[] = [
            'observation_type'   => 'hostname_observed',
            'raw_value'          => trim($raw),
            'normalized_value'   => $short,
            'source_id'          => $sourceId,
            'source_object_ref'  => $pfx . 'short',
            'confidence_level'   => $confidence,
            'provenance_json'    => json_encode(['field' => $provenanceField, 'derived_from' => 'fqdn', 'origin' => 'identity_snapshot'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}',
        ];
    } else {
        $defs[] = [
            'observation_type'   => 'hostname_observed',
            'raw_value'          => trim($raw),
            'normalized_value'   => $short,
            'source_id'          => $sourceId,
            'source_object_ref'  => $pfx . 'host',
            'confidence_level'   => $confidence,
            'provenance_json'    => json_encode(['field' => $provenanceField, 'origin' => 'identity_snapshot'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}',
        ];
    }

    return $defs;
}

/**
 * Zabbix host naming + inventory strings for identity observations (read-only).
 *
 * @return array{hostid:string,host_strings:array<string,string>,synced_at:?string}|null
 */
function st_recon_zabbix_identity_host_context(PDO $pdo, int $assetId): ?array
{
    if ($assetId <= 0 || ! function_exists('st_zabbix_table_ready') || ! st_zabbix_table_ready($pdo)) {
        return null;
    }
    try {
        $st = $pdo->prepare(
            'SELECT h.hostid, h.tech_name, h.visible_name, h.inventory_json, h.synced_at
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
        $hid = trim((string) ($row['hostid'] ?? ''));
        if ($hid === '') {
            return null;
        }
        $strings = [];
        $vn = trim((string) ($row['visible_name'] ?? ''));
        $tn = trim((string) ($row['tech_name'] ?? ''));
        if ($vn !== '') {
            $strings['visible_name'] = $vn;
        }
        if ($tn !== '' && strcasecmp($tn, $vn) !== 0) {
            $strings['tech_name'] = $tn;
        }
        $inv = json_decode((string) ($row['inventory_json'] ?? '{}'), true);
        if (is_array($inv)) {
            foreach (['name', 'alias', 'dns'] as $k) {
                $v = isset($inv[$k]) ? trim((string) $inv[$k]) : '';
                if ($v !== '') {
                    $strings['inv_' . $k] = $v;
                }
            }
        }

        return [
            'hostid'       => $hid,
            'host_strings' => $strings,
            'synced_at'    => isset($row['synced_at']) ? (string) $row['synced_at'] : null,
        ];
    } catch (Throwable $e) {
        return null;
    }
}

function st_recon_asset_has_identity_anchor(PDO $pdo, int $assetId): bool
{
    if ($assetId <= 0) {
        return false;
    }
    $types = ['mac_observed', 'device_link'];
    $in = implode(',', array_fill(0, count($types), '?'));
    $st = $pdo->prepare("SELECT 1 FROM asset_observations WHERE asset_id = ? AND observation_type IN ($in) LIMIT 1");
    $st->execute(array_merge([$assetId], $types));

    return (int) $st->fetchColumn() === 1;
}

/**
 * @return list<array<string,mixed>>
 */
function st_recon_collect_identity_observation_defs(PDO $pdo, int $assetId, array $assetRowDecoded): array
{
    st_recon_seed_sources($pdo);
    $sidScan = st_recon_source_id($pdo, 'surveytrace_scan');
    $sidZbx = st_recon_source_id($pdo, 'zabbix_inventory');
    if ($sidScan === null || $sidZbx === null) {
        return [];
    }

    /** @var list<array<string,mixed>> $defs */
    $defs = [];

    $ip = trim((string) ($assetRowDecoded['ip'] ?? ''));
    if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $defs[] = [
            'observation_type'   => 'ipv4_observed',
            'raw_value'          => $ip,
            'normalized_value'   => strtolower($ip),
            'source_id'          => $sidScan,
            'source_object_ref'  => 'asset_ip',
            'confidence_level'   => 'medium',
            'provenance_json'    => json_encode(['field' => 'ip', 'origin' => 'asset_snapshot'], JSON_UNESCAPED_SLASHES) ?: '{}',
        ];
    }

    $mac = trim((string) ($assetRowDecoded['mac'] ?? ''));
    $macN = st_recon_normalize_mac_identity_string($mac);
    if ($macN !== '') {
        $defs[] = [
            'observation_type'   => 'mac_observed',
            'raw_value'          => $mac,
            'normalized_value'   => $macN,
            'source_id'          => $sidScan,
            'source_object_ref'  => 'asset_mac',
            'confidence_level'   => 'high',
            'provenance_json'    => json_encode(['field' => 'mac', 'origin' => 'asset_snapshot'], JSON_UNESCAPED_SLASHES) ?: '{}',
        ];
    }

    $did = (int) ($assetRowDecoded['device_id'] ?? 0);
    if ($did > 0) {
        $defs[] = [
            'observation_type'   => 'device_link',
            'raw_value'          => (string) $did,
            'normalized_value'   => (string) $did,
            'source_id'          => $sidScan,
            'source_object_ref'  => 'device:' . $did,
            'confidence_level'   => 'high',
            'provenance_json'    => json_encode(['field' => 'device_id', 'origin' => 'asset_snapshot'], JSON_UNESCAPED_SLASHES) ?: '{}',
        ];
    }

    $hn = trim((string) ($assetRowDecoded['hostname'] ?? ''));
    if ($hn !== '') {
        foreach (st_recon_identity_hostname_defs_from_string($hn, $sidScan, 'asset', 'assets.hostname', 'medium') as $d) {
            $defs[] = $d;
        }
    }

    $zc = st_recon_zabbix_identity_host_context($pdo, $assetId);
    if ($zc !== null) {
        $hid = (string) $zc['hostid'];
        $provBase = ['zabbix_hostid' => $hid, 'origin' => 'zabbix_host'];
        if (($zc['synced_at'] ?? '') !== '') {
            $provBase['zabbix_synced_at'] = $zc['synced_at'];
        }
        $defs[] = [
            'observation_type'   => 'monitoring_hostid',
            'raw_value'          => $hid,
            'normalized_value'   => strtolower($hid),
            'source_id'          => $sidZbx,
            'source_object_ref'  => $hid,
            'confidence_level'   => 'high',
            'provenance_json'    => json_encode($provBase, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}',
        ];
        foreach ($zc['host_strings'] as $slot => $label) {
            foreach (st_recon_identity_hostname_defs_from_string($label, $sidZbx, $hid . ':' . $slot, 'zabbix.' . $slot, 'medium') as $d) {
                $defs[] = $d;
            }
        }
    }

    return $defs;
}

function st_recon_identity_short_key_from_obs_row(array $r): string
{
    $t = (string) ($r['observation_type'] ?? '');
    $n = strtolower(trim((string) ($r['normalized_value'] ?? '')));
    if ($n === '') {
        return '';
    }
    if ($t === 'fqdn_observed') {
        $p = strpos($n, '.');
        if ($p !== false && $p > 0) {
            return substr($n, 0, $p);
        }

        return $n;
    }

    return $n;
}

/**
 * @return array{skip:bool,reason?:string,short?:string,label?:string,confidence?:string,explanation?:string,winner_rows?:list<array<string,mixed>>,conflict_ids?:list<int>}
 */
function st_recon_resolve_canonical_hostname_from_rows(PDO $pdo, int $assetId, array $rows): array
{
    if ($rows === []) {
        return ['skip' => true, 'reason' => 'no_hostname_observations'];
    }
    /** @var array<string, list<array<string,mixed>>> $groups */
    $groups = [];
    foreach ($rows as $r) {
        if (! is_array($r)) {
            continue;
        }
        $obsType = (string) ($r['observation_type'] ?? '');
        if ($obsType !== 'hostname_observed' && $obsType !== 'fqdn_observed') {
            continue;
        }
        $sk = st_recon_identity_short_key_from_obs_row($r);
        if ($sk === '' || strlen($sk) > 253) {
            continue;
        }
        if (! preg_match('/^[a-z0-9]([a-z0-9-]{0,251}[a-z0-9])?$/', $sk)) {
            continue;
        }
        $groups[$sk][] = $r;
    }
    if ($groups === []) {
        return ['skip' => true, 'reason' => 'no_valid_hostname_groups'];
    }

    $hasAnchor = st_recon_asset_has_identity_anchor($pdo, $assetId);
    $now = time();

    $scoreGroup = static function (string $short, array $g) use ($hasAnchor, $now): array {
        $hasAuth = false;
        $hasFqdn = false;
        $hasHost = false;
        $src = [];
        $maxTs = '';
        $staleAll = true;
        $hasCredSysname = false;
        $hasOtherHostnameSignal = false;
        foreach ($g as $r) {
            $conf = strtolower((string) ($r['confidence_level'] ?? ''));
            if ($conf === 'authoritative') {
                $hasAuth = true;
            }
            $src[(int) ($r['source_id'] ?? 0)] = true;
            $t = (string) ($r['observation_type'] ?? '');
            if ($t === 'fqdn_observed') {
                $hasFqdn = true;
            }
            if ($t === 'hostname_observed') {
                $hasHost = true;
            }
            if ($t === 'hostname_observed' || $t === 'fqdn_observed') {
                if (st_recon_identity_obs_row_is_cred_sysname($r)) {
                    $hasCredSysname = true;
                } else {
                    $hasOtherHostnameSignal = true;
                }
            }
            $oa = (string) ($r['observed_at'] ?? '');
            if ($oa !== '' && strcmp($oa, $maxTs) > 0) {
                $maxTs = $oa;
            }
            $ts = strtotime($oa !== '' ? $oa : 'now');
            if ($ts !== false && ($now - $ts) < 90 * 86400) {
                $staleAll = false;
            }
        }
        $hnFqRows = [];
        foreach ($g as $r) {
            $t = (string) ($r['observation_type'] ?? '');
            if ($t === 'hostname_observed' || $t === 'fqdn_observed') {
                $hnFqRows[] = $r;
            }
        }
        $typesSeen = [];
        foreach ($hnFqRows as $hr) {
            $typesSeen[(string) ($hr['observation_type'] ?? '')] = true;
        }
        $snmpSelfCorr = count($hnFqRows) >= 2
            && isset($typesSeen['fqdn_observed'], $typesSeen['hostname_observed'])
            && array_reduce(
                $hnFqRows,
                static function (bool $ok, array $row): bool {
                    return $ok && st_recon_identity_obs_row_is_cred_sysname($row);
                },
                true
            );
        $corroboratedFqdn = $hasFqdn && $hasHost && ! $snmpSelfCorr;
        $uniq = count($src);
        $credSnmpOnlyGroup = $hasCredSysname && ! $hasOtherHostnameSignal && $uniq <= 1;
        $score = ($hasAuth ? 1000 : 0)
            + ($corroboratedFqdn ? 80 : 0)
            + ($uniq >= 2 ? 40 : 0)
            + (count($g) >= 2 ? 10 : 0)
            + ($hasAnchor ? 25 : 0)
            + (($hasCredSysname && $hasOtherHostnameSignal) ? 38 : 0)
            - ($credSnmpOnlyGroup ? 42 : 0);
        if ($staleAll) {
            $score -= 50;
        }

        return [
            'short'                => $short,
            'rows'                 => $g,
            'score'                => $score,
            'has_auth'             => $hasAuth,
            'corroboratedFqdn'     => $corroboratedFqdn,
            'uniq'                 => $uniq,
            'max_ts'               => $maxTs,
            'stale_all'            => $staleAll,
            'cred_snmp_only_group' => $credSnmpOnlyGroup,
            'has_cred_sysname'     => $hasCredSysname,
            'has_other_hostname'   => $hasOtherHostnameSignal,
        ];
    };

    $meta = [];
    foreach ($groups as $short => $g) {
        $meta[] = $scoreGroup($short, $g);
    }
    usort($meta, static function (array $a, array $b): int {
        if (($a['score'] ?? 0) !== ($b['score'] ?? 0)) {
            return ($b['score'] ?? 0) <=> ($a['score'] ?? 0);
        }
        if (($a['has_auth'] ?? false) !== ($b['has_auth'] ?? false)) {
            return ($a['has_auth'] ?? false) ? -1 : 1;
        }
        $cmp = strcmp((string) ($b['max_ts'] ?? ''), (string) ($a['max_ts'] ?? ''));

        return $cmp !== 0 ? $cmp : strcmp((string) ($a['short'] ?? ''), (string) ($b['short'] ?? ''));
    });

    $winner = $meta[0];
    $wshort = (string) ($winner['short'] ?? '');
    $wrows = isset($winner['rows']) && is_array($winner['rows']) ? $winner['rows'] : [];

    $rankForLabel = static function (array $r): int {
        $conf = strtolower((string) ($r['confidence_level'] ?? ''));
        if ($conf === 'authoritative') {
            return 0;
        }
        $isCredSnmp = st_recon_identity_obs_row_is_cred_sysname($r);
        $t = (string) ($r['observation_type'] ?? '');
        if (! $isCredSnmp && $t === 'fqdn_observed') {
            return 2;
        }
        if (! $isCredSnmp && $t === 'hostname_observed') {
            return 4;
        }
        if ($isCredSnmp && $t === 'fqdn_observed') {
            return 6;
        }
        if ($isCredSnmp && $t === 'hostname_observed') {
            return 8;
        }

        return 10;
    };
    usort($wrows, static function (array $a, array $b) use ($rankForLabel): int {
        $cmp = $rankForLabel($a) <=> $rankForLabel($b);

        return $cmp !== 0 ? $cmp : ((int) ($a['id'] ?? 0) <=> (int) ($b['id'] ?? 0));
    });

    $labelRaw = '';
    foreach ($wrows as $r) {
        if (strtolower((string) ($r['confidence_level'] ?? '')) === 'authoritative') {
            $labelRaw = (string) ($r['raw_value'] ?? '');
            break;
        }
    }
    if ($labelRaw === '') {
        foreach ($wrows as $r) {
            if (($r['observation_type'] ?? '') === 'fqdn_observed') {
                $labelRaw = (string) ($r['raw_value'] ?? '');
                break;
            }
        }
    }
    if ($labelRaw === '') {
        foreach ($wrows as $r) {
            if (($r['observation_type'] ?? '') === 'hostname_observed') {
                $labelRaw = (string) ($r['raw_value'] ?? '');
                break;
            }
        }
    }
    $label = $labelRaw !== '' ? trim($labelRaw) : $wshort;

    $conf = 'low';
    if ($winner['has_auth'] ?? false) {
        $conf = 'authoritative';
    } elseif (($winner['corroboratedFqdn'] ?? false) && $hasAnchor) {
        $conf = 'high';
    } elseif (($winner['corroboratedFqdn'] ?? false) || (($winner['uniq'] ?? 0) >= 2)) {
        $conf = 'medium';
    } elseif (($winner['uniq'] ?? 0) >= 1 && ! ($winner['stale_all'] ?? false)) {
        $conf = 'medium';
    }
    if (($winner['stale_all'] ?? false) && $conf !== 'authoritative') {
        $conf = st_recon_confidence_min($conf, 'low');
    }
    if (($winner['cred_snmp_only_group'] ?? false) && $conf !== 'authoritative') {
        $conf = st_recon_confidence_min($conf, 'medium');
    }

    $expl = [];
    $expl[] = 'Canonical hostname is the short DNS label (' . $wshort . ') chosen from hostname and FQDN observations.';
    if ($winner['corroboratedFqdn'] ?? false) {
        $expl[] = 'An FQDN observation aligns with a hostname label on this asset.';
    }
    if (($winner['uniq'] ?? 0) >= 2) {
        $expl[] = 'Multiple independent sources agree on this label.';
    }
    if (($winner['has_cred_sysname'] ?? false) && ($winner['has_other_hostname'] ?? false)) {
        $expl[] = 'Credentialed SNMP sysName agrees with other hostname or FQDN observations.';
    }
    if (($winner['cred_snmp_only_group'] ?? false) && ! ($winner['has_auth'] ?? false)) {
        $expl[] = 'SNMP sysName supports this label where stronger DNS or operator hostname signals were absent.';
    }
    if ($hasAnchor) {
        $expl[] = 'MAC and/or device linkage is present, which strengthens identity confidence.';
    }
    if ($winner['stale_all'] ?? false) {
        $expl[] = 'Supporting hostname evidence is older than 90 days; confidence is capped lower.';
    }
    if (count($meta) > 1) {
        $expl[] = 'Other hostname or FQDN observations differ and are kept as conflicting evidence.';
    }

    $conflictIds = [];
    foreach ($rows as $r) {
        if (! is_array($r)) {
            continue;
        }
        $rid = (int) ($r['id'] ?? 0);
        $t = (string) ($r['observation_type'] ?? '');
        if ($rid <= 0 || ($t !== 'hostname_observed' && $t !== 'fqdn_observed')) {
            continue;
        }
        if (st_recon_identity_short_key_from_obs_row($r) !== $wshort) {
            $conflictIds[] = $rid;
        }
    }

    return [
        'skip'          => false,
        'short'         => $wshort,
        'label'         => $label,
        'confidence'    => $conf,
        'explanation'   => trim(implode(' ', $expl)),
        'winner_rows'   => $wrows,
        'conflict_ids'  => $conflictIds,
    ];
}

/**
 * @return array<string, mixed>
 */
function st_recon_build_identity_bundle_from_db(PDO $pdo, int $assetId): array
{
    $out = st_recon_empty_identity_bundle();
    if (! st_recon_tables_ready($pdo) || $assetId <= 0) {
        return $out;
    }
    try {
        $ast = $pdo->prepare(
            "SELECT id, assertion_type, asserted_value, confidence_level, explanation, reconciled_at, version
             FROM asset_assertions WHERE asset_id = ? AND assertion_type = 'canonical_hostname' LIMIT 1"
        );
        $ast->execute([$assetId]);
        $assert = $ast->fetch(PDO::FETCH_ASSOC);
        if (! is_array($assert)) {
            return $out;
        }
        $slug = strtolower(trim((string) ($assert['asserted_value'] ?? '')));
        $display = $slug;
        $obsSt = $pdo->prepare(
            "SELECT o.raw_value, o.observation_type
             FROM assertion_sources asrc
             JOIN asset_observations o ON o.id = asrc.observation_id
             WHERE asrc.assertion_id = ?
               AND o.observation_type IN ('hostname_observed','fqdn_observed')
             ORDER BY CASE WHEN o.observation_type = 'fqdn_observed' THEN 0 ELSE 1 END, asrc.id ASC
             LIMIT 4"
        );
        $obsSt->execute([(int) ($assert['id'] ?? 0)]);
        foreach ($obsSt->fetchAll(PDO::FETCH_ASSOC) ?: [] as $or) {
            $rv = trim((string) ($or['raw_value'] ?? ''));
            if ($rv !== '') {
                $display = $rv;
                break;
            }
        }

        $srcSt = $pdo->prepare(
            "SELECT DISTINCT s.display_name
             FROM assertion_sources asrc
             JOIN asset_observations o ON o.id = asrc.observation_id
             JOIN recon_sources s ON s.id = o.source_id
             WHERE asrc.assertion_id = ? AND o.observation_type IN ('hostname_observed','fqdn_observed')"
        );
        $srcSt->execute([(int) ($assert['id'] ?? 0)]);
        $srcs = [];
        foreach ($srcSt->fetchAll(PDO::FETCH_COLUMN) ?: [] as $dn) {
            $dn = trim((string) $dn);
            if ($dn !== '') {
                $srcs[$dn] = true;
            }
        }

        $out['canonical_hostname_assertion'] = $display !== '' ? $display : $slug;
        $out['canonical_hostname_confidence'] = (string) ($assert['confidence_level'] ?? 'medium');
        $out['canonical_hostname_sources'] = array_keys($srcs);
        $out['canonical_hostname_explanation'] = (string) ($assert['explanation'] ?? '');
        $out['identity_assertions'] = [[
            'type'          => 'canonical_hostname',
            'value_slug'    => $slug,
            'value_label'   => $display !== '' ? $display : $slug,
            'confidence'    => (string) ($assert['confidence_level'] ?? 'medium'),
            'explanation'   => (string) ($assert['explanation'] ?? ''),
            'reconciled_at' => $assert['reconciled_at'] ?? null,
            'version'       => (int) ($assert['version'] ?? 1),
        ]];
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_recon_build_identity_bundle_from_db: ' . $e->getMessage());
    }

    return $out;
}

/**
 * Lazy reconcile canonical_hostname for one asset (single-asset GET path).
 *
 * @param array<string,mixed> $assetRowDecoded
 *
 * @return array<string, mixed>
 */
function st_recon_lazy_reconcile_canonical_hostname(PDO $pdo, int $assetId, array $assetRowDecoded): array
{
    if (! st_recon_tables_ready($pdo) || $assetId <= 0) {
        return st_recon_empty_identity_bundle();
    }

    $existingStmt = $pdo->prepare(
        "SELECT id, reconciled_at, asserted_value, confidence_level, explanation, version
         FROM asset_assertions WHERE asset_id = ? AND assertion_type = 'canonical_hostname' LIMIT 1"
    );
    $existingStmt->execute([$assetId]);
    $existing = $existingStmt->fetch(PDO::FETCH_ASSOC);

    $lastSeen = isset($assetRowDecoded['last_seen']) ? (string) $assetRowDecoded['last_seen'] : null;
    if (! st_recon_should_refresh_cached_assertion(is_array($existing) ? $existing : null, $lastSeen)) {
        return st_recon_build_identity_bundle_from_db($pdo, $assetId);
    }

    $runStarted = date('Y-m-d H:i:s');
    $summary = ['slice' => 'identity_hostname', 'observations' => 0, 'result' => 'pending'];

    $defs = st_recon_collect_identity_observation_defs($pdo, $assetId, $assetRowDecoded);
    $summary['observations'] = count($defs);

    try {
        $pdo->beginTransaction();

        $oldAssertId = is_array($existing) ? (int) ($existing['id'] ?? 0) : 0;
        if ($oldAssertId > 0) {
            $pdo->prepare('DELETE FROM assertion_sources WHERE assertion_id = ?')->execute([$oldAssertId]);
        }

        $obsIdByKey = [];
        foreach ($defs as $def) {
            $oid = st_recon_upsert_asset_observation(
                $pdo,
                $assetId,
                (string) $def['observation_type'],
                (string) $def['raw_value'],
                (string) ($def['normalized_value'] ?? ''),
                (int) $def['source_id'],
                (string) ($def['source_object_ref'] ?? ''),
                (string) ($def['confidence_level'] ?? 'medium'),
                (string) ($def['provenance_json'] ?? '{}')
            );
            if ($oid > 0) {
                $k = (string) $def['observation_type'] . "\0" . (string) ($def['source_object_ref'] ?? '');
                $obsIdByKey[$k] = $oid;
            }
        }

        $hnSt = $pdo->prepare(
            "SELECT id, observation_type, raw_value, normalized_value, observed_at, confidence_level, source_id, source_object_ref, provenance_json
             FROM asset_observations
             WHERE asset_id = ? AND observation_type IN ('hostname_observed','fqdn_observed')
             ORDER BY observed_at DESC, id DESC"
        );
        $hnSt->execute([$assetId]);
        $hnRows = $hnSt->fetchAll(PDO::FETCH_ASSOC) ?: [];

        $resolved = st_recon_resolve_canonical_hostname_from_rows($pdo, $assetId, $hnRows);
        if (($resolved['skip'] ?? false) === true) {
            if ($oldAssertId > 0) {
                $pdo->prepare('DELETE FROM asset_assertions WHERE id = ?')->execute([$oldAssertId]);
            }
            $pdo->commit();
            $summary['result'] = 'skipped';
            $insRun = $pdo->prepare(
                "INSERT INTO reconciliation_runs (started_at, finished_at, entity_type, entity_id, slice_key, status, result_summary_json, error)
                 VALUES (?, datetime('now'), 'asset', ?, 'identity_hostname', 'skipped', ?, NULL)"
            );
            $insRun->execute([$runStarted, $assetId, json_encode($summary, JSON_UNESCAPED_SLASHES) ?: '{}']);

            return st_recon_empty_identity_bundle();
        }

        $slug = strtolower(trim((string) ($resolved['short'] ?? '')));
        $confidence = (string) ($resolved['confidence'] ?? 'medium');
        $explanation = (string) ($resolved['explanation'] ?? '');
        if ($slug === '') {
            if ($oldAssertId > 0) {
                $pdo->prepare('DELETE FROM asset_assertions WHERE id = ?')->execute([$oldAssertId]);
            }
            $pdo->commit();
            $summary['result'] = 'skipped_empty';
            $insRun = $pdo->prepare(
                "INSERT INTO reconciliation_runs (started_at, finished_at, entity_type, entity_id, slice_key, status, result_summary_json, error)
                 VALUES (?, datetime('now'), 'asset', ?, 'identity_hostname', 'skipped', ?, NULL)"
            );
            $insRun->execute([$runStarted, $assetId, json_encode($summary, JSON_UNESCAPED_SLASHES) ?: '{}']);

            return st_recon_empty_identity_bundle();
        }

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
                 VALUES (?, 'canonical_hostname', ?, ?, 'active', datetime('now'), ?, 1, datetime('now'), datetime('now'))"
            )->execute([$assetId, $slug, $confidence, $explanation]);
            $aid = (int) $pdo->lastInsertId();
        }

        $link = $pdo->prepare(
            'INSERT INTO assertion_sources (assertion_id, observation_id, source_id, contribution, weight_note)
             VALUES (?,?,?,?,?)'
        );

        $winnerRows = isset($resolved['winner_rows']) && is_array($resolved['winner_rows']) ? $resolved['winner_rows'] : [];
        foreach ($winnerRows as $row) {
            $otyp = (string) ($row['observation_type'] ?? '');
            $oref = (string) ($row['source_object_ref'] ?? '');
            $sid = (int) ($row['source_id'] ?? 0);
            $k = $otyp . "\0" . $oref;
            $oid = (int) ($row['id'] ?? 0);
            if ($oid <= 0) {
                $oid = (int) ($obsIdByKey[$k] ?? 0);
            }
            if ($oid <= 0) {
                continue;
            }
            $prim = ($otyp === 'fqdn_observed') ? 'primary' : 'corroborates';
            $link->execute([$aid, $oid, $sid, $prim, null]);
        }

        $extraTypes = ['mac_observed', 'device_link', 'ipv4_observed', 'monitoring_hostid'];
        $exSt = $pdo->prepare(
            'SELECT id, source_id FROM asset_observations WHERE asset_id = ? AND observation_type = ? ORDER BY id DESC LIMIT 3'
        );
        foreach ($extraTypes as $xt) {
            $exSt->execute([$assetId, $xt]);
            foreach ($exSt->fetchAll(PDO::FETCH_ASSOC) ?: [] as $xr) {
                $xid = (int) ($xr['id'] ?? 0);
                $xsid = (int) ($xr['source_id'] ?? 0);
                if ($xid > 0 && $xsid > 0) {
                    $link->execute([$aid, $xid, $xsid, 'corroborates', 'identity anchor / monitoring context']);
                }
            }
        }

        $diSt = $pdo->prepare(
            "SELECT id, source_id FROM asset_observations WHERE asset_id = ? AND observation_type = 'device_identity_observed'
             ORDER BY datetime(observed_at) DESC, id DESC LIMIT 1"
        );
        $diSt->execute([$assetId]);
        $diRow = $diSt->fetch(PDO::FETCH_ASSOC);
        if (is_array($diRow)) {
            $did = (int) ($diRow['id'] ?? 0);
            $dsid = (int) ($diRow['source_id'] ?? 0);
            if ($did > 0 && $dsid > 0) {
                $link->execute([$aid, $did, $dsid, 'corroborates', 'SNMP device identity summary (context only; not hostname)']);
            }
        }

        $pdo->commit();

        $summary['result'] = 'ok';
        $summary['asserted_short'] = $slug;
        $insRun = $pdo->prepare(
            "INSERT INTO reconciliation_runs (started_at, finished_at, entity_type, entity_id, slice_key, status, result_summary_json, error)
             VALUES (?, datetime('now'), 'asset', ?, 'identity_hostname', 'ok', ?, NULL)"
        );
        $insRun->execute([$runStarted, $assetId, json_encode($summary, JSON_UNESCAPED_SLASHES) ?: '{}']);

        return st_recon_build_identity_bundle_from_db($pdo, $assetId);
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        @error_log('SurveyTrace reconciliation identity_hostname lazy: ' . $e->getMessage());
        $insRun = $pdo->prepare(
            "INSERT INTO reconciliation_runs (started_at, finished_at, entity_type, entity_id, slice_key, status, result_summary_json, error)
             VALUES (?, datetime('now'), 'asset', ?, 'identity_hostname', 'error', NULL, ?)"
        );
        $insRun->execute([$runStarted, $assetId, $e->getMessage()]);

        return st_recon_empty_identity_bundle();
    }
}

function st_recon_delete_orphan_zabbix_identity_observations(PDO $pdo, int $zabbixSourceId): void
{
    $pdo->prepare(
        "DELETE FROM asset_observations WHERE source_id = ?
         AND observation_type IN ('monitoring_hostid','hostname_observed','fqdn_observed')
         AND asset_id NOT IN (SELECT asset_id FROM zabbix_asset_links)"
    )->execute([$zabbixSourceId]);
}

function st_recon_sync_zabbix_identity_observations_globally(PDO $pdo): void
{
    if (! st_recon_tables_ready($pdo) || ! function_exists('st_zabbix_table_ready') || ! st_zabbix_table_ready($pdo)) {
        return;
    }
    try {
        st_recon_seed_sources($pdo);
        $sidZbx = st_recon_source_id($pdo, 'zabbix_inventory');
        if ($sidZbx === null) {
            return;
        }
        st_recon_delete_orphan_zabbix_identity_observations($pdo, $sidZbx);
        $q = $pdo->query('SELECT DISTINCT l.asset_id FROM zabbix_asset_links l');
        foreach ($q ? $q->fetchAll(PDO::FETCH_COLUMN) : [] as $aid) {
            $assetId = (int) $aid;
            if ($assetId <= 0) {
                continue;
            }
            $ar = $pdo->prepare('SELECT * FROM assets WHERE id = ? LIMIT 1');
            $ar->execute([$assetId]);
            $row = $ar->fetch(PDO::FETCH_ASSOC);
            if (! is_array($row)) {
                continue;
            }
            foreach (st_recon_collect_identity_observation_defs($pdo, $assetId, $row) as $def) {
                st_recon_upsert_asset_observation(
                    $pdo,
                    $assetId,
                    (string) $def['observation_type'],
                    (string) $def['raw_value'],
                    (string) ($def['normalized_value'] ?? ''),
                    (int) $def['source_id'],
                    (string) ($def['source_object_ref'] ?? ''),
                    (string) ($def['confidence_level'] ?? 'medium'),
                    (string) ($def['provenance_json'] ?? '{}')
                );
            }
        }
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_recon_sync_zabbix_identity_observations_globally: ' . $e->getMessage());
    }
}

function st_recon_record_operator_hostname_put(PDO $pdo, int $assetId, string $hostname): void
{
    if (! st_recon_tables_ready($pdo) || $assetId <= 0) {
        return;
    }
    $hostname = trim($hostname);
    if ($hostname === '') {
        return;
    }
    try {
        st_recon_seed_sources($pdo);
        $sidEnr = st_recon_source_id($pdo, 'surveytrace_enrichment');
        if ($sidEnr === null) {
            return;
        }
        foreach (st_recon_identity_hostname_defs_from_string($hostname, $sidEnr, 'operator', 'api.assets.put.hostname', 'authoritative') as $def) {
            st_recon_upsert_asset_observation(
                $pdo,
                $assetId,
                (string) $def['observation_type'],
                (string) $def['raw_value'],
                (string) ($def['normalized_value'] ?? ''),
                (int) $def['source_id'],
                (string) $def['source_object_ref'],
                (string) $def['confidence_level'],
                (string) $def['provenance_json']
            );
        }
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_recon_record_operator_hostname_put: ' . $e->getMessage());
    }
}

/**
 * Identity evidence block for Host Details / admin (size-bounded).
 *
 * @return array<string, mixed>
 */
function st_recon_build_identity_recon_detail_for_asset(
    PDO $pdo,
    int $assetId,
    int $obsLimit = 32,
    int $runLimit = 8,
    bool $includeAssertionSources = false
): array {
    $types = st_recon_identity_observation_types();
    $inTypes = implode(',', array_fill(0, count($types), '?'));
    $empty = [
        'tables_ready'              => false,
        'assertion'                 => null,
        'observations'              => [],
        'recent_runs'               => [],
        'assertion_sources'         => [],
        'supporting_observation_ids'=> [],
        'conflicting_observation_ids'=> [],
    ];
    if ($assetId <= 0 || ! st_recon_tables_ready($pdo)) {
        return $empty;
    }
    $empty['tables_ready'] = true;
    try {
        $ast = $pdo->prepare(
            "SELECT id, assertion_type, asserted_value, confidence_level, explanation, reconciled_at, version, updated_at
             FROM asset_assertions WHERE asset_id = ? AND assertion_type = 'canonical_hostname' LIMIT 1"
        );
        $ast->execute([$assetId]);
        $ar = $ast->fetch(PDO::FETCH_ASSOC);
        $assertId = 0;
        if (is_array($ar)) {
            $assertId = (int) ($ar['id'] ?? 0);
            $slug = strtolower(trim((string) ($ar['asserted_value'] ?? '')));
            $empty['assertion'] = [
                'id'            => $assertId,
                'type'          => 'canonical_hostname',
                'value_slug'    => $slug,
                'value_label'   => $slug,
                'confidence'    => (string) ($ar['confidence_level'] ?? 'medium'),
                'explanation'   => st_recon_truncate_evidence_string((string) ($ar['explanation'] ?? ''), 1200),
                'reconciled_at' => $ar['reconciled_at'] ?? null,
                'version'       => (int) ($ar['version'] ?? 1),
                'updated_at'    => $ar['updated_at'] ?? null,
            ];
        }

        /** @var array<int, string> $contribByObsId */
        $contribByObsId = [];
        if ($assertId > 0) {
            $cg = $pdo->prepare(
                'SELECT observation_id, contribution, weight_note FROM assertion_sources WHERE assertion_id = ?'
            );
            $cg->execute([$assertId]);
            foreach ($cg->fetchAll(PDO::FETCH_ASSOC) ?: [] as $cr) {
                $oidc = (int) ($cr['observation_id'] ?? 0);
                if ($oidc > 0) {
                    $contribByObsId[$oidc] = st_recon_evidence_contribution_hint(
                        isset($cr['contribution']) ? (string) $cr['contribution'] : '',
                        isset($cr['weight_note']) ? (string) $cr['weight_note'] : ''
                    );
                }
            }
        }

        $lim = max(1, min(80, $obsLimit));
        $ost = $pdo->prepare(
            "SELECT o.id, o.observation_type, o.raw_value, o.normalized_value, o.observed_at, o.confidence_level,
                    o.source_object_ref, s.source_type, s.display_name
             FROM asset_observations o
             JOIN recon_sources s ON s.id = o.source_id
             WHERE o.asset_id = ? AND o.observation_type IN ($inTypes)
             ORDER BY o.id DESC
             LIMIT {$lim}"
        );
        $ost->execute(array_merge([$assetId], $types));
        $obsList = [];
        foreach ($ost->fetchAll(PDO::FETCH_ASSOC) ?: [] as $r) {
            $oid = (int) ($r['id'] ?? 0);
            $ch = $contribByObsId[$oid] ?? '';
            if ($ch === '' && (($r['observation_type'] ?? '') === 'device_identity_observed')) {
                $ch = 'Context only · SNMP digest (not hostname)';
            }
            $obsList[] = [
                'id'                 => $oid,
                'observation_type'   => (string) ($r['observation_type'] ?? ''),
                'source_type'        => (string) ($r['source_type'] ?? ''),
                'display_name'       => (string) ($r['display_name'] ?? ''),
                'source_object_ref'  => (string) ($r['source_object_ref'] ?? ''),
                'raw_value'          => st_recon_truncate_evidence_string((string) ($r['raw_value'] ?? ''), 420),
                'normalized_value'   => st_recon_truncate_evidence_string((string) ($r['normalized_value'] ?? ''), 200),
                'observed_at'        => $r['observed_at'] ?? null,
                'confidence_level'   => (string) ($r['confidence_level'] ?? 'medium'),
                'contribution_hint'  => $ch,
            ];
        }
        $empty['observations'] = $obsList;

        $winnerShort = '';
        if (is_array($empty['assertion'])) {
            $winnerShort = strtolower(trim((string) ($empty['assertion']['value_slug'] ?? '')));
        }
        $sup = [];
        $con = [];
        foreach ($obsList as $o) {
            $oid = (int) ($o['id'] ?? 0);
            $ot = (string) ($o['observation_type'] ?? '');
            if ($oid <= 0) {
                continue;
            }
            if ($ot !== 'hostname_observed' && $ot !== 'fqdn_observed') {
                continue;
            }
            $row = [
                'observation_type'  => $ot,
                'normalized_value' => (string) ($o['normalized_value'] ?? ''),
                'confidence_level'  => (string) ($o['confidence_level'] ?? ''),
                'id'                => $oid,
            ];
            if ($winnerShort === '') {
                continue;
            }
            if (st_recon_identity_short_key_from_obs_row($row) === $winnerShort) {
                $sup[] = $oid;
            } else {
                $con[] = $oid;
            }
        }
        $empty['supporting_observation_ids'] = $sup;
        $empty['conflicting_observation_ids'] = $con;

        $rlim = max(1, min(40, $runLimit));
        $rst = $pdo->prepare(
            "SELECT id, started_at, finished_at, status, slice_key, error, result_summary_json
             FROM reconciliation_runs
             WHERE entity_type = 'asset' AND entity_id = ? AND slice_key = 'identity_hostname'
             ORDER BY id DESC
             LIMIT {$rlim}"
        );
        $rst->execute([$assetId]);
        foreach ($rst->fetchAll(PDO::FETCH_ASSOC) ?: [] as $r) {
            $sum = (string) ($r['result_summary_json'] ?? '');
            if (strlen($sum) > 240) {
                $sum = substr($sum, 0, 240) . '…';
            }
            $empty['recent_runs'][] = [
                'id'             => (int) ($r['id'] ?? 0),
                'started_at'     => $r['started_at'] ?? null,
                'finished_at'    => $r['finished_at'] ?? null,
                'status'         => (string) ($r['status'] ?? ''),
                'slice_key'      => (string) ($r['slice_key'] ?? ''),
                'error'          => st_recon_truncate_evidence_string((string) ($r['error'] ?? ''), 360),
                'result_summary' => $sum !== '' ? $sum : null,
            ];
        }

        if ($includeAssertionSources && $assertId > 0) {
            $lst = $pdo->prepare(
                'SELECT asrc.contribution, asrc.weight_note, o.observation_type, o.normalized_value,
                        o.source_object_ref AS observation_source_ref, o.observed_at AS observation_observed_at,
                        s.display_name, s.source_type
                 FROM assertion_sources asrc
                 JOIN asset_observations o ON o.id = asrc.observation_id
                 JOIN recon_sources s ON s.id = asrc.source_id
                 WHERE asrc.assertion_id = ?
                 ORDER BY asrc.id ASC
                 LIMIT 48'
            );
            $lst->execute([$assertId]);
            $empty['assertion_sources'] = $lst->fetchAll(PDO::FETCH_ASSOC) ?: [];
        }
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_recon_build_identity_recon_detail_for_asset: ' . $e->getMessage());
    }

    return $empty;
}

/**
 * Build OS observation defs for lazy reconcile (same shape as prior inline builder).
 *
 * @return list<array<string,mixed>>
 */
function st_recon_collect_os_observation_defs(PDO $pdo, int $assetId, array $assetRowDecoded): array
{
    st_recon_seed_sources($pdo);
    $sidScan = st_recon_source_id($pdo, 'surveytrace_scan');
    $sidZbx = st_recon_source_id($pdo, 'zabbix_inventory');
    $sidEnr = st_recon_source_id($pdo, 'surveytrace_enrichment');

    /** @var list<array<string,mixed>> $obsDefs */
    $obsDefs = [];

    $osGuess = trim((string) ($assetRowDecoded['os_guess'] ?? ''));
    if ($osGuess !== '' && $sidScan !== null) {
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
    if ($cpe !== '' && $sidScan !== null) {
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

    $zctx = $sidZbx !== null ? st_recon_zabbix_os_context($pdo, $assetId) : null;
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
    if ($sidEnr !== null && is_array($disc) && $disc !== []) {
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

    $credOs = st_recon_fetch_latest_cred_os_version_obs_def($pdo, $assetId);
    if ($credOs !== null) {
        $obsDefs[] = $credOs;
    }

    return $obsDefs;
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

// ---------------------------------------------------------------------------
// Slice 5 — trusted operational read preference (additive API / UI; no writes)
// ---------------------------------------------------------------------------

/**
 * Whether a reconciled value may be preferred in UI, exports, and search display.
 * Low remains informational-only (still visible in evidence; not promoted as trusted_*).
 */
function st_recon_confidence_meets_trusted_operational_threshold(?string $level): bool
{
    $c = strtolower(trim((string) ($level ?? '')));

    return in_array($c, ['medium', 'high', 'authoritative'], true);
}

/**
 * Compact trusted summary for APIs (nulls when confidence is too low or value empty).
 *
 * @return array{trusted_hostname:?string,trusted_hostname_confidence:?string,trusted_os_platform:?string,trusted_os_confidence:?string}
 */
function st_recon_trusted_operational_api_fields(
    ?string $canonicalHostnameLabel,
    ?string $canonicalHostnameConfidence,
    ?string $osPlatformLabel,
    ?string $osPlatformConfidence
): array {
    $hLabel = $canonicalHostnameLabel !== null ? trim($canonicalHostnameLabel) : '';
    $hConf = $canonicalHostnameConfidence !== null ? trim($canonicalHostnameConfidence) : '';
    $osLabel = $osPlatformLabel !== null ? trim($osPlatformLabel) : '';
    $osConf = $osPlatformConfidence !== null ? trim($osPlatformConfidence) : '';

    return [
        'trusted_hostname' => ($hLabel !== '' && st_recon_confidence_meets_trusted_operational_threshold($hConf))
            ? $hLabel : null,
        'trusted_hostname_confidence' => ($hLabel !== '' && st_recon_confidence_meets_trusted_operational_threshold($hConf))
            ? strtolower($hConf) : null,
        'trusted_os_platform' => ($osLabel !== '' && st_recon_confidence_meets_trusted_operational_threshold($osConf))
            ? $osLabel : null,
        'trusted_os_confidence' => ($osLabel !== '' && st_recon_confidence_meets_trusted_operational_threshold($osConf))
            ? strtolower($osConf) : null,
    ];
}

/**
 * List / export rows: merge LEFT JOIN assertion aliases into public trusted_* fields.
 *
 * @param array<string,mixed> $row
 * @return array<string,mixed>
 */
function st_recon_augment_asset_row_with_trusted_operational_fields(array $row): array
{
    if (! array_key_exists('st_rec_hv', $row) && ! array_key_exists('st_rec_os', $row)) {
        return array_merge($row, st_recon_trusted_operational_api_fields(null, null, null, null));
    }
    $hv = isset($row['st_rec_hv']) ? trim((string) $row['st_rec_hv']) : '';
    $hc = isset($row['st_rec_hc']) ? trim((string) $row['st_rec_hc']) : '';
    $os = isset($row['st_rec_os']) ? trim((string) $row['st_rec_os']) : '';
    $oc = isset($row['st_rec_oc']) ? trim((string) $row['st_rec_oc']) : '';
    unset($row['st_rec_hv'], $row['st_rec_hc'], $row['st_rec_os'], $row['st_rec_oc']);

    $osLabel = $os !== '' ? st_recon_os_display_label_for_slug($os) : '';

    $tf = st_recon_trusted_operational_api_fields(
        $hv !== '' ? $hv : null,
        $hc !== '' ? $hc : null,
        $osLabel !== '' ? $osLabel : null,
        $oc !== '' ? $oc : null
    );

    return array_merge($row, $tf);
}

function st_recon_list_query_assertion_select_sql(): string
{
    return ', ah.asserted_value AS st_rec_hv, ah.confidence_level AS st_rec_hc, ao.asserted_value AS st_rec_os, ao.confidence_level AS st_rec_oc';
}

function st_recon_list_query_assertion_join_sql(): string
{
    return " LEFT JOIN asset_assertions ah ON ah.asset_id = a.id AND ah.assertion_type = 'canonical_hostname' "
        . " LEFT JOIN asset_assertions ao ON ao.asset_id = a.id AND ao.assertion_type = 'os_platform' ";
}

/**
 * Same st_rec_* aliases as the JOIN variant, but scalar subqueries (safe with GROUP BY on assets).
 */
function st_recon_list_query_assertion_select_sql_scalar(): string
{
    return ", (SELECT asserted_value FROM asset_assertions WHERE asset_id = a.id AND assertion_type = 'canonical_hostname' LIMIT 1) AS st_rec_hv"
        . ", (SELECT confidence_level FROM asset_assertions WHERE asset_id = a.id AND assertion_type = 'canonical_hostname' LIMIT 1) AS st_rec_hc"
        . ", (SELECT asserted_value FROM asset_assertions WHERE asset_id = a.id AND assertion_type = 'os_platform' LIMIT 1) AS st_rec_os"
        . ", (SELECT confidence_level FROM asset_assertions WHERE asset_id = a.id AND assertion_type = 'os_platform' LIMIT 1) AS st_rec_oc";
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
 * Whether a cached assertion row should be recomputed (shared by OS and identity lazy paths).
 *
 * Uses asset last_seen vs assertion reconciled_at plus a short TTL so repeated host opens stay cheap
 * while scans still refresh beliefs within minutes.
 */
function st_recon_should_refresh_cached_assertion(?array $existingRow, ?string $assetLastSeen): bool
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

/** Same logic as st_recon_should_refresh_cached_assertion; name reflects primary OS call site. */
function st_recon_should_refresh_os_assertion(?array $existingRow, ?string $assetLastSeen): bool
{
    return st_recon_should_refresh_cached_assertion($existingRow, $assetLastSeen);
}

/**
 * Scan/CPE + Zabbix OS resolver (no credentialed os_version_observed).
 *
 * @param array<string,mixed>|null $cpeRow
 * @param array<string,mixed>|null $scanRow
 * @param array<string,mixed>|null $zbxRow
 *
 * @return array<string,mixed>
 */
function st_recon_resolve_os_platform_legacy_scan_zbx(?array $cpeRow, ?array $scanRow, ?array $zbxRow): array
{
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
 * @param array<int, array<string, mixed>> $obsDefs
 *
 * @return array<string, mixed>
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

    $credRow = null;
    foreach ($normalizedRows as $r) {
        if (($r['observation_type'] ?? '') === 'os_version_observed') {
            $credRow = $r;
            break;
        }
    }

    $scanSlug = null;
    if ($cpeRow) {
        $scanSlug = (string) $cpeRow['normalized_slug'];
    } elseif ($scanRow) {
        $scanSlug = (string) $scanRow['normalized_slug'];
    }

    $zslug = $zbxRow ? (string) $zbxRow['normalized_slug'] : null;

    $credFresh = $credRow !== null && ! st_recon_cred_os_obs_def_is_stale($credRow);
    $credStale = $credRow !== null && ! $credFresh;

    if ($credFresh && $credRow !== null) {
        $cslug = (string) $credRow['normalized_slug'];
        $clabel = (string) $credRow['normalized_label'];
        $fpAgree = $scanSlug !== null && $scanSlug === $cslug;
        $zAgree = $zslug !== null && $zslug === $cslug;
        $zConflict = $zslug !== null && $zslug !== $cslug;
        $fpConflict = $scanSlug !== null && $scanSlug !== $cslug;

        $tieOrder = array_values(array_filter([$credRow, $cpeRow, $scanRow, $zbxRow]));
        $expl = [];
        $confidence = 'high';

        if ($fpAgree) {
            if ($zConflict) {
                $expl[] = 'Authenticated OS release agrees with SurveyTrace scan fingerprint; Zabbix inventory differs — conflicting evidence is retained.';
            } elseif ($zAgree) {
                $expl[] = 'Authenticated OS release agrees with SurveyTrace scan fingerprint and Zabbix inventory (' . $clabel . ').';
            } else {
                $expl[] = 'Authenticated OS release agrees with SurveyTrace scan fingerprint (' . $clabel . ').';
            }
            $confidence = 'high';
        } elseif ($zAgree && ! $fpConflict) {
            $expl[] = 'Authenticated OS release agrees with Zabbix inventory (' . $clabel . ', no SurveyTrace scan fingerprint yet).';
            $confidence = 'high';
        } elseif ($zAgree && $fpConflict) {
            $expl[] = 'Authenticated OS release agrees with Zabbix inventory; SurveyTrace scan fingerprint differs — conflicting evidence is retained.';
            $confidence = 'medium';
        } elseif ($scanSlug === null && $zslug === null) {
            $expl[] = 'Based on authenticated OS release from credentialed check (' . $clabel . ').';
            $confidence = 'high';
        } else {
            $expl[] = 'Authenticated OS release (' . $clabel . ') differs from unauthenticated scan/inventory signals — both sides kept as evidence.';
            $confidence = 'medium';
        }

        return [
            'skip'         => false,
            'slug'         => $cslug,
            'label'        => $clabel,
            'confidence'   => $confidence,
            'explanation'  => trim(implode(' ', $expl)),
            'primary_type' => 'os_version_observed',
            'tie_order'    => $tieOrder,
        ];
    }

    if ($credStale && $credRow !== null) {
        $legacy = st_recon_resolve_os_platform_legacy_scan_zbx($cpeRow, $scanRow, $zbxRow);
        if (($legacy['skip'] ?? false) !== true) {
            $legacySlug = (string) ($legacy['slug'] ?? '');
            $credSlug = (string) $credRow['normalized_slug'];
            if ($legacySlug !== '' && $credSlug !== '' && $legacySlug !== $credSlug) {
                $legacy['explanation'] = trim(
                    (string) ($legacy['explanation'] ?? '')
                    . ' Older authenticated OS observation disagrees and remains visible as stale evidence.'
                );
            } elseif ($legacySlug !== '' && $credSlug !== '' && $legacySlug === $credSlug) {
                $legacy['explanation'] = trim(
                    (string) ($legacy['explanation'] ?? '')
                    . ' An older authenticated OS observation (>90 days) agrees but is not used to raise confidence; belief follows current scan/inventory.'
                );
            } else {
                $legacy['explanation'] = trim(
                    (string) ($legacy['explanation'] ?? '')
                    . ' An older authenticated OS observation (>90 days) did not override fresher scan/inventory signals.'
                );
            }
            $legacy['tie_order'] = array_values(array_filter(array_merge((array) ($legacy['tie_order'] ?? []), [$credRow])));

            return $legacy;
        }

        return [
            'skip'         => false,
            'slug'         => (string) $credRow['normalized_slug'],
            'label'        => (string) $credRow['normalized_label'],
            'confidence'   => 'low',
            'explanation'  => 'Only an older authenticated OS observation is available (>90 days); confidence is capped low until refreshed.',
            'primary_type' => 'os_version_observed',
            'tie_order'    => [$credRow],
        ];
    }

    return st_recon_resolve_os_platform_legacy_scan_zbx($cpeRow, $scanRow, $zbxRow);
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
         WHERE o.asset_id = ? AND o.observation_type IN (
            'os_fingerprint_scan','os_fingerprint_cpe','os_inventory_zabbix','os_hint_enrichment',
            'os_version_observed','package_inventory_observed'
         )
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

    /** @var list<array<string, mixed>> $obsDefs */
    $obsDefs = st_recon_collect_os_observation_defs($pdo, $assetId, $assetRowDecoded);
    $sidEnr = st_recon_source_id($pdo, 'surveytrace_enrichment');

    $summary['observations'] = count($obsDefs);

    try {
        $pdo->beginTransaction();

        $oldAssertId = is_array($existing) ? (int) ($existing['id'] ?? 0) : 0;
        if ($oldAssertId > 0) {
            $pdo->prepare('DELETE FROM assertion_sources WHERE assertion_id = ?')->execute([$oldAssertId]);
        }

        $resolved = st_recon_resolve_os_platform($obsDefs);
        if (($resolved['skip'] ?? false) === true) {
            if ($oldAssertId > 0) {
                $pdo->prepare('DELETE FROM asset_assertions WHERE id = ?')->execute([$oldAssertId]);
            }
            // Keep persisted observations (write-path capture); only drop the assertion when we cannot resolve.
            $pdo->commit();

            $summary['result'] = 'skipped';

            $insRun = $pdo->prepare(
                "INSERT INTO reconciliation_runs (started_at, finished_at, entity_type, entity_id, slice_key, status, result_summary_json, error)
                 VALUES (?, datetime('now'), 'asset', ?, 'os_platform', 'skipped', ?, NULL)"
            );
            $insRun->execute([$runStarted, $assetId, json_encode($summary, JSON_UNESCAPED_SLASHES) ?: '{}']);

            return st_recon_empty_bundle();
        }

        $obsIdByKey = [];
        $allObsIds = [];
        foreach ($obsDefs as $def) {
            $existingOid = (int) ($def['_existing_observation_id'] ?? 0);
            if ($existingOid > 0) {
                $oid = $existingOid;
            } else {
                $oid = st_recon_upsert_asset_observation(
                    $pdo,
                    $assetId,
                    (string) $def['observation_type'],
                    (string) $def['raw_value'],
                    (string) ($def['normalized_slug'] ?? ''),
                    (int) $def['source_id'],
                    (string) ($def['source_object_ref'] ?? ''),
                    (string) ($def['confidence_level'] ?? 'medium'),
                    (string) ($def['provenance_json'] ?? '{}')
                );
            }
            if ($oid > 0) {
                $k = (string) $def['observation_type'] . "\0" . (string) ($def['source_object_ref'] ?? '');
                $obsIdByKey[$k] = $oid;
                $allObsIds[] = $oid;
            }
        }
        st_recon_prune_os_observation_rows($pdo, $assetId, $allObsIds);

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
            $oref = (string) ($row['source_object_ref'] ?? '');
            if ($otyp === '') {
                continue;
            }
            $k = $otyp . "\0" . $oref;
            $oid = $obsIdByKey[$k] ?? ($obsIdByKey[$otyp . "\0"] ?? null);
            if ($oid === null) {
                continue;
            }
            $sid = (int) $row['source_id'];
            $contrib = ($otyp === $primaryType) ? 'primary' : 'corroborates';
            $link->execute([$aid, (int) $oid, $sid, $contrib, null]);
        }

        // Include enrichment hint observation(s) when present (corroborates context)
        if ($sidEnr !== null) {
            $kDisc = "os_hint_enrichment\0";
            if (isset($obsIdByKey[$kDisc])) {
                $link->execute([$aid, (int) $obsIdByKey[$kDisc], $sidEnr, 'corroborates', 'discovery_sources metadata']);
            }
            $opHint = $pdo->prepare(
                "SELECT id FROM asset_observations WHERE asset_id = ? AND observation_type = 'os_hint_enrichment' AND source_id = ? AND source_object_ref = 'operator_os_guess' LIMIT 1"
            );
            $opHint->execute([$assetId, $sidEnr]);
            $opId = $opHint->fetchColumn();
            if ($opId !== false && (int) $opId > 0) {
                $link->execute([$aid, (int) $opId, $sidEnr, 'corroborates', 'operator os metadata']);
            }
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

function st_recon_truncate_evidence_string(?string $s, int $maxLen = 360): string
{
    $s = (string) ($s ?? '');
    if (strlen($s) <= $maxLen) {
        return $s;
    }

    return substr($s, 0, $maxLen) . '…';
}

/** Compact explanation line for observation ↔ assertion linkage (host modal evidence). */
function st_recon_evidence_contribution_hint(?string $contribution, ?string $weightNote): string
{
    $c = strtolower(trim((string) ($contribution ?? '')));
    $w = trim((string) ($weightNote ?? ''));
    if ($c === '' && $w === '') {
        return '';
    }
    $cc = $c !== '' ? ucfirst($c) : '';

    return ($cc !== '' && $w !== '') ? ($cc . ' · ' . $w) : ($cc !== '' ? $cc : $w);
}

/**
 * Trim oldest reconciliation_runs rows (audit log). Returns rows deleted.
 * Safe to call occasionally (e.g. admin maintenance); not invoked on every health poll.
 */
function st_recon_trim_reconciliation_runs(PDO $pdo, int $keepNewest = 8000): int
{
    if (! st_recon_tables_ready($pdo)) {
        return 0;
    }
    try {
        $cnt = (int) $pdo->query('SELECT COUNT(*) FROM reconciliation_runs')->fetchColumn();
        if ($cnt <= $keepNewest) {
            return 0;
        }
        $off = max(0, $keepNewest - 1);
        $st = $pdo->query('SELECT id FROM reconciliation_runs ORDER BY id DESC LIMIT 1 OFFSET ' . $off);
        $cutId = $st ? $st->fetchColumn() : false;
        if ($cutId === false || (int) $cutId < 1) {
            return 0;
        }
        $del = $pdo->prepare('DELETE FROM reconciliation_runs WHERE id < ?');
        $del->execute([(int) $cutId]);

        return $del->rowCount();
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_recon_trim_reconciliation_runs: ' . $e->getMessage());

        return 0;
    }
}

/**
 * System Health: compact trusted-data / OS reconciliation diagnostics.
 *
 * @return array<string, mixed>
 */
function st_recon_health_snapshot(PDO $pdo): array
{
    $out = [
        'tables_ready'                       => false,
        'observation_count'                  => 0,
        'assertion_count'                    => 0,
        'identity_observation_count'         => 0,
        'identity_assertion_count'             => 0,
        'identity_hostname_conflict_assets'  => 0,
        'reconciliation_runs_total'          => 0,
        'failed_runs_24h'                    => 0,
        'last_failure_message'               => null,
        'stale_os_assertions_30d'            => 0,
        'credentialed_observation_count'    => 0,
        'stale_cred_os_observations_90d'     => 0,
        'warning_hints'                      => [],
    ];
    if (! st_recon_tables_ready($pdo)) {
        $out['warning_hints'][] = 'Trusted data tables are not present (migration may not have run).';

        return $out;
    }
    $out['tables_ready'] = true;
    try {
        $out['observation_count'] = (int) $pdo->query('SELECT COUNT(*) FROM asset_observations')->fetchColumn();
        $idTypes = st_recon_identity_observation_types();
        $idIn = implode(',', array_fill(0, count($idTypes), '?'));
        $idSt = $pdo->prepare("SELECT COUNT(*) FROM asset_observations WHERE observation_type IN ($idIn)");
        $idSt->execute($idTypes);
        $out['identity_observation_count'] = (int) $idSt->fetchColumn();
        $out['assertion_count'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM asset_assertions WHERE assertion_type = 'os_platform'"
        )->fetchColumn();
        $out['identity_assertion_count'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM asset_assertions WHERE assertion_type = 'canonical_hostname'"
        )->fetchColumn();
        $out['identity_hostname_conflict_assets'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM (
                SELECT asset_id FROM asset_observations
                WHERE observation_type = 'hostname_observed' AND TRIM(COALESCE(normalized_value,'')) != ''
                GROUP BY asset_id HAVING COUNT(DISTINCT normalized_value) > 1
            )"
        )->fetchColumn();
        $out['reconciliation_runs_total'] = (int) $pdo->query('SELECT COUNT(*) FROM reconciliation_runs')->fetchColumn();
        $out['failed_runs_24h'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM reconciliation_runs WHERE status = 'error' AND datetime(finished_at) >= datetime('now', '-1 day')"
        )->fetchColumn();
        $out['stale_os_assertions_30d'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM asset_assertions WHERE assertion_type = 'os_platform'
             AND datetime(reconciled_at) < datetime('now', '-30 days')"
        )->fetchColumn();
        $sidCred = st_recon_source_id($pdo, 'credentialed_check');
        if ($sidCred !== null) {
            $cs = $pdo->prepare('SELECT COUNT(*) FROM asset_observations WHERE source_id = ?');
            $cs->execute([$sidCred]);
            $out['credentialed_observation_count'] = (int) $cs->fetchColumn();
            $cs2 = $pdo->prepare(
                "SELECT COUNT(*) FROM asset_observations WHERE source_id = ? AND observation_type = 'os_version_observed'
                 AND datetime(observed_at) < datetime('now', '-90 days')"
            );
            $cs2->execute([$sidCred]);
            $out['stale_cred_os_observations_90d'] = (int) $cs2->fetchColumn();
        }
        $msg = $pdo->query(
            "SELECT error FROM reconciliation_runs WHERE status = 'error' AND COALESCE(error,'') <> '' ORDER BY id DESC LIMIT 1"
        )->fetchColumn();
        if ($msg !== false && trim((string) $msg) !== '') {
            $out['last_failure_message'] = st_recon_truncate_evidence_string((string) $msg, 400);
        }
        if ($out['failed_runs_24h'] > 0) {
            $out['warning_hints'][] = (string) $out['failed_runs_24h']
                . ' lazy reconciliation run(s) failed in the last 24h (OS platform / identity slices).';
        }
        if ($out['stale_os_assertions_30d'] > 200) {
            $out['warning_hints'][] = 'Many OS/platform assertions are older than 30 days — review scan/enrichment freshness.';
        }
        if ((int) ($out['identity_hostname_conflict_assets'] ?? 0) > 100) {
            $out['warning_hints'][] = 'Many assets show conflicting hostname observations — review enrichment and Zabbix naming.';
        }
    } catch (Throwable $e) {
        $out['warning_hints'][] = 'Trusted data diagnostics query failed.';
        @error_log('SurveyTrace st_recon_health_snapshot: ' . $e->getMessage());
    }

    return $out;
}

/**
 * Host detail / admin diagnostics: observations + assertion + recent runs (size-bounded).
 *
 * @return array<string, mixed>
 */
function st_recon_build_evidence_detail_for_asset(
    PDO $pdo,
    int $assetId,
    int $obsLimit = 24,
    int $runLimit = 8,
    bool $includeAssertionSources = false
): array {
    $empty = [
        'tables_ready'         => false,
        'assertion'            => null,
        'observations'         => [],
        'recent_runs'          => [],
        'assertion_sources'    => [],
    ];
    if ($assetId <= 0 || ! st_recon_tables_ready($pdo)) {
        return $empty;
    }
    $empty['tables_ready'] = true;
    try {
        $ast = $pdo->prepare(
            "SELECT id, assertion_type, asserted_value, confidence_level, explanation, reconciled_at, version, updated_at
             FROM asset_assertions WHERE asset_id = ? AND assertion_type = 'os_platform' LIMIT 1"
        );
        $ast->execute([$assetId]);
        $ar = $ast->fetch(PDO::FETCH_ASSOC);
        if (is_array($ar)) {
            $slug = (string) ($ar['asserted_value'] ?? '');
            $empty['assertion'] = [
                'id'             => (int) ($ar['id'] ?? 0),
                'type'           => (string) ($ar['assertion_type'] ?? ''),
                'value_slug'     => $slug,
                'value_label'    => st_recon_os_display_label_for_slug($slug),
                'confidence'     => (string) ($ar['confidence_level'] ?? 'medium'),
                'explanation'    => st_recon_truncate_evidence_string((string) ($ar['explanation'] ?? ''), 1200),
                'reconciled_at'  => $ar['reconciled_at'] ?? null,
                'version'        => (int) ($ar['version'] ?? 1),
                'updated_at'     => $ar['updated_at'] ?? null,
            ];
        }
        $assertIdForHints = is_array($empty['assertion']) ? (int) ($empty['assertion']['id'] ?? 0) : 0;
        /** @var array<int, string> $contribByObsId */
        $contribByObsId = [];
        if ($assertIdForHints > 0) {
            $cg = $pdo->prepare(
                'SELECT observation_id, contribution, weight_note FROM assertion_sources WHERE assertion_id = ?'
            );
            $cg->execute([$assertIdForHints]);
            foreach ($cg->fetchAll(PDO::FETCH_ASSOC) ?: [] as $cr) {
                $oid = (int) ($cr['observation_id'] ?? 0);
                if ($oid > 0) {
                    $contribByObsId[$oid] = st_recon_evidence_contribution_hint(
                        isset($cr['contribution']) ? (string) $cr['contribution'] : '',
                        isset($cr['weight_note']) ? (string) $cr['weight_note'] : ''
                    );
                }
            }
        }

        $lim = max(1, min(80, $obsLimit));
        $ost = $pdo->prepare(
            "SELECT o.id, o.observation_type, o.raw_value, o.normalized_value, o.observed_at, o.confidence_level,
                    o.source_object_ref, s.source_type, s.display_name
             FROM asset_observations o
             JOIN recon_sources s ON s.id = o.source_id
             WHERE o.asset_id = ?
               AND o.observation_type IN (
                    'os_fingerprint_scan','os_fingerprint_cpe','os_inventory_zabbix','os_hint_enrichment',
                    'os_version_observed','package_inventory_observed'
               )
             ORDER BY o.id DESC
             LIMIT {$lim}"
        );
        $ost->execute([$assetId]);
        foreach ($ost->fetchAll(PDO::FETCH_ASSOC) ?: [] as $r) {
            $oid = (int) ($r['id'] ?? 0);
            $empty['observations'][] = [
                'id'                 => $oid,
                'observation_type'   => (string) ($r['observation_type'] ?? ''),
                'source_type'        => (string) ($r['source_type'] ?? ''),
                'display_name'       => (string) ($r['display_name'] ?? ''),
                'source_object_ref'  => (string) ($r['source_object_ref'] ?? ''),
                'raw_value'          => st_recon_truncate_evidence_string((string) ($r['raw_value'] ?? ''), 420),
                'normalized_value'   => st_recon_truncate_evidence_string((string) ($r['normalized_value'] ?? ''), 200),
                'observed_at'        => $r['observed_at'] ?? null,
                'confidence_level'   => (string) ($r['confidence_level'] ?? 'medium'),
                'contribution_hint'  => $contribByObsId[$oid] ?? '',
            ];
        }
        $rlim = max(1, min(40, $runLimit));
        $rst = $pdo->prepare(
            "SELECT id, started_at, finished_at, status, slice_key, error, result_summary_json
             FROM reconciliation_runs
             WHERE entity_type = 'asset' AND entity_id = ? AND slice_key = 'os_platform'
             ORDER BY id DESC
             LIMIT {$rlim}"
        );
        $rst->execute([$assetId]);
        foreach ($rst->fetchAll(PDO::FETCH_ASSOC) ?: [] as $r) {
            $sum = (string) ($r['result_summary_json'] ?? '');
            if (strlen($sum) > 240) {
                $sum = substr($sum, 0, 240) . '…';
            }
            $empty['recent_runs'][] = [
                'id'          => (int) ($r['id'] ?? 0),
                'started_at'  => $r['started_at'] ?? null,
                'finished_at' => $r['finished_at'] ?? null,
                'status'      => (string) ($r['status'] ?? ''),
                'slice_key'   => (string) ($r['slice_key'] ?? ''),
                'error'       => st_recon_truncate_evidence_string((string) ($r['error'] ?? ''), 360),
                'result_summary' => $sum !== '' ? $sum : null,
            ];
        }
        if ($includeAssertionSources && is_array($empty['assertion']) && ($empty['assertion']['id'] ?? 0) > 0) {
            $aid = (int) $empty['assertion']['id'];
            $lst = $pdo->prepare(
                'SELECT asrc.contribution, asrc.weight_note, o.observation_type, o.normalized_value,
                        o.source_object_ref AS observation_source_ref, o.observed_at AS observation_observed_at,
                        s.display_name, s.source_type
                 FROM assertion_sources asrc
                 JOIN asset_observations o ON o.id = asrc.observation_id
                 JOIN recon_sources s ON s.id = asrc.source_id
                 WHERE asrc.assertion_id = ?
                 ORDER BY asrc.id ASC
                 LIMIT 40'
            );
            $lst->execute([$aid]);
            $empty['assertion_sources'] = $lst->fetchAll(PDO::FETCH_ASSOC) ?: [];
        }
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_recon_build_evidence_detail_for_asset: ' . $e->getMessage());
    }

    return $empty;
}
