<?php
/**
 * SurveyTrace — GET /api/export.php
 *
 * Exports the full asset inventory (with findings) as CSV or JSON.
 *
 * Query params:
 *   format   — csv | json (default: csv)
 *   category — filter by category (optional)
 *   severity — filter by severity (optional)
 *   findings  — 1 = include findings rows in CSV (default: 0)
 *   device_id — if > 0, only assets for this logical device
 *   lifecycle_status — active|stale|retired (optional; Phase 12)
 *   zabbix_monitored — ''|0|1, zabbix_unavailable=1, zabbix_has_problems=1, zabbix_group, zabbix_tag (Phase 16.2; when migrations applied)
 *
 * CSV/JSON include Phase 12 lifecycle and business-context columns on asset rows.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_zabbix.php';
st_auth();
st_require_role(['viewer', 'scan_editor', 'admin']);
st_method('GET');

/**
 * Normalize a DB cell for CSV (null → empty string; trim strings).
 */
function st_export_csv_cell(mixed $v): string {
    if ($v === null || $v === false) {
        return '';
    }
    if (is_int($v) || is_float($v)) {
        return (string)$v;
    }
    return trim((string)$v);
}

$db       = st_db();
$format   = st_str('format', 'csv', ['csv', 'json']);
$category = st_str('category');
$severity = st_str('severity', '', ['', 'critical', 'high', 'medium', 'low', 'none']);
$inc_find = st_str('findings') === '1';

// ---------------------------------------------------------------------------
// Build asset query
// ---------------------------------------------------------------------------
$sev_ranges = [
    'critical' => [9.0, 10.1],
    'high'     => [7.0,  9.0],
    'medium'   => [4.0,  7.0],
    'low'      => [0.1,  4.0],
];

$where  = ['1=1'];
$params = [];

if ($category !== '') {
    $where[]        = 'a.category = :cat';
    $params[':cat'] = $category;
}

if ($severity !== '') {
    if ($severity === 'none') {
        $where[] = '(a.top_cvss IS NULL OR a.top_cvss = 0)';
    } elseif (isset($sev_ranges[$severity])) {
        [$lo, $hi]      = $sev_ranges[$severity];
        $where[]        = 'a.top_cvss >= :slo AND a.top_cvss < :shi';
        $params[':slo'] = $lo;
        $params[':shi'] = $hi;
    }
}

$device_filter = st_int('device_id', 0, 0, PHP_INT_MAX);
if ($device_filter > 0) {
    $where[]          = 'a.device_id = :devid';
    $params[':devid'] = $device_filter;
}

$lifecycle_status = st_str('lifecycle_status', '', ['', 'active', 'stale', 'retired']);
if ($lifecycle_status !== '') {
    $where[]          = "COALESCE(a.lifecycle_status,'active') = :lfs";
    $params[':lfs']   = $lifecycle_status;
}

$zbxFilters = st_zabbix_filters_available_for_assets($db);
$zabbix_monitored = st_str('zabbix_monitored', '', ['', '0', '1']);
$zabbix_unavailable = st_str('zabbix_unavailable') === '1';
$zabbix_has_problems = st_str('zabbix_has_problems') === '1';
$zabbix_group = trim(st_str('zabbix_group'));
$zabbix_tag = trim(st_str('zabbix_tag'));
if ($zbxFilters) {
    if ($zabbix_monitored === '1') {
        $where[] = 'EXISTS (SELECT 1 FROM zabbix_asset_links lz1 WHERE lz1.asset_id = a.id)
            AND COALESCE(a.monitored_by_zabbix, 0) = 1';
    } elseif ($zabbix_monitored === '0') {
        $where[] = '(NOT EXISTS (SELECT 1 FROM zabbix_asset_links lz0 WHERE lz0.asset_id = a.id)
            OR (EXISTS (SELECT 1 FROM zabbix_asset_links lz0b WHERE lz0b.asset_id = a.id)
                AND COALESCE(a.monitored_by_zabbix, 0) = 0))';
    }
    if ($zabbix_unavailable) {
        $where[] = 'EXISTS (SELECT 1 FROM zabbix_asset_links lzu WHERE lzu.asset_id = a.id)
            AND COALESCE(a.monitored_by_zabbix, 0) = 1
            AND TRIM(COALESCE(a.zabbix_availability, \'\')) != \'\'
            AND LOWER(TRIM(COALESCE(a.zabbix_availability, \'\'))) != \'available\'';
    }
    if ($zabbix_has_problems) {
        $where[] = 'EXISTS (SELECT 1 FROM zabbix_asset_links lzp WHERE lzp.asset_id = a.id)
            AND COALESCE(a.zabbix_problem_count, 0) > 0';
    }
    if ($zabbix_group !== '') {
        $where[] = 'EXISTS (
            SELECT 1 FROM zabbix_asset_links lgg
            JOIN zabbix_host_groups gg ON gg.hostid = lgg.zabbix_hostid
            WHERE lgg.asset_id = a.id AND LOWER(gg.group_name) = LOWER(:zabbix_group)
        )';
        $params[':zabbix_group'] = $zabbix_group;
    }
    if ($zabbix_tag !== '') {
        if (str_contains($zabbix_tag, '=')) {
            [$tk, $tv] = array_map('trim', explode('=', $zabbix_tag, 2));
            if ($tk !== '') {
                $where[] = 'EXISTS (
                    SELECT 1 FROM zabbix_asset_links ltt
                    JOIN zabbix_host_tags tg ON tg.hostid = ltt.zabbix_hostid
                    WHERE ltt.asset_id = a.id
                      AND LOWER(tg.tag) = LOWER(:zabbix_tag_k)
                      AND LOWER(tg.value) = LOWER(:zabbix_tag_v)
                )';
                $params[':zabbix_tag_k'] = $tk;
                $params[':zabbix_tag_v'] = $tv;
            }
        } else {
            $where[] = 'EXISTS (
                SELECT 1 FROM zabbix_asset_links ltn
                JOIN zabbix_host_tags tn ON tn.hostid = ltn.zabbix_hostid
                WHERE ltn.asset_id = a.id AND LOWER(tn.tag) = LOWER(:zabbix_tag_name)
            )';
            $params[':zabbix_tag_name'] = $zabbix_tag;
        }
    }
}

$where_sql = implode(' AND ', $where);

$stmt = $db->prepare("
    SELECT
        a.ip, a.device_id, a.hostname, a.mac, a.mac_vendor, a.category,
        a.vendor, a.model, a.os_guess, a.cpe,
        a.open_ports, a.top_cve, a.top_cvss,
        (SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id AND f.resolved = 0) AS open_findings,
        a.first_seen, a.last_seen,
        COALESCE(a.lifecycle_status, 'active') AS lifecycle_status,
        a.lifecycle_reason,
        COALESCE(a.missed_scan_count, 0) AS missed_scan_count,
        a.last_expected_scan_id, a.last_expected_scan_at,
        a.last_missed_scan_id, a.last_missed_scan_at,
        a.retired_at,
        a.owner, a.business_unit,
        COALESCE(a.criticality, 'medium') AS criticality,
        COALESCE(a.environment, 'unknown') AS environment,
        a.identity_confidence, a.identity_confidence_reason,
        a.notes
    FROM assets a
    WHERE $where_sql
    ORDER BY a.ip
");
$stmt->execute($params);
$assets = $stmt->fetchAll();

$timestamp = date('Y-m-d_H-i-s');

// ---------------------------------------------------------------------------
// JSON export
// ---------------------------------------------------------------------------
if ($format === 'json') {
    $export = [];
    foreach ($assets as $a) {
        $row = $a;
        $row['open_ports'] = json_decode($a['open_ports'] ?? '[]', true) ?: [];
        $row['top_cvss']   = $a['top_cvss'] ? (float)$a['top_cvss'] : null;
        $row['severity']   = $a['top_cvss'] ? st_severity((float)$a['top_cvss']) : 'none';
        $row['lifecycle_status'] = (string)($a['lifecycle_status'] ?? 'active');
        $row['lifecycle_reason'] = isset($a['lifecycle_reason']) && $a['lifecycle_reason'] !== ''
            ? (string)$a['lifecycle_reason'] : null;
        $row['missed_scan_count'] = (int)($a['missed_scan_count'] ?? 0);
        foreach (
            [
                'last_expected_scan_id', 'last_expected_scan_at', 'last_missed_scan_id',
                'last_missed_scan_at', 'retired_at', 'owner', 'business_unit',
                'identity_confidence', 'identity_confidence_reason',
            ] as $fk
        ) {
            $row[$fk] = isset($a[$fk]) && $a[$fk] !== '' && $a[$fk] !== null ? $a[$fk] : null;
        }
        $row['criticality'] = (string)($a['criticality'] ?? 'medium');
        $row['environment'] = (string)($a['environment'] ?? 'unknown');

        if ($inc_find) {
            $fstmt = $db->prepare("
                SELECT cve_id, cvss, severity, description, published, resolved
                FROM findings WHERE asset_id = (SELECT id FROM assets WHERE ip = ?)
                ORDER BY cvss DESC
            ");
            $fstmt->execute([$a['ip']]);
            $row['findings'] = $fstmt->fetchAll();
        }
        $export[] = $row;
    }

    header('Content-Type: application/json; charset=utf-8');
    header("Content-Disposition: attachment; filename=\"surveytrace_assets_{$timestamp}.json\"");
    header('Cache-Control: no-store');
    echo json_encode([
        'exported_at'  => date('c'),
        'total_assets' => count($export),
        'assets'       => $export,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// ---------------------------------------------------------------------------
// CSV export
// ---------------------------------------------------------------------------
header('Content-Type: text/csv; charset=utf-8');
header("Content-Disposition: attachment; filename=\"surveytrace_assets_{$timestamp}.csv\"");
header('Cache-Control: no-store');

$out = fopen('php://output', 'w');

// BOM for Excel UTF-8 compatibility
fwrite($out, "\xEF\xBB\xBF");

// Asset header row (Phase 12 fields follow Last Seen, before Notes — same order as SELECT)
fputcsv($out, [
    'IP Address', 'Device ID', 'Hostname', 'MAC', 'MAC Vendor', 'Category',
    'Vendor', 'Model', 'OS Guess', 'CPE',
    'Open Ports', 'Top CVE', 'Top CVSS', 'Severity',
    'Open Findings', 'First Seen', 'Last Seen',
    'Lifecycle Status', 'Lifecycle Reason', 'Missed Scan Count',
    'Last Expected Scan Id', 'Last Expected Scan At', 'Last Missed Scan Id', 'Last Missed Scan At', 'Retired At',
    'Owner', 'Business Unit', 'Criticality', 'Environment',
    'Identity Confidence', 'Identity Confidence Reason',
    'Notes',
]);

foreach ($assets as $a) {
    $ports    = json_decode($a['open_ports'] ?? '[]', true) ?: [];
    $cvss     = $a['top_cvss'] ? (float)$a['top_cvss'] : null;
    $severity = $cvss ? st_severity($cvss) : 'none';

    fputcsv($out, [
        $a['ip'],
        isset($a['device_id']) && $a['device_id'] !== '' && $a['device_id'] !== null
            ? (int)$a['device_id'] : '',
        $a['hostname'] ?? '',
        $a['mac'] ?? '',
        $a['mac_vendor'] ?? '',
        $a['category'] ?? 'unk',
        $a['vendor'] ?? '',
        $a['model'] ?? '',
        $a['os_guess'] ?? '',
        $a['cpe'] ?? '',
        implode(' ', $ports),
        $a['top_cve'] ?? '',
        $cvss ?? '',
        $severity,
        (int)($a['open_findings'] ?? 0),
        st_export_csv_cell($a['first_seen'] ?? ''),
        st_export_csv_cell($a['last_seen'] ?? ''),
        st_export_csv_cell($a['lifecycle_status'] ?? ''),
        st_export_csv_cell($a['lifecycle_reason'] ?? ''),
        st_export_csv_cell($a['missed_scan_count'] ?? ''),
        st_export_csv_cell($a['last_expected_scan_id'] ?? ''),
        st_export_csv_cell($a['last_expected_scan_at'] ?? ''),
        st_export_csv_cell($a['last_missed_scan_id'] ?? ''),
        st_export_csv_cell($a['last_missed_scan_at'] ?? ''),
        st_export_csv_cell($a['retired_at'] ?? ''),
        st_export_csv_cell($a['owner'] ?? ''),
        st_export_csv_cell($a['business_unit'] ?? ''),
        st_export_csv_cell($a['criticality'] ?? ''),
        st_export_csv_cell($a['environment'] ?? ''),
        st_export_csv_cell($a['identity_confidence'] ?? ''),
        st_export_csv_cell($a['identity_confidence_reason'] ?? ''),
        st_export_csv_cell($a['notes'] ?? ''),
    ]);

    // Optionally append finding rows beneath each asset
    if ($inc_find && (int)($a['open_findings'] ?? 0) > 0) {
        $fstmt = $db->prepare("
            SELECT cve_id, cvss, severity, description, published
            FROM findings
            WHERE asset_id = (SELECT id FROM assets WHERE ip = ?)
              AND resolved = 0
            ORDER BY cvss DESC
        ");
        $fstmt->execute([$a['ip']]);
        foreach ($fstmt->fetchAll() as $f) {
            // 32 columns — align with asset header (CVE row reuses legacy slots: Top CVE..Severity, Last Seen, Notes).
            $frow = array_fill(0, 32, '');
            $frow[11] = (string)($f['cve_id'] ?? '');
            $frow[12] = (string)($f['cvss'] ?? '');
            $frow[13] = (string)($f['severity'] ?? '');
            $frow[16] = (string)($f['published'] ?? '');
            $frow[31] = (string)($f['description'] ?? '');
            fputcsv($out, $frow);
        }
    }
}

fclose($out);
exit;
