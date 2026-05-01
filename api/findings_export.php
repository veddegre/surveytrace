<?php
/**
 * SurveyTrace — GET /api/findings_export.php
 *
 * Exports CVE findings with the same filters as the Vulnerabilities tab.
 *
 * Query params (all optional):
 *   format    — csv | json (default: csv)
 *   cve_id    — search CVE ID or description
 *   ip        — exact IP or prefix match
 *   severity  — critical | high | medium | low
 *   category  — srv | ws | net | iot | ot | voi | prn | hv
 *   resolved  — 0 (open) | 1 (resolved) | '' (all)
 *   min_year  — minimum CVE publication year (e.g. 2015)
 *   confidence — high|medium|low (Phase 10)
 */

require_once __DIR__ . '/db.php';
st_auth();
st_require_role(['viewer', 'scan_editor', 'admin']);
st_method('GET');

$db     = st_db();
$format = st_str('format', 'csv', ['csv', 'json']);

// --- Filters (mirrors findings.php) ---------------------------------------
$cve_srch = st_str('cve_id');
$ip_filter= st_str('ip');
$severity = st_str('severity', '', ['','critical','high','medium','low']);
$category = st_str('category');
$resolved = st_str('resolved', '');   // '' = all, '0' = open, '1' = resolved
$min_year = (int)(st_str('min_year') ?: 0);
$confidence = st_str('confidence', '', ['', 'high', 'medium', 'low']);

// --- Build WHERE ----------------------------------------------------------
$where  = ['1=1'];
$params = [];

if ($cve_srch !== '') {
    $where[]       = "(f.cve_id LIKE :cve OR f.description LIKE :cve)";
    $params[':cve'] = '%' . $cve_srch . '%';
}

if ($ip_filter !== '') {
    if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $ip_filter)) {
        $where[]      = 'f.ip = :ip';
        $params[':ip'] = $ip_filter;
    } else {
        $where[]      = "(f.ip = :ip OR f.ip LIKE :ip_prefix)";
        $params[':ip']        = $ip_filter;
        $params[':ip_prefix'] = rtrim($ip_filter, '.') . '.%';
    }
}

$sev_map = [
    'critical' => [9.0, 10.1],
    'high'     => [7.0,  9.0],
    'medium'   => [4.0,  7.0],
    'low'      => [0.0,  4.0],
];
if ($severity !== '' && isset($sev_map[$severity])) {
    [$lo, $hi]      = $sev_map[$severity];
    $where[]        = 'f.cvss >= :slo AND f.cvss < :shi';
    $params[':slo'] = $lo;
    $params[':shi'] = $hi;
}

if ($category !== '') {
    $where[]         = 'a.category = :cat';
    $params[':cat']  = $category;
}

if ($resolved !== '') {
    $where[]          = 'f.resolved = :res';
    $params[':res']   = (int)$resolved;
}

if ($min_year > 0) {
    $where[]          = "CAST(substr(f.published,1,4) AS INTEGER) >= :miny";
    $params[':miny']  = $min_year;
}

if ($confidence !== '') {
    $where[] = "COALESCE(NULLIF(TRIM(f.confidence), ''), 'low') = :conf";
    $params[':conf'] = $confidence;
}

$where_sql = implode(' AND ', $where);

$stmt = $db->prepare("
    SELECT
        f.id, f.cve_id, f.ip, a.hostname, a.category, a.vendor,
        f.cvss, f.severity, f.description, f.published, f.resolved,
        a.cpe,
        COALESCE(NULLIF(TRIM(f.provenance_source), ''), 'unknown') AS provenance_source,
        f.detection_method,
        COALESCE(NULLIF(TRIM(f.confidence), ''), 'low') AS confidence,
        f.risk_score,
        f.evidence_json,
        COALESCE(ci.kev, 0) AS intel_kev,
        ci.epss AS intel_epss,
        ci.epss_percentile AS intel_epss_percentile,
        ci.osv_ecosystems AS intel_osv_ecosystems
    FROM findings f
    LEFT JOIN assets a ON a.id = f.asset_id
    LEFT JOIN cve_intel ci ON ci.cve_id = f.cve_id
    WHERE $where_sql
    ORDER BY f.cvss DESC, f.cve_id ASC
");
$stmt->execute($params);
$rows = $stmt->fetchAll();

$timestamp = date('Y-m-d_H-i-s');

// --- JSON -----------------------------------------------------------------
if ($format === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    header("Content-Disposition: attachment; filename=\"surveytrace_cves_{$timestamp}.json\"");
    header('Cache-Control: no-store');
    echo json_encode([
        'exported_at'    => date('c'),
        'total_findings' => count($rows),
        'filters'        => [
            'cve_id'   => $cve_srch  ?: null,
            'ip'       => $ip_filter ?: null,
            'severity' => $severity  ?: null,
            'category' => $category  ?: null,
            'resolved' => $resolved !== '' ? (bool)(int)$resolved : null,
            'min_year' => $min_year  ?: null,
            'confidence' => $confidence ?: null,
        ],
        'findings' => array_map(function($r) {
            $ev = [];
            if (!empty($r['evidence_json'])) {
                $dec = json_decode((string)$r['evidence_json'], true);
                $ev = is_array($dec) ? $dec : [];
            }
            $osv = [];
            if (!empty($r['intel_osv_ecosystems'])) {
                $ox = json_decode((string)$r['intel_osv_ecosystems'], true);
                $osv = is_array($ox) ? $ox : [];
            }
            return [
                'cve_id'      => $r['cve_id'],
                'ip'          => $r['ip'],
                'hostname'    => $r['hostname'] ?? '',
                'category'    => $r['category'] ?? '',
                'vendor'      => $r['vendor']   ?? '',
                'cpe'         => $r['cpe']       ?? '',
                'cvss'        => $r['cvss']      ? (float)$r['cvss'] : null,
                'severity'    => $r['severity']  ?? '',
                'description' => $r['description'] ?? '',
                'published'   => $r['published'] ?? '',
                'resolved'    => (bool)$r['resolved'],
                'provenance_source' => $r['provenance_source'] ?? 'unknown',
                'detection_method' => $r['detection_method'] ?? '',
                'confidence'  => $r['confidence'] ?? 'low',
                'risk_score'  => isset($r['risk_score']) && $r['risk_score'] !== null && $r['risk_score'] !== ''
                    ? (float)$r['risk_score'] : null,
                'evidence'    => $ev,
                'kev'         => !empty($r['intel_kev']) && (int)$r['intel_kev'] === 1,
                'epss'        => isset($r['intel_epss']) && $r['intel_epss'] !== null && $r['intel_epss'] !== ''
                    ? (float)$r['intel_epss'] : null,
                'epss_percentile' => isset($r['intel_epss_percentile']) && $r['intel_epss_percentile'] !== null && $r['intel_epss_percentile'] !== ''
                    ? (float)$r['intel_epss_percentile'] : null,
                'osv_ecosystems' => $osv,
            ];
        }, $rows),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// --- CSV ------------------------------------------------------------------
header('Content-Type: text/csv; charset=utf-8');
header("Content-Disposition: attachment; filename=\"surveytrace_cves_{$timestamp}.csv\"");
header('Cache-Control: no-store');

$out = fopen('php://output', 'w');
fwrite($out, "\xEF\xBB\xBF");  // UTF-8 BOM for Excel

fputcsv($out, [
    'CVE ID', 'IP Address', 'Hostname', 'Type', 'Vendor', 'CPE',
    'CVSS', 'Severity', 'Published', 'Resolved',
    'Provenance', 'Detection method', 'Confidence', 'Risk score', 'Evidence JSON',
    'CISA KEV', 'EPSS', 'EPSS percentile', 'OSV ecosystems JSON',
    'Description',
]);

foreach ($rows as $r) {
    fputcsv($out, [
        $r['cve_id']      ?? '',
        $r['ip']          ?? '',
        $r['hostname']    ?? '',
        $r['category']    ?? '',
        $r['vendor']      ?? '',
        $r['cpe']         ?? '',
        $r['cvss']        ?? '',
        $r['severity']    ?? '',
        $r['published']   ?? '',
        $r['resolved']    ? 'Yes' : 'No',
        $r['provenance_source'] ?? '',
        $r['detection_method'] ?? '',
        $r['confidence'] ?? '',
        $r['risk_score'] ?? '',
        $r['evidence_json'] ?? '',
        !empty($r['intel_kev']) && (int)$r['intel_kev'] === 1 ? 'Yes' : '',
        $r['intel_epss'] ?? '',
        $r['intel_epss_percentile'] ?? '',
        $r['intel_osv_ecosystems'] ?? '',
        $r['description'] ?? '',
    ]);
}

fclose($out);
exit;
