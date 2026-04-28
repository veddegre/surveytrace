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
 *   findings — 1 = include findings rows in CSV (default: 0)
 */

require_once __DIR__ . '/db.php';
st_auth();
st_method('GET');

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

$where_sql = implode(' AND ', $where);

$stmt = $db->prepare("
    SELECT
        a.ip, a.device_id, a.hostname, a.mac, a.mac_vendor, a.category,
        a.vendor, a.model, a.os_guess, a.cpe,
        a.open_ports, a.top_cve, a.top_cvss,
        (SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id AND f.resolved = 0) AS open_findings,
        a.first_seen, a.last_seen, a.notes
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

// Asset header row
fputcsv($out, [
    'IP Address', 'Device ID', 'Hostname', 'MAC', 'MAC Vendor', 'Category',
    'Vendor', 'Model', 'OS Guess', 'CPE',
    'Open Ports', 'Top CVE', 'Top CVSS', 'Severity',
    'Open Findings', 'First Seen', 'Last Seen', 'Notes',
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
        $a['first_seen'] ?? '',
        $a['last_seen'] ?? '',
        $a['notes'] ?? '',
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
            fputcsv($out, [
                '',                  // IP (blank — belongs to asset above)
                '',                  // Device ID
                '',                  // Hostname
                '', '', '',          // MAC, MAC Vendor, Category
                '',                  // Vendor
                '',                  // Model
                '',                  // OS
                '',                  // CPE
                '',                  // Open Ports
                $f['cve_id'],        // Top CVE → CVE ID
                $f['cvss'] ?? '',    // CVSS
                $f['severity'] ?? '',
                '',                  // Open Findings count
                '',                  // First Seen
                $f['published'] ?? '',  // Last Seen → Published date
                $f['description'] ?? '', // Notes → Description
            ]);
        }
    }
}

fclose($out);
exit;
