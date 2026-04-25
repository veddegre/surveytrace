<?php
/**
 * SurveyTrace — GET /api/findings.php
 *
 * Returns CVE findings with rich filtering.
 * Also supports POST to mark findings resolved/unresolved.
 *
 * GET query params:
 *   asset_id  — filter by asset
 *   ip        — filter by IP string
 *   category  — filter by asset category
 *   severity  — critical|high|medium|low
 *   cve_id    — search by CVE ID substring
 *   resolved  — 0 (default) or 1
 *   sort      — cvss|severity|published|confirmed_at|ip|cve_id (default: cvss)
 *   order     — asc|desc (default: desc)
 *   page, per_page
 *
 * Response:
 * {
 *   "total": N, "page": N, "pages": N,
 *   "severity_counts": {"critical": N, "high": N, "medium": N, "low": N},
 *   "findings": [{
 *     "id", "asset_id", "ip", "cve_id", "cvss", "severity",
 *     "description", "published", "confirmed_at", "resolved", "notes",
 *     "hostname", "vendor", "category"   ← joined from assets
 *   }]
 * }
 *
 * POST body:
 * {"action": "resolve",   "finding_id": N, "notes": "patched"}
 * {"action": "unresolve", "finding_id": N}
 * {"action": "resolve_all", "asset_id": N}
 */

require_once __DIR__ . '/db.php';
st_auth();

$db = st_db();

// ---------------------------------------------------------------------------
// POST — resolve / unresolve
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body      = st_input();
    $action    = st_str('action', '', ['resolve','unresolve','resolve_all']);
    if (empty($action)) $action = trim((string)($body['action'] ?? ''));

    switch ($action) {
        case 'resolve':
            $fid   = (int)($body['finding_id'] ?? 0);
            $notes = substr(trim((string)($body['notes'] ?? '')), 0, 500);
            if (!$fid) st_json(['error' => 'finding_id required'], 400);
            $db->prepare("UPDATE findings SET resolved=1, notes=? WHERE id=?")->execute([$notes, $fid]);
            st_json(['ok' => true, 'finding_id' => $fid, 'resolved' => true]);

        case 'unresolve':
            $fid = (int)($body['finding_id'] ?? 0);
            if (!$fid) st_json(['error' => 'finding_id required'], 400);
            $db->prepare("UPDATE findings SET resolved=0 WHERE id=?")->execute([$fid]);
            st_json(['ok' => true, 'finding_id' => $fid, 'resolved' => false]);

        case 'resolve_all':
            $aid   = (int)($body['asset_id'] ?? 0);
            $notes = substr(trim((string)($body['notes'] ?? 'bulk resolved')), 0, 500);
            if (!$aid) st_json(['error' => 'asset_id required'], 400);
            $db->prepare("UPDATE findings SET resolved=1, notes=? WHERE asset_id=?")->execute([$notes, $aid]);
            $count = $db->query("SELECT changes()")->fetchColumn();
            st_json(['ok' => true, 'asset_id' => $aid, 'resolved_count' => (int)$count]);

        default:
            st_json(['error' => 'Unknown action. Use: resolve, unresolve, resolve_all'], 400);
    }
}

st_method('GET');

// ---------------------------------------------------------------------------
// Build WHERE clause
// ---------------------------------------------------------------------------
$asset_id = st_int('asset_id');
$ip_filter= st_str('ip');
$category = st_str('category');
$severity = st_str('severity', '', ['','critical','high','medium','low']);
$cve_srch = st_str('cve_id');
$resolved = st_int('resolved', 0, 0, 1);
$min_year = isset($_GET['min_year']) ? (int)$_GET['min_year'] : 0;
$page     = st_int('page',     1,  1);
$per_page = st_int('per_page', 50, 1, 200);
$offset   = ($page - 1) * $per_page;

$valid_sorts = ['cvss','severity','published','confirmed_at','ip','cve_id'];
$sort_col    = st_str('sort', 'cvss', $valid_sorts);
$sort_order  = st_str('order', 'desc', ['asc','desc']) === 'asc' ? 'ASC' : 'DESC';

$sev_cvss = [
    'critical' => [9.0, 10.1],
    'high'     => [7.0,  9.0],
    'medium'   => [4.0,  7.0],
    'low'      => [0.1,  4.0],
];

$where  = ['f.resolved = :resolved'];
$params = [':resolved' => $resolved];

if ($asset_id > 0) {
    $where[]         = 'f.asset_id = :aid';
    $params[':aid']  = $asset_id;
}

if ($ip_filter !== '') {
    // Exact match if input looks like a full IP, otherwise prefix with dot boundary
    // This prevents 192.168.86.1 matching 192.168.86.18 and 192.168.86.185
    if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $ip_filter)) {
        // Full IP — exact match only
        $where[]       = 'f.ip = :ip';
        $params[':ip'] = $ip_filter;
    } else {
        // Partial — match as prefix with trailing dot to avoid partial octet matches
        $where[]       = "(f.ip = :ip OR f.ip LIKE :ip_prefix)";
        $params[':ip'] = $ip_filter;
        $params[':ip_prefix'] = rtrim($ip_filter, '.') . '.%';
    }
}

if ($category !== '') {
    $where[]         = 'a.category = :cat';
    $params[':cat']  = $category;
}

if ($severity !== '' && isset($sev_cvss[$severity])) {
    [$lo, $hi]       = $sev_cvss[$severity];
    $where[]         = 'f.cvss >= :slo AND f.cvss < :shi';
    $params[':slo']  = $lo;
    $params[':shi']  = $hi;
}

if ($cve_srch !== '') {
    $where[]         = "(f.cve_id LIKE :cve OR f.description LIKE :cve)";
    $params[':cve']  = '%' . $cve_srch . '%';
}

if ($min_year > 0) {
    $where[]          = "CAST(substr(f.published, 1, 4) AS INTEGER) >= :miny";
    $params[':miny']  = $min_year;
}

$where_sql = implode(' AND ', $where);

// ---------------------------------------------------------------------------
// Severity counts (for the UI filter badges, ignoring current severity filter)
// ---------------------------------------------------------------------------
$base_where  = str_replace('f.cvss >= :slo AND f.cvss < :shi', '1=1', $where_sql);
$base_params = array_diff_key($params, [':slo' => 1, ':shi' => 1]);

$sev_count_sql = "
    SELECT
        SUM(CASE WHEN f.cvss >= 9.0 THEN 1 ELSE 0 END)              AS critical,
        SUM(CASE WHEN f.cvss >= 7.0 AND f.cvss < 9.0 THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN f.cvss >= 4.0 AND f.cvss < 7.0 THEN 1 ELSE 0 END) AS medium,
        SUM(CASE WHEN f.cvss > 0    AND f.cvss < 4.0 THEN 1 ELSE 0 END) AS low
    FROM findings f
    JOIN assets a ON a.id = f.asset_id
    WHERE $base_where
";
$sev_stmt = $db->prepare($sev_count_sql);
$sev_stmt->execute($base_params);
$sev_counts = $sev_stmt->fetch();
$sev_counts = array_map('intval', $sev_counts ?: []);

// ---------------------------------------------------------------------------
// Count + rows
// ---------------------------------------------------------------------------
$count_sql = "SELECT COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id WHERE $where_sql";
$cstmt     = $db->prepare($count_sql);
$cstmt->execute($params);
$total = (int)$cstmt->fetchColumn();

$sql = "
    SELECT
        f.id, f.asset_id, f.ip, f.cve_id, f.cvss, f.severity,
        f.description, f.published, f.confirmed_at, f.resolved, f.notes,
        a.hostname, a.vendor, a.model, a.category, a.cpe
    FROM findings f
    JOIN assets a ON a.id = f.asset_id
    WHERE $where_sql
    ORDER BY f.$sort_col $sort_order
    LIMIT :lim OFFSET :off
";

$stmt = $db->prepare($sql);
foreach ($params as $k => $v) $stmt->bindValue($k, $v);
$stmt->bindValue(':lim', $per_page, PDO::PARAM_INT);
$stmt->bindValue(':off', $offset,   PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll();

// Ensure numeric types
foreach ($rows as &$r) {
    $r['cvss']     = $r['cvss'] ? (float)$r['cvss'] : null;
    $r['resolved'] = (bool)$r['resolved'];
    if (empty($r['severity']) && $r['cvss']) {
        $r['severity'] = st_severity($r['cvss']);
    }
}
unset($r);

st_json([
    'total'           => $total,
    'page'            => $page,
    'per_page'        => $per_page,
    'pages'           => (int)ceil(max(1, $total) / $per_page),
    'severity_counts' => $sev_counts,
    'findings'        => $rows,
]);
