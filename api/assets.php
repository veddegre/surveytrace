<?php
/**
 * SurveyTrace — GET /api/assets.php
 *
 * Returns the full asset inventory with filtering, sorting, and pagination.
 * Also supports PUT to update asset metadata (category override, notes).
 *
 * GET query params:
 *   q          — free-text search across ip, hostname, vendor, model, mac
 *   category   — srv|ws|net|iot|ot|voi|prn|hv|unk
 *   severity   — critical|high|medium|low|none
 *   port       — filter assets with this port open (integer)
 *   since_days — only assets seen in last N days
 *   new_only   — "1" = only assets first seen in last 24h
 *   sort       — ip|hostname|category|top_cvss|last_seen|first_seen|vendor (default: ip)
 *   order      — asc|desc (default: asc)
 *   page       — 1-based (default: 1)
 *   per_page   — 1–200 (default: 50)
 *   id         — fetch a single asset by ID (returns full detail with findings)
 *
 * Response (list):
 * {
 *   "total": 187, "page": 1, "pages": 4, "per_page": 50,
 *   "assets": [{
 *     "id", "device_id", "ip", "hostname", "mac", "mac_vendor", "category",
 *     "vendor", "model", "os_guess", "cpe",
 *     "open_ports",     // decoded array
 *     "banners",        // decoded object
 *     "top_cve", "top_cvss", "severity",
 *     "open_findings",  // count of unresolved CVEs
 *     "first_seen", "last_seen", "notes"
 *   }]
 * }
 *
 * Single asset (?id=N) adds:
 *   "findings": [{cve_id, cvss, severity, description, published, resolved}]
 *   "port_history": [{ports, seen_at}]
 */

require_once __DIR__ . '/db.php';
st_auth();

// ---------------------------------------------------------------------------
// PUT — update asset metadata (category, hostname, notes)
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    $body     = st_input();
    $asset_id = st_int('id', 0, 1);
    if (!$asset_id) st_json(['error' => 'id required for PUT'], 400);

    $allowed_cats = ['srv','ws','net','iot','ot','voi','prn','hv','unk'];
    $updates = [];
    $params  = [];

    if (isset($body['category']) && in_array($body['category'], $allowed_cats, true)) {
        $updates[]           = 'category = :cat';
        $params[':cat']      = $body['category'];
    }
    if (isset($body['hostname'])) {
        $updates[]           = 'hostname = :host';
        $params[':host']     = substr(trim($body['hostname']), 0, 253);
    }
    if (isset($body['notes'])) {
        $updates[]           = 'notes = :notes';
        $params[':notes']    = substr(trim($body['notes']), 0, 2000);
    }
    if (isset($body['vendor'])) {
        $updates[]           = 'vendor = :vendor';
        $params[':vendor']   = substr(trim($body['vendor']), 0, 200);
    }

    if (empty($updates)) st_json(['error' => 'No updatable fields provided'], 400);

    $params[':id'] = $asset_id;
    st_db()->prepare("UPDATE assets SET " . implode(', ', $updates) . " WHERE id = :id")
           ->execute($params);

    $row = st_db()->prepare("SELECT * FROM assets WHERE id = ?")->execute([$asset_id])
        ? st_db()->prepare("SELECT * FROM assets WHERE id = ?")->execute([$asset_id]) && false
        : null;

    $stmt = st_db()->prepare("SELECT * FROM assets WHERE id = ?");
    $stmt->execute([$asset_id]);
    $asset = $stmt->fetch();
    if (!$asset) st_json(['error' => 'Asset not found'], 404);

    st_json(['ok' => true, 'asset' => decode_asset($asset)]);
}

st_method('GET');

$db = st_db();

// ---------------------------------------------------------------------------
// Single asset detail
// ---------------------------------------------------------------------------
$single_id = st_int('id');
if ($single_id > 0) {
    $stmt = $db->prepare("SELECT * FROM assets WHERE id = ?");
    $stmt->execute([$single_id]);
    $asset = $stmt->fetch();
    if (!$asset) st_json(['error' => 'Asset not found'], 404);

    $asset = decode_asset($asset);

    // Findings for this asset
    $fstmt = $db->prepare("
        SELECT cve_id, cvss, severity, description, published, confirmed_at, resolved, notes
        FROM findings
        WHERE asset_id = ?
        ORDER BY cvss DESC, cve_id
    ");
    $fstmt->execute([$single_id]);
    $asset['findings'] = $fstmt->fetchAll();

    // Port history (last 20 snapshots)
    $phstmt = $db->prepare("
        SELECT ports, seen_at FROM port_history
        WHERE asset_id = ?
        ORDER BY seen_at DESC LIMIT 20
    ");
    $phstmt->execute([$single_id]);
    $asset['port_history'] = array_map(function($r) {
        $r['ports'] = json_decode($r['ports'] ?? '[]', true) ?: [];
        return $r;
    }, $phstmt->fetchAll());

    st_json(['asset' => $asset]);
}

// ---------------------------------------------------------------------------
// List mode — build WHERE clause
// ---------------------------------------------------------------------------
$q          = st_str('q');
$category   = st_str('category', '', ['','srv','ws','net','iot','ot','voi','prn','hv','unk']);
$severity   = st_str('severity', '', ['','critical','high','medium','low','none']);
$port_filter= st_int('port');
$since_days = st_int('since_days');
$new_only   = st_str('new_only') === '1';
$page       = st_int('page',     1,  1);
$per_page   = st_int('per_page', 50, 1, 200);
$offset     = ($page - 1) * $per_page;

$valid_sorts = ['ip','hostname','category','top_cvss','last_seen','first_seen','vendor','open_findings'];
$sort_col    = st_str('sort', 'ip', $valid_sorts);
$sort_order  = st_str('order', 'asc', ['asc','desc']) === 'desc' ? 'DESC' : 'ASC';

// Severity → CVSS range map
$sev_ranges = [
    'critical' => [9.0, 10.1],
    'high'     => [7.0,  9.0],
    'medium'   => [4.0,  7.0],
    'low'      => [0.1,  4.0],
];

$where  = ['1=1'];
$params = [];

if ($q !== '') {
    $where[]      = "(a.ip LIKE :q OR a.hostname LIKE :q OR a.vendor LIKE :q OR a.model LIKE :q OR a.mac LIKE :q OR a.cpe LIKE :q)";
    $params[':q'] = '%' . $q . '%';
}

if ($category !== '') {
    $where[]         = 'a.category = :cat';
    $params[':cat']  = $category;
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

if ($port_filter > 0) {
    // open_ports is JSON array — use LIKE as a simple substring match
    $where[]          = "a.open_ports LIKE :port";
    $params[':port']  = '%' . $port_filter . '%';
}

if ($since_days > 0) {
    $where[]          = "a.last_seen >= datetime('now', :days)";
    $params[':days']  = "-{$since_days} days";
}

if ($new_only) {
    $where[]          = "a.first_seen >= datetime('now', '-1 day')";
}

$where_sql = implode(' AND ', $where);

// For open_findings sort, we need the subquery in ORDER BY
$findings_subq = "(SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id AND f.resolved = 0)";

// Numeric IP sort — split into 4 integer octets, no REVERSE() needed
// Works by progressively stripping octets from left
$o1 = "CAST(substr(a.ip, 1, instr(a.ip,'.')-1) AS INTEGER)";
$s2 = "substr(a.ip, instr(a.ip,'.')+1)";
$o2 = "CAST(substr($s2, 1, instr($s2,'.')-1) AS INTEGER)";
$s3 = "substr($s2, instr($s2,'.')+1)";
$o3 = "CAST(substr($s3, 1, instr($s3,'.')-1) AS INTEGER)";
$o4 = "CAST(substr($s3, instr($s3,'.')+1) AS INTEGER)";
$ip_sort = "$o1 $sort_order, $o2 $sort_order, $o3 $sort_order, $o4 $sort_order";

$order_expr = match($sort_col) {
    'ip'            => $ip_sort,
    'top_cvss'      => "a.top_cvss $sort_order NULLS LAST",
    'open_findings' => "$findings_subq $sort_order",
    default         => "a.$sort_col $sort_order",
};

// ---------------------------------------------------------------------------
// Count
// ---------------------------------------------------------------------------
$count_stmt = $db->prepare("SELECT COUNT(*) FROM assets a WHERE $where_sql");
$count_stmt->execute($params);
$total = (int)$count_stmt->fetchColumn();

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------
$sql = "
    SELECT
        a.*,
        $findings_subq AS open_findings
    FROM assets a
    WHERE $where_sql
    ORDER BY $order_expr
    LIMIT :lim OFFSET :off
";

$stmt = $db->prepare($sql);
foreach ($params as $k => $v) $stmt->bindValue($k, $v);
$stmt->bindValue(':lim', $per_page, PDO::PARAM_INT);
$stmt->bindValue(':off', $offset,   PDO::PARAM_INT);
$stmt->execute();
$rows = array_map('decode_asset', $stmt->fetchAll());

// ---------------------------------------------------------------------------
// Category breakdown counts (for UI filter badges)
// ---------------------------------------------------------------------------
$cat_counts_raw = $db->query("SELECT category, COUNT(*) AS cnt FROM assets GROUP BY category")->fetchAll();
$cat_counts = [];
foreach ($cat_counts_raw as $r) $cat_counts[$r['category']] = (int)$r['cnt'];

st_json([
    'total'      => $total,
    'page'       => $page,
    'per_page'   => $per_page,
    'pages'      => (int)ceil(max(1, $total) / $per_page),
    'cat_counts' => $cat_counts,
    'assets'     => $rows,
]);

// ---------------------------------------------------------------------------
// Helper: decode JSON columns and add derived fields
// ---------------------------------------------------------------------------
function decode_asset(array $a): array {
    if (isset($a['device_id']) && $a['device_id'] !== null && $a['device_id'] !== '') {
        $a['device_id'] = (int)$a['device_id'];
    }
    $a['open_ports']    = json_decode($a['open_ports'] ?? '[]', true) ?: [];
    $a['banners']       = json_decode($a['banners']    ?? '{}', true) ?: [];
    $a['discovery_sources'] = json_decode($a['discovery_sources'] ?? '[]', true) ?: [];
    $a['open_findings'] = (int)($a['open_findings'] ?? 0);
    $a['top_cvss']      = $a['top_cvss'] ? (float)$a['top_cvss'] : null;
    $a['severity']      = $a['top_cvss'] ? st_severity($a['top_cvss']) : 'none';
    return $a;
}
