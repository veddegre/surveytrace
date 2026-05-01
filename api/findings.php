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
 *   lifecycle — optional lifecycle_state filter
 *   confidence — high|medium|low (Phase 10 triage)
 *   sort      — cvss|severity|published|confirmed_at|ip|cve_id|risk_score (default: cvss)
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
 *     "provenance_source", "detection_method", "confidence", "risk_score", "evidence" (object)
 *   }]
 * }
 *
 * POST body:
 * {"action": "resolve",   "finding_id": N, "notes": "patched"}
 * {"action": "unresolve", "finding_id": N}
 * {"action": "resolve_all", "asset_id": N}
 * {"action": "accept_risk", "finding_id": N} — lifecycle accepted (excluded from open list)
 */

require_once __DIR__ . '/db.php';
st_auth();
st_require_role(['viewer', 'scan_editor', 'admin']);

/**
 * Dismiss open Phase-9 change alerts tied to specific findings (UI noise vs. risk acceptance).
 */
function st_dismiss_open_change_alerts_for_finding_ids(PDO $db, array $findingIds, ?int $actorUserId): void {
    $findingIds = array_values(array_unique(array_filter(array_map('intval', $findingIds), static function ($x) {
        return $x > 0;
    })));
    if ($findingIds === []) {
        return;
    }
    $ph = implode(',', array_fill(0, count($findingIds), '?'));
    $sql = "UPDATE change_alerts SET dismissed_at = datetime('now'), dismissed_by_user_id = ? WHERE dismissed_at IS NULL AND finding_id IN ($ph)";
    $params = array_merge([$actorUserId], $findingIds);
    try {
        $db->prepare($sql)->execute($params);
    } catch (Throwable $e) {
        // change_alerts missing on straggler installs until migration runs
    }
}

function st_refresh_asset_top_cve(PDO $db, int $assetId): void {
    if ($assetId <= 0) {
        return;
    }
    $db->prepare(
        "UPDATE assets SET
            top_cve = (SELECT cve_id FROM findings WHERE asset_id = assets.id AND resolved = 0 ORDER BY cvss DESC LIMIT 1),
            top_cvss = (SELECT cvss FROM findings WHERE asset_id = assets.id AND resolved = 0 ORDER BY cvss DESC LIMIT 1)
         WHERE id = ?"
    )->execute([$assetId]);
}

$db = st_db();

// ---------------------------------------------------------------------------
// POST — resolve / unresolve
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    st_method('POST');
    st_require_role(['scan_editor', 'admin']);
    $body      = st_input();
    $action    = st_str('action', '', ['resolve','unresolve','resolve_all','accept_risk']);
    if (empty($action)) $action = trim((string)($body['action'] ?? ''));

    switch ($action) {
        case 'resolve':
            $fid   = (int)($body['finding_id'] ?? 0);
            $notes = substr(trim((string)($body['notes'] ?? '')), 0, 500);
            if (!$fid) st_json(['error' => 'finding_id required'], 400);
            $actor = st_current_user();
            $uidDismiss = (int)($actor['id'] ?? 0) > 0 ? (int)$actor['id'] : null;
            $db->prepare(
                "UPDATE findings SET resolved=1, notes=?, lifecycle_state='mitigated', mitigated_at=datetime('now'),
                 accepted_at=NULL, accepted_by_user_id=NULL WHERE id=?"
            )->execute([$notes, $fid]);
            st_dismiss_open_change_alerts_for_finding_ids($db, [$fid], $uidDismiss);
            $aRow = $db->prepare("SELECT asset_id FROM findings WHERE id = ?");
            $aRow->execute([$fid]);
            $aidTop = (int)($aRow->fetchColumn());
            st_refresh_asset_top_cve($db, $aidTop);
            st_json(['ok' => true, 'finding_id' => $fid, 'resolved' => true, 'lifecycle_state' => 'mitigated']);

        case 'unresolve':
            $fid = (int)($body['finding_id'] ?? 0);
            if (!$fid) st_json(['error' => 'finding_id required'], 400);
            $db->prepare(
                "UPDATE findings SET resolved=0, lifecycle_state='active', mitigated_at=NULL,
                 accepted_at=NULL, accepted_by_user_id=NULL WHERE id=?"
            )->execute([$fid]);
            $aRow = $db->prepare("SELECT asset_id FROM findings WHERE id = ?");
            $aRow->execute([$fid]);
            $aidTop = (int)($aRow->fetchColumn());
            st_refresh_asset_top_cve($db, $aidTop);
            st_json(['ok' => true, 'finding_id' => $fid, 'resolved' => false, 'lifecycle_state' => 'active']);

        case 'resolve_all':
            $aid   = (int)($body['asset_id'] ?? 0);
            $notes = substr(trim((string)($body['notes'] ?? 'bulk resolved')), 0, 500);
            if (!$aid) st_json(['error' => 'asset_id required'], 400);
            $actor = st_current_user();
            $uidDismiss = (int)($actor['id'] ?? 0) > 0 ? (int)$actor['id'] : null;
            $idsStmt = $db->prepare("SELECT id FROM findings WHERE asset_id = ? AND resolved = 0");
            $idsStmt->execute([$aid]);
            $fids = $idsStmt->fetchAll(PDO::FETCH_COLUMN);
            $fids = is_array($fids) ? array_map('intval', $fids) : [];
            st_dismiss_open_change_alerts_for_finding_ids($db, $fids, $uidDismiss);
            $db->prepare(
                "UPDATE findings SET resolved=1, notes=?, lifecycle_state='mitigated', mitigated_at=datetime('now'),
                 accepted_at=NULL, accepted_by_user_id=NULL WHERE asset_id=? AND resolved=0"
            )->execute([$notes, $aid]);
            $count = $db->query("SELECT changes()")->fetchColumn();
            st_refresh_asset_top_cve($db, $aid);
            st_json(['ok' => true, 'asset_id' => $aid, 'resolved_count' => (int)$count]);

        case 'accept_risk':
            $fid = (int)($body['finding_id'] ?? 0);
            if (!$fid) st_json(['error' => 'finding_id required'], 400);
            $actor = st_current_user();
            $uid = (int)($actor['id'] ?? 0);
            $uidBind = $uid > 0 ? $uid : null;
            $db->prepare(
                "UPDATE findings SET lifecycle_state='accepted', accepted_at=datetime('now'), accepted_by_user_id=?,
                 resolved=1, mitigated_at=NULL WHERE id=?"
            )->execute([$uidBind, $fid]);
            st_dismiss_open_change_alerts_for_finding_ids($db, [$fid], $uidBind);
            $aRow = $db->prepare("SELECT asset_id FROM findings WHERE id = ?");
            $aRow->execute([$fid]);
            $aidTop = (int)($aRow->fetchColumn());
            st_refresh_asset_top_cve($db, $aidTop);
            st_json(['ok' => true, 'finding_id' => $fid, 'lifecycle_state' => 'accepted']);

        default:
            st_json(['error' => 'Unknown action. Use: resolve, unresolve, resolve_all, accept_risk'], 400);
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
$lifecycle = st_str('lifecycle', '', ['', 'new', 'active', 'mitigated', 'accepted', 'reopened']);
$confidence = st_str('confidence', '', ['', 'high', 'medium', 'low']);
$min_year = isset($_GET['min_year']) ? (int)$_GET['min_year'] : 0;
$page     = st_int('page',     1,  1);
$per_page = st_int('per_page', 50, 1, 200);
$offset   = ($page - 1) * $per_page;

$valid_sorts = ['cvss','severity','published','confirmed_at','ip','cve_id','risk_score'];
$sort_col    = st_str('sort', 'cvss', $valid_sorts);
$sort_order  = st_str('order', 'desc', ['asc','desc']) === 'asc' ? 'ASC' : 'DESC';
$sort_sql_map = [
    'cvss' => 'f.cvss',
    'severity' => 'f.severity',
    'published' => 'f.published',
    'confirmed_at' => 'f.confirmed_at',
    'ip' => 'f.ip',
    'cve_id' => 'f.cve_id',
    'risk_score' => 'COALESCE(f.risk_score, -1)',
];
$sort_sql = $sort_sql_map[$sort_col] ?? 'f.cvss';

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

if ($lifecycle !== '') {
    $where[] = "COALESCE(f.lifecycle_state, 'active') = :lcs";
    $params[':lcs'] = $lifecycle;
}

if ($confidence !== '') {
    $where[] = "COALESCE(NULLIF(TRIM(f.confidence), ''), 'low') = :conf";
    $params[':conf'] = $confidence;
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
$count_sql = "SELECT COUNT(*) FROM findings f JOIN assets a ON a.id = f.asset_id
    LEFT JOIN cve_intel ci ON ci.cve_id = f.cve_id WHERE $where_sql";
$cstmt     = $db->prepare($count_sql);
$cstmt->execute($params);
$total = (int)$cstmt->fetchColumn();

$sql = "
    SELECT
        f.id, f.asset_id, f.ip, f.cve_id, f.cvss, f.severity,
        f.description, f.published, f.confirmed_at, f.resolved, f.notes,
        COALESCE(f.lifecycle_state, 'active') AS lifecycle_state,
        f.mitigated_at, f.accepted_at, f.accepted_by_user_id,
        f.first_seen_job_id, f.last_seen_job_id,
        COALESCE(NULLIF(TRIM(f.provenance_source), ''), 'unknown') AS provenance_source,
        f.detection_method,
        COALESCE(NULLIF(TRIM(f.confidence), ''), 'low') AS confidence,
        f.risk_score,
        f.evidence_json,
        COALESCE(ci.kev, 0) AS _intel_kev,
        ci.kev_date_added AS _intel_kev_date_added,
        ci.kev_due_date AS _intel_kev_due_date,
        ci.kev_vendor AS _intel_kev_vendor,
        ci.kev_product AS _intel_kev_product,
        ci.epss AS _intel_epss,
        ci.epss_percentile AS _intel_epss_percentile,
        ci.epss_scored_at AS _intel_epss_scored_at,
        ci.osv_ecosystems AS _intel_osv_ecosystems,
        a.hostname, a.vendor, a.model, a.category, a.cpe
    FROM findings f
    JOIN assets a ON a.id = f.asset_id
    LEFT JOIN cve_intel ci ON ci.cve_id = f.cve_id
    WHERE $where_sql
    ORDER BY $sort_sql $sort_order
    LIMIT :lim OFFSET :off
";

$stmt = $db->prepare($sql);
foreach ($params as $k => $v) $stmt->bindValue($k, $v);
$stmt->bindValue(':lim', $per_page, PDO::PARAM_INT);
$stmt->bindValue(':off', $offset,   PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll();

// Ensure numeric types + Phase 10 evidence object
foreach ($rows as &$r) {
    $r['cvss']     = $r['cvss'] ? (float)$r['cvss'] : null;
    $r['resolved'] = (bool)$r['resolved'];
    if (empty($r['severity']) && $r['cvss']) {
        $r['severity'] = st_severity($r['cvss']);
    }
    $ev = [];
    if (!empty($r['evidence_json'])) {
        $dec = json_decode((string)$r['evidence_json'], true);
        $ev = is_array($dec) ? $dec : [];
    }
    unset($r['evidence_json']);
    $r['evidence'] = $ev;
    if (isset($r['risk_score']) && $r['risk_score'] !== null && $r['risk_score'] !== '') {
        $r['risk_score'] = (float)$r['risk_score'];
    } else {
        $r['risk_score'] = null;
    }
    $osv_list = [];
    if (!empty($r['_intel_osv_ecosystems'])) {
        $oj = json_decode((string)$r['_intel_osv_ecosystems'], true);
        $osv_list = is_array($oj) ? $oj : [];
    }
    $intel_keys = [
        '_intel_kev', '_intel_kev_date_added', '_intel_kev_due_date', '_intel_kev_vendor',
        '_intel_kev_product', '_intel_epss', '_intel_epss_percentile', '_intel_epss_scored_at',
        '_intel_osv_ecosystems',
    ];
    $r['intel'] = [
        'kev' => !empty($r['_intel_kev']) && (int)$r['_intel_kev'] === 1,
        'kev_date_added' => $r['_intel_kev_date_added'] ?? null,
        'kev_due_date' => $r['_intel_kev_due_date'] ?? null,
        'kev_vendor' => $r['_intel_kev_vendor'] ?? null,
        'kev_product' => $r['_intel_kev_product'] ?? null,
        'epss' => isset($r['_intel_epss']) && $r['_intel_epss'] !== null && $r['_intel_epss'] !== ''
            ? (float)$r['_intel_epss'] : null,
        'epss_percentile' => isset($r['_intel_epss_percentile']) && $r['_intel_epss_percentile'] !== null && $r['_intel_epss_percentile'] !== ''
            ? (float)$r['_intel_epss_percentile'] : null,
        'epss_scored_at' => $r['_intel_epss_scored_at'] ?? null,
        'osv_ecosystems' => $osv_list,
    ];
    foreach ($intel_keys as $ik) {
        unset($r[$ik]);
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
