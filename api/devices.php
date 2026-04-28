<?php
/**
 * SurveyTrace — GET /api/devices.php
 *
 * Lists logical devices (stable ids) with aggregate info from linked assets.
 *
 * GET query params:
 *   q          — search id, MAC norm, label, or any linked asset IP/hostname
 *   sort       — id | asset_count | last_seen | primary_mac_norm (default: id)
 *   order      — asc | desc (default: desc for id: use asc)
 *   page       — 1-based (default: 1)
 *   per_page   — 1–200 (default: 50)
 *   id         — if set, return one device plus its assets (no pagination)
 */

require_once __DIR__ . '/db.php';
st_auth();
st_method('GET');

$db = st_db();

$id = st_int('id', 0, 0, PHP_INT_MAX);
if ($id > 0) {
    $stmt = $db->prepare('SELECT * FROM devices WHERE id = ?');
    $stmt->execute([$id]);
    $device = $stmt->fetch();
    if (!$device) {
        st_json(['error' => 'Device not found'], 404);
    }
    $device['id'] = (int)$device['id'];
    if (isset($device['primary_mac_norm'])) {
        $device['primary_mac_norm'] = $device['primary_mac_norm'] ?: null;
    }

    $ast = $db->prepare('
        SELECT id, ip, hostname, category, top_cvss, last_seen, first_seen
        FROM assets
        WHERE device_id = ?
        ORDER BY last_seen DESC
    ');
    $ast->execute([$id]);
    $rows = $ast->fetchAll();
    foreach ($rows as &$r) {
        $r['id'] = (int)$r['id'];
        $r['top_cvss'] = $r['top_cvss'] !== null && $r['top_cvss'] !== ''
            ? (float)$r['top_cvss'] : null;
    }
    unset($r);

    st_json([
        'device' => $device,
        'assets' => $rows,
        'asset_count' => count($rows),
    ]);
}

// ---------------------------------------------------------------------------
// List mode
// ---------------------------------------------------------------------------
$q          = st_str('q');
$page       = st_int('page', 1, 1);
$per_page   = st_int('per_page', 50, 1, 200);
$offset     = ($page - 1) * $per_page;

$valid_sorts = ['id', 'asset_count', 'last_seen', 'primary_mac_norm'];
$sort_col    = st_str('sort', 'id', $valid_sorts);
$sort_order  = st_str('order', 'asc', ['asc', 'desc']) === 'desc' ? 'DESC' : 'ASC';

$where  = ['1=1'];
$params = [];

if ($q !== '') {
    $where[] = '(
        CAST(d.id AS TEXT) LIKE :dq
        OR IFNULL(d.primary_mac_norm, \'\') LIKE :dq
        OR IFNULL(d.label, \'\') LIKE :dq
        OR EXISTS (
            SELECT 1 FROM assets ax
            WHERE ax.device_id = d.id
              AND (ax.ip LIKE :dq OR IFNULL(ax.hostname, \'\') LIKE :dq)
        )
    )';
    $params[':dq'] = '%' . $q . '%';
}

$where_sql = implode(' AND ', $where);

$sub_cnt = '(SELECT COUNT(*) FROM assets a WHERE a.device_id = d.id)';
$sub_max = '(SELECT MAX(a2.last_seen) FROM assets a2 WHERE a2.device_id = d.id)';
$sub_ips = '(SELECT group_concat(ip, \' · \') FROM (
    SELECT ip FROM assets WHERE device_id = d.id ORDER BY last_seen DESC LIMIT 5
))';

$order_expr = match ($sort_col) {
    'asset_count'       => "$sub_cnt $sort_order",
    'last_seen'         => "$sub_max $sort_order NULLS LAST",
    'primary_mac_norm'  => "d.primary_mac_norm $sort_order NULLS LAST",
    default             => "d.id $sort_order",
};

$count_sql = "SELECT COUNT(*) FROM devices d WHERE $where_sql";
$count_stmt = $db->prepare($count_sql);
$count_stmt->execute($params);
$total = (int)$count_stmt->fetchColumn();

$sql = "
    SELECT
        d.id,
        d.primary_mac_norm,
        d.label,
        d.created_at,
        d.updated_at,
        $sub_cnt AS asset_count,
        $sub_max AS last_seen_max,
        $sub_ips AS ip_sample
    FROM devices d
    WHERE $where_sql
    ORDER BY $order_expr
    LIMIT :lim OFFSET :off
";

$stmt = $db->prepare($sql);
foreach ($params as $k => $v) {
    $stmt->bindValue($k, $v);
}
$stmt->bindValue(':lim', $per_page, PDO::PARAM_INT);
$stmt->bindValue(':off', $offset, PDO::PARAM_INT);
$stmt->execute();
$devices = $stmt->fetchAll();

foreach ($devices as &$row) {
    $row['id'] = (int)$row['id'];
    $row['asset_count'] = (int)($row['asset_count'] ?? 0);
    $row['primary_mac_norm'] = $row['primary_mac_norm'] ?: null;
    $row['ip_sample'] = $row['ip_sample'] ?? null;
}
unset($row);

$pages = (int)ceil(max(1, $total) / $per_page);

st_json([
    'total'    => $total,
    'page'     => $page,
    'per_page' => $per_page,
    'pages'    => $pages,
    'devices'  => $devices,
]);
