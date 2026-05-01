<?php
/**
 * SurveyTrace — GET/POST /api/change_alerts.php
 *
 * Phase 9 change-detection feed (new assets, port changes, CVE lifecycle).
 *
 * GET: ?dismissed=0|1|all&limit=100&offset=0
 * POST: {"action":"dismiss","alert_id":N} | {"action":"dismiss_all"}
 */

require_once __DIR__ . '/db.php';
st_auth();
st_require_role(['viewer', 'scan_editor', 'admin']);

$db = st_db();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    st_method('POST');
    st_require_role(['scan_editor', 'admin']);
    $body = st_input();
    $action = trim((string)($body['action'] ?? ''));
    if ($action === 'dismiss') {
        $aid = (int)($body['alert_id'] ?? 0);
        if ($aid <= 0) {
            st_json(['error' => 'alert_id required'], 400);
        }
        $u = st_current_user();
        $uid = (int)($u['id'] ?? 0) > 0 ? (int)$u['id'] : null;
        $db->prepare(
            "UPDATE change_alerts SET dismissed_at=datetime('now'), dismissed_by_user_id=? WHERE id=? AND dismissed_at IS NULL"
        )->execute([$uid, $aid]);
        st_json(['ok' => true, 'alert_id' => $aid]);
    }
    if ($action === 'dismiss_all') {
        $u = st_current_user();
        $uid = (int)($u['id'] ?? 0) > 0 ? (int)$u['id'] : null;
        $db->prepare(
            "UPDATE change_alerts SET dismissed_at=datetime('now'), dismissed_by_user_id=? WHERE dismissed_at IS NULL"
        )->execute([$uid]);
        st_json(['ok' => true, 'dismissed_all' => true]);
    }
    st_json(['error' => 'Unknown action (use dismiss, dismiss_all)'], 400);
}

st_method('GET');

$dismissed = st_str('dismissed', '0', ['0', '1', 'all']);
$limit = st_int('limit', 100, 1, 500);
$offset = st_int('offset', 0, 0, 100000);

if ($dismissed === '0') {
    $where = 'c.dismissed_at IS NULL';
} elseif ($dismissed === '1') {
    $where = 'c.dismissed_at IS NOT NULL';
} else {
    $where = '1=1';
}

$sql = "
    SELECT c.id, c.created_at, c.alert_type, c.job_id, c.asset_id, c.finding_id, c.detail_json,
           c.dismissed_at, c.dismissed_by_user_id,
           a.ip AS asset_ip
    FROM change_alerts c
    LEFT JOIN assets a ON a.id = c.asset_id
    WHERE $where
    ORDER BY c.id DESC
    LIMIT :lim OFFSET :off
";
$stmt = $db->prepare($sql);
$stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
$stmt->bindValue(':off', $offset, PDO::PARAM_INT);
$stmt->execute();
$rows = $stmt->fetchAll();

$countWhere = $dismissed === 'all' ? '1=1' : $where;
$total = (int)$db->query("SELECT COUNT(*) FROM change_alerts c WHERE $countWhere")->fetchColumn();

$open = (int)$db->query('SELECT COUNT(*) FROM change_alerts WHERE dismissed_at IS NULL')->fetchColumn();

$out = [];
foreach ($rows as $r) {
    $dj = [];
    if (!empty($r['detail_json'])) {
        $decoded = json_decode((string)$r['detail_json'], true);
        $dj = is_array($decoded) ? $decoded : [];
    }
    $out[] = [
        'id' => (int)$r['id'],
        'created_at' => (string)($r['created_at'] ?? ''),
        'alert_type' => (string)($r['alert_type'] ?? ''),
        'job_id' => (int)($r['job_id'] ?? 0),
        'asset_id' => $r['asset_id'] !== null ? (int)$r['asset_id'] : null,
        'finding_id' => $r['finding_id'] !== null ? (int)$r['finding_id'] : null,
        'detail' => $dj,
        'asset_ip' => (string)($r['asset_ip'] ?? ''),
        'dismissed_at' => $r['dismissed_at'] ? (string)$r['dismissed_at'] : null,
        'dismissed_by_user_id' => $r['dismissed_by_user_id'] !== null ? (int)$r['dismissed_by_user_id'] : null,
    ];
}

st_json([
    'ok' => true,
    'open_count' => $open,
    'total' => $total,
    'offset' => $offset,
    'limit' => $limit,
    'alerts' => $out,
]);
