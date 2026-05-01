<?php
/**
 * Admin collector management API.
 */
require_once __DIR__ . '/lib_collectors.php';

st_auth();
st_collector_bootstrap_schema();
$db = st_db();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    st_method('GET');
    st_require_role(['scan_editor', 'admin']);
    $rows = $db->query(
        "SELECT c.*,
                (SELECT COUNT(*) FROM collector_ingest_queue q WHERE q.collector_id=c.id AND q.status='pending') AS pending_chunks,
                (SELECT COUNT(*) FROM collector_ingest_queue q WHERE q.collector_id=c.id AND q.status='failed') AS failed_chunks,
                CASE
                    WHEN COALESCE(c.revoked_at, '') != '' THEN 0
                    WHEN c.last_seen_at IS NOT NULL
                         AND c.last_seen_at >= datetime('now', '-120 seconds') THEN 1
                    ELSE 0
                END AS online_recent_2m
         FROM collectors c
         ORDER BY c.id DESC"
    )->fetchAll();
    $schedules = $db->query(
        "SELECT id, name, target_cidr, enabled, paused, collector_id
         FROM scan_schedules
         ORDER BY id DESC"
    )->fetchAll();
    st_json(['ok' => true, 'collectors' => $rows, 'schedules' => $schedules]);
}

st_method('POST');
st_require_role(['admin']);
$body = st_input();
$action = strtolower(trim((string)($body['action'] ?? '')));
$collectorId = (int)($body['collector_id'] ?? 0);
if ($collectorId <= 0) {
    st_json(['ok' => false, 'error' => 'collector_id required'], 400);
}

if ($action === 'assign_schedules') {
    $scheduleIds = $body['schedule_ids'] ?? [];
    if (!is_array($scheduleIds)) {
        st_json(['ok' => false, 'error' => 'schedule_ids array required'], 400);
    }
    $scheduleIds = array_values(array_unique(array_filter(array_map('intval', $scheduleIds), fn($x) => $x > 0)));
    $allowRow = $db->prepare("SELECT allowed_cidrs_json FROM collectors WHERE id=? LIMIT 1");
    $allowRow->execute([$collectorId]);
    $allow = json_decode((string)($allowRow->fetchColumn() ?: '[]'), true);
    if (!is_array($allow)) $allow = [];
    if ($allow && $scheduleIds) {
        $inChk = implode(',', array_fill(0, count($scheduleIds), '?'));
        $chk = $db->prepare("SELECT id, target_cidr FROM scan_schedules WHERE id IN ($inChk)");
        $chk->execute($scheduleIds);
        foreach ($chk->fetchAll() as $sr) {
            if (!st_collector_target_allowed($collectorId, (string)($sr['target_cidr'] ?? ''))) {
                st_json(['ok' => false, 'error' => 'One or more schedules are outside collector allowed CIDR ranges'], 400);
            }
        }
    }
    $db->exec("BEGIN IMMEDIATE");
    try {
        $db->prepare("UPDATE scan_schedules SET collector_id=0 WHERE collector_id=?")->execute([$collectorId]);
        if ($scheduleIds) {
            $in = implode(',', array_fill(0, count($scheduleIds), '?'));
            $params = array_merge([$collectorId], $scheduleIds);
            $db->prepare("UPDATE scan_schedules SET collector_id=? WHERE id IN ($in)")->execute($params);
        }
        $db->prepare("UPDATE collectors SET schedule_ids_json=?, updated_at=datetime('now') WHERE id=?")
            ->execute([json_encode($scheduleIds), $collectorId]);
        $db->exec("COMMIT");
    } catch (Throwable $e) {
        $db->exec("ROLLBACK");
        st_json(['ok' => false, 'error' => 'schedule assignment failed'], 500);
    }
    st_audit_log('collector.schedules_assigned', null, null, null, null, [
        'collector_id' => $collectorId,
        'schedule_ids' => $scheduleIds,
    ]);
    st_json(['ok' => true, 'collector_id' => $collectorId, 'schedule_ids' => $scheduleIds]);
}

if ($action === 'set_allowed_cidrs') {
    $raw = trim((string)($body['allowed_cidrs'] ?? ''));
    $cidrs = st_collector_parse_cidrs($raw);
    $db->prepare("UPDATE collectors SET allowed_cidrs_json=?, updated_at=datetime('now') WHERE id=?")
        ->execute([json_encode($cidrs), $collectorId]);
    st_audit_log('collector.allowed_cidrs_updated', null, null, null, null, [
        'collector_id' => $collectorId,
        'allowed_cidrs' => $cidrs,
    ]);
    st_json(['ok' => true, 'collector_id' => $collectorId, 'allowed_cidrs' => $cidrs]);
}

if ($action === 'rotate_token') {
    $db->prepare("UPDATE collector_tokens SET revoked_at=datetime('now') WHERE collector_id=? AND revoked_at IS NULL")->execute([$collectorId]);
    $issued = st_collector_issue_token($collectorId, ['collector:checkin', 'collector:jobs:read', 'collector:submit:write', 'collector:status:write']);
    st_audit_log('collector.token_rotated', null, null, null, null, ['collector_id' => $collectorId]);
    st_json([
        'ok' => true,
        'collector_id' => $collectorId,
        'token' => $issued['token'],
        'token_expires_at' => $issued['expires_at'],
    ]);
}

if ($action === 'revoke') {
    $db->prepare("UPDATE collector_tokens SET revoked_at=datetime('now') WHERE collector_id=? AND revoked_at IS NULL")->execute([$collectorId]);
    $db->prepare("UPDATE collectors SET revoked_at=datetime('now'), status='revoked', updated_at=datetime('now') WHERE id=?")->execute([$collectorId]);
    st_audit_log('collector.revoked', null, null, null, null, ['collector_id' => $collectorId]);
    st_json(['ok' => true, 'collector_id' => $collectorId, 'revoked' => true]);
}

st_json(['ok' => false, 'error' => 'Unsupported action'], 400);
