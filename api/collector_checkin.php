<?php
/**
 * Collector registration and heartbeat endpoint.
 */
require_once __DIR__ . '/lib_collectors.php';

st_collector_require_post();
st_collector_bootstrap_schema();
$db = st_db();
$body = st_input();
$action = strtolower(trim((string)($body['action'] ?? 'heartbeat')));

if ($action === 'register') {
    $installToken = trim((string)($_SERVER['HTTP_X_COLLECTOR_INSTALL_TOKEN'] ?? ''));
    $expected = trim(st_config('collector_install_token', ''));
    if ($expected === '' || !hash_equals($expected, $installToken)) {
        st_json(['ok' => false, 'error' => 'Collector install token denied'], 401);
    }
    $name = trim((string)($body['name'] ?? 'collector'));
    $site = trim((string)($body['site_label'] ?? ''));
    $version = trim((string)($body['version'] ?? ''));
    if ($name === '' || strlen($name) > 120) {
        st_json(['ok' => false, 'error' => 'Invalid collector name'], 400);
    }
    $maxRps = max(1.0, min(50.0, (float)($body['max_rps'] ?? (float)st_config('collector_rate_default_rps', '5'))));
    $maxSubmit = max(1.0, min(256.0, (float)($body['max_submit_mbps'] ?? (float)st_config('collector_submit_max_mb', '8'))));
    $caps = $body['capabilities'] ?? [];
    if (!is_array($caps)) {
        $caps = [];
    }
    $sched = $body['schedule_ids'] ?? [];
    if (!is_array($sched)) {
        $sched = [];
    }
    $sched = array_values(array_unique(array_map('intval', $sched)));

    $db->prepare(
        "INSERT INTO collectors
         (name, site_label, status, version, capabilities_json, max_rps, max_submit_mbps, schedule_ids_json, token_issued_at, last_seen_at, last_ip, created_at, updated_at)
         VALUES (?, ?, 'online', ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?, datetime('now'), datetime('now'))"
    )->execute([
        $name,
        $site,
        $version,
        json_encode($caps, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        $maxRps,
        $maxSubmit,
        json_encode($sched),
        st_request_ip(),
    ]);
    $collectorId = (int)$db->lastInsertId();
    $scopes = ['collector:checkin', 'collector:jobs:read', 'collector:submit:write', 'collector:status:write'];
    $issued = st_collector_issue_token($collectorId, $scopes);
    st_audit_log('collector.registered', null, null, null, null, [
        'collector_id' => $collectorId,
        'name' => $name,
        'site_label' => $site,
        'version' => $version,
    ]);
    st_json([
        'ok' => true,
        'collector_id' => $collectorId,
        'token' => $issued['token'],
        'token_expires_at' => $issued['expires_at'],
        'scopes' => $scopes,
    ]);
}

$auth = st_collector_auth_required('collector:checkin');
$collectorId = (int)$auth['collector_id'];
$stmt = $db->prepare("SELECT max_rps FROM collectors WHERE id=? LIMIT 1");
$stmt->execute([$collectorId]);
$maxRps = (float)($stmt->fetchColumn() ?: 5.0);
st_collector_rate_limit($collectorId, 'checkin', $maxRps);
$version = trim((string)($body['version'] ?? ''));
$error = trim((string)($body['last_error'] ?? ''));
$caps = $body['capabilities'] ?? [];
if (!is_array($caps)) {
    $caps = [];
}
$db->prepare(
    "UPDATE collectors
     SET status='online',
         version=?,
         capabilities_json=?,
         last_seen_at=datetime('now'),
         last_ip=?,
         last_error=?,
         updated_at=datetime('now')
     WHERE id=?"
)->execute([
    $version,
    json_encode($caps, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
    st_request_ip(),
    $error,
    $collectorId,
]);
st_json(['ok' => true, 'collector_id' => $collectorId, 'server_time' => gmdate('c')]);
