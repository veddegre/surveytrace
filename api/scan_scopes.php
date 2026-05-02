<?php
/**
 * SurveyTrace — /api/scan_scopes.php
 *
 * GET  — list scopes + suggested default for reporting UI
 * POST — create scope (scan_editor+)
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_scan_scopes.php';

st_auth();
st_require_role(['viewer', 'scan_editor', 'admin']);

$db = st_db();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    $scopes = st_scan_scopes_list($db);
    $defaultId = st_scan_scopes_default_id($db);
    st_json([
        'ok'                => true,
        'scopes'            => $scopes,
        'default_scope_id'  => $defaultId,
        'scoping_enabled'   => st_scan_scopes_table_scan_jobs_has_scope_id($db),
    ]);
}

st_method('POST');
st_require_role(['scan_editor', 'admin']);
st_require_csrf();

$body = st_input();
$name = trim((string) ($body['name'] ?? ''));
if ($name === '') {
    st_json(['ok' => false, 'error' => 'name is required'], 400);
}
$description = trim((string) ($body['description'] ?? ''));
$scopeType = trim((string) ($body['scope_type'] ?? 'network'));
if ($scopeType === '') {
    $scopeType = 'network';
}
$cidrsJson = st_scan_scopes_json_list_normalize($body['cidrs'] ?? null, '[]');
$tagsJson = st_scan_scopes_json_list_normalize($body['tags'] ?? null, '[]');
$owner = trim((string) ($body['owner'] ?? ''));
$environment = trim((string) ($body['environment'] ?? 'unknown'));
if ($environment === '') {
    $environment = 'unknown';
}

$has = (int) $db->query(
    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_scopes' LIMIT 1"
)->fetchColumn();
if ($has !== 1) {
    st_json(['ok' => false, 'error' => 'scan_scopes table missing (run migrations)'], 503);
}

$db->prepare(
    'INSERT INTO scan_scopes (name, description, scope_type, cidrs, tags, owner, environment, updated_at)
     VALUES (?,?,?,?,?,?,?,CURRENT_TIMESTAMP)'
)->execute([
    substr($name, 0, 200),
    $description !== '' ? substr($description, 0, 2000) : null,
    substr($scopeType, 0, 64),
    $cidrsJson,
    $tagsJson,
    $owner !== '' ? substr($owner, 0, 200) : null,
    substr($environment, 0, 120),
]);
$id = (int) $db->lastInsertId();
$actor = st_current_user();
st_audit_log('scan.scope_created', (int) ($actor['id'] ?? 0), (string) ($actor['username'] ?? ''), null, null, [
    'scope_id' => $id,
    'name'     => $name,
]);
$st = $db->prepare('SELECT id, name, description, scope_type, cidrs, tags, owner, environment, created_at, updated_at FROM scan_scopes WHERE id = ?');
$st->execute([$id]);
$row = $st->fetch(PDO::FETCH_ASSOC);
st_json(['ok' => true, 'scope' => $row]);
