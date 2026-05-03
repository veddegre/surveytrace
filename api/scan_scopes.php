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
    try {
        $scopes = st_scan_scopes_list($db);
        $defaultId = st_scan_scopes_default_id($db);
        $enabled = st_scan_scopes_table_scan_jobs_has_scope_id($db);
        st_json([
            'ok'               => true,
            'scopes'           => $scopes,
            'default_scope_id' => $defaultId,
            'scoping_enabled'  => $enabled,
        ]);
    } catch (Throwable $e) {
        @error_log('SurveyTrace scan_scopes GET: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $e->getMessage()));
        $out = [
            'ok'               => true,
            'scopes'           => [],
            'default_scope_id' => null,
            'scoping_enabled'  => false,
            'scope_catalog_error' => 'Scope catalog could not be read (database or migration issue).',
        ];
        if (getenv('SURVEYTRACE_REPORTING_DEBUG') && trim((string) getenv('SURVEYTRACE_REPORTING_DEBUG')) !== '' && trim((string) getenv('SURVEYTRACE_REPORTING_DEBUG')) !== '0') {
            $m = preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $e->getMessage());
            $out['debug_error'] = strlen($m) > 400 ? substr($m, 0, 400) . '…' : $m;
        }
        st_json($out);
    }
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
    st_json(['ok' => false, 'error' => 'scan_scopes table missing (run migrations or redeploy)']);
}

try {
    $row = st_scan_scopes_insert_catalog_row(
        $db,
        $name,
        $description,
        $scopeType,
        $cidrsJson,
        $tagsJson,
        $owner,
        $environment
    );
} catch (InvalidArgumentException $e) {
    $msg = $e->getMessage();
    st_json(['ok' => false, 'error' => $msg], 400);
} catch (Throwable $e) {
    st_json(['ok' => false, 'error' => 'Could not create scope'], 500);
}
$id = (int) ($row['id'] ?? 0);
$actor = st_current_user();
st_audit_log('scope.created', (int) ($actor['id'] ?? 0), (string) ($actor['username'] ?? ''), null, null, [
    'scope_id' => $id,
    'name'     => substr($name, 0, 200),
]);
st_json(['ok' => true, 'scope' => $row]);
