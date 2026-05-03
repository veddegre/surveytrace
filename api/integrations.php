<?php
/**
 * SurveyTrace — /api/integrations.php
 *
 * Admin-only: list integrations, CRUD, manual test/sample push, per-row pull token rotation, legacy global pull token.
 * Secrets are never returned; use auth_configured and rotate flows.
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_integrations.php';

st_auth();
st_require_role(['admin']);

$db = st_db();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    st_json([
        'ok'                                    => true,
        'integrations'                        => st_integrations_list($db),
        'legacy_pull_token_configured'          => st_integrations_legacy_pull_token_configured(),
        'per_integration_pull_token_configured' => st_integrations_any_row_pull_token_configured($db),
        'pull_token_configured'                 => st_integrations_legacy_pull_token_configured()
            || st_integrations_any_row_pull_token_configured($db),
    ]);
}

st_method('POST');
st_require_csrf();

$body = st_input();
$action = strtolower(trim((string) ($body['action'] ?? '')));

if ($action === 'rotate_pull_token') {
    $r = st_integrations_pull_token_rotate();
    if (! $r['ok']) {
        st_json(['ok' => false, 'error' => $r['error'] ?? 'rotate_failed'], 500);
    }
    @error_log('SurveyTrace.integrations ' . json_encode([
        '_event' => 'integrations.legacy_pull_token_rotated',
    ], JSON_UNESCAPED_SLASHES));
    st_json([
        'ok'                     => true,
        'pull_token'             => $r['token'],
        'pull_token_reveal_once' => true,
        'message'                => 'Legacy global token — store now; it will not be shown again. Prefer per-integration tokens.',
    ]);
}

if ($action === 'rotate_token') {
    $id = (int) ($body['integration_id'] ?? 0);
    $row = st_integrations_get_by_id($db, $id);
    if ($row === null) {
        st_json(['ok' => false, 'error' => 'integration not found'], 404);
    }
    if (! st_integrations_is_pull_type((string) ($row['type'] ?? ''))) {
        st_json(['ok' => false, 'error' => 'rotate_token applies to prometheus_pull, json_events_pull, or report_summary_pull only'], 400);
    }
    $r = st_integrations_pull_token_rotate_for_row($db, $id);
    if (! $r['ok']) {
        st_json(['ok' => false, 'error' => $r['error'] ?? 'rotate_failed'], 500);
    }
    @error_log('SurveyTrace.integrations ' . json_encode([
        '_event' => 'integrations.pull_token_rotated',
        'id'     => $id,
    ], JSON_UNESCAPED_SLASHES));
    st_json([
        'ok'                => true,
        'integration_id'    => $id,
        'token'             => $r['token'],
        'token_reveal_once' => true,
        'message'           => 'Copy this token now. It will not be shown again.',
    ]);
}

if ($action === 'create') {
    $name = trim((string) ($body['name'] ?? ''));
    $type = strtolower(trim((string) ($body['type'] ?? '')));
    if ($name === '' || ! st_integrations_type_valid($type)) {
        st_json(['ok' => false, 'error' => 'name and valid type required'], 400);
    }
    $enabled = ! empty($body['enabled']) ? 1 : 0;
    $endpoint = trim((string) ($body['endpoint_url'] ?? ''));
    $host = trim((string) ($body['host'] ?? ''));
    $port = array_key_exists('port', $body) && $body['port'] !== null && $body['port'] !== ''
        ? (int) $body['port']
        : null;
    $auth = trim((string) ($body['auth_secret'] ?? ''));
    $extra = trim((string) ($body['extra_json'] ?? '{}'));
    if ($extra === '') {
        $extra = '{}';
    }
    json_decode($extra);
    if (json_last_error() !== JSON_ERROR_NONE) {
        st_json(['ok' => false, 'error' => 'extra_json must be valid JSON'], 400);
    }
    $db->prepare(
        'INSERT INTO integrations (name, type, enabled, endpoint_url, host, port, auth_secret, extra_json, updated_at)
         VALUES (?,?,?,?,?,?,?,?, CURRENT_TIMESTAMP)'
    )->execute([$name, $type, $enabled, $endpoint, $host, $port, $auth !== '' ? $auth : null, $extra]);
    $id = (int) $db->lastInsertId();
    st_json(['ok' => true, 'id' => $id]);
}

if ($action === 'update') {
    $id = (int) ($body['id'] ?? 0);
    $row = st_integrations_get_by_id($db, $id);
    if ($row === null) {
        st_json(['ok' => false, 'error' => 'integration not found'], 404);
    }
    $name = array_key_exists('name', $body) ? trim((string) $body['name']) : (string) $row['name'];
    $type = array_key_exists('type', $body) ? strtolower(trim((string) $body['type'])) : (string) $row['type'];
    if ($name === '' || ! st_integrations_type_valid($type)) {
        st_json(['ok' => false, 'error' => 'invalid name or type'], 400);
    }
    $enabled = array_key_exists('enabled', $body) ? (! empty($body['enabled']) ? 1 : 0) : (int) $row['enabled'];
    $endpoint = array_key_exists('endpoint_url', $body) ? trim((string) $body['endpoint_url']) : (string) $row['endpoint_url'];
    $host = array_key_exists('host', $body) ? trim((string) $body['host']) : (string) $row['host'];
    $port = array_key_exists('port', $body)
        ? ($body['port'] === null || $body['port'] === '' ? null : (int) $body['port'])
        : ($row['port'] !== null && $row['port'] !== '' ? (int) $row['port'] : null);
    $extra = array_key_exists('extra_json', $body) ? trim((string) $body['extra_json']) : (string) $row['extra_json'];
    if ($extra === '') {
        $extra = '{}';
    }
    json_decode($extra);
    if (json_last_error() !== JSON_ERROR_NONE) {
        st_json(['ok' => false, 'error' => 'extra_json must be valid JSON'], 400);
    }
    $authClear = ! empty($body['auth_secret_clear']);
    $authNew = array_key_exists('auth_secret', $body) ? trim((string) $body['auth_secret']) : null;
    $authVal = (string) ($row['auth_secret'] ?? '');
    if ($authClear) {
        $authVal = '';
    } elseif ($authNew !== null && $authNew !== '') {
        $authVal = $authNew;
    }
    $clearPullTok = st_integrations_is_pull_type((string) ($row['type'] ?? ''))
        && ! st_integrations_is_pull_type($type);
    $db->prepare(
        'UPDATE integrations SET name=?, type=?, enabled=?, endpoint_url=?, host=?, port=?, auth_secret=?, extra_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?'
    )->execute([$name, $type, $enabled, $endpoint, $host, $port, $authVal !== '' ? $authVal : null, $extra, $id]);
    if ($clearPullTok) {
        $db->prepare(
            'UPDATE integrations SET token_hash = NULL, token_created_at = NULL, token_last_used_at = NULL, token_last_used_ip = NULL, updated_at = datetime(\'now\') WHERE id = ?'
        )->execute([$id]);
    }
    st_json(['ok' => true]);
}

if ($action === 'delete') {
    $id = (int) ($body['id'] ?? 0);
    if ($id <= 0) {
        st_json(['ok' => false, 'error' => 'id required'], 400);
    }
    $db->prepare('DELETE FROM integrations WHERE id = ?')->execute([$id]);
    st_json(['ok' => true]);
}

if ($action === 'test' || $action === 'sample') {
    $id = (int) ($body['id'] ?? 0);
    $row = st_integrations_get_by_id($db, $id);
    if ($row === null) {
        st_json(['ok' => false, 'error' => 'integration not found'], 404);
    }
    if (! st_integrations_is_push_type((string) $row['type'])) {
        st_json(['ok' => false, 'error' => 'test/sample applies to push types only (webhook, splunk_hec, syslog, loki)'], 400);
    }
    $event = st_integrations_sample_canonical_event();
    if ($action === 'sample' && ! empty($body['use_live_artifact']) && st_sqlite_table_exists($db, 'report_artifacts')) {
        $st = $db->query('SELECT id, created_at, schedule_id, baseline_job_id, compare_job_id, title FROM report_artifacts ORDER BY id DESC LIMIT 1');
        $lr = $st ? $st->fetch(PDO::FETCH_ASSOC) : false;
        if (is_array($lr)) {
            $event = st_reporting_event_from_report_artifact_row($lr);
        }
    }
    $res = st_integrations_push_send_test($db, $row, $event);
    st_json([
        'ok'         => $res['ok'],
        'http_code'  => $res['http_code'] ?? null,
        'detail'     => $res['detail'],
        'event_type' => $event['event_type'] ?? null,
    ], $res['ok'] ? 200 : 502);
}

st_json(['ok' => false, 'error' => 'unknown action'], 400);
