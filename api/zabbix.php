<?php
/**
 * SurveyTrace — /api/zabbix.php
 *
 * Admin-only: Zabbix source connector config, API test, bounded sync (background worker),
 * scope-map rules (preview/save; never mutates asset scopes automatically).
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_scan_scopes.php';
require_once __DIR__ . '/lib_zabbix.php';

st_auth();
st_require_role(['admin']);

$db = st_db();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    if (! st_zabbix_table_ready($db)) {
        st_json(['ok' => false, 'error' => 'Zabbix tables missing; run database migrations'], 503);
    }
    $row = st_zabbix_connector_get($db);
    $scopes = st_zabbix_scan_scopes_table_exists($db) ? st_scan_scopes_list($db) : [];
    $out = [
        'ok' => true,
        'connector' => st_zabbix_connector_public($row),
        'stats' => st_zabbix_stats($db),
        'sample_matches' => st_zabbix_sample_matches($db, 8),
        'scope_rules' => st_zabbix_scope_rules_all($db),
        'scope_map_catalog' => st_zabbix_scope_map_catalog($db),
        'scopes' => $scopes,
        'scope_catalog_count' => count($scopes),
        'workflow' => [
            'asset_scope_apply' => st_zabbix_scan_scopes_table_exists($db) && st_zabbix_asset_workflow_columns_ready($db),
        ],
    ];
    if (isset($_GET['match_review']) && (string) $_GET['match_review'] === '1') {
        $out['match_review'] = st_zabbix_match_review($db);
    }
    st_json($out);
}

st_method('POST');
st_require_csrf();

$body = st_input();
$action = strtolower(trim((string) ($body['action'] ?? '')));

if ($action === 'save_connector') {
    if (! st_zabbix_table_ready($db)) {
        st_json(['ok' => false, 'error' => 'Zabbix tables missing; run database migrations'], 503);
    }
    st_zabbix_connector_save($db, $body);
    $row = st_zabbix_connector_get($db);
    st_json(['ok' => true, 'connector' => st_zabbix_connector_public($row)]);
}

if ($action === 'test') {
    $url = st_zabbix_normalize_api_url(trim((string) ($body['api_url'] ?? '')));
    $tok = trim((string) ($body['api_token'] ?? ''));
    if ($url === '') {
        st_json(['ok' => false, 'error' => 'api_url required'], 400);
    }
    if ($tok === '') {
        $row = st_zabbix_connector_get($db);
        $tok = (string) ($row['api_token'] ?? '');
    }
    if ($tok === '') {
        st_json(['ok' => false, 'error' => 'api_token required (or save a token first)'], 400);
    }
    $t = st_zabbix_api_test($url, $tok);
    if (! $t['ok']) {
        st_json(['ok' => false, 'error' => st_zabbix_redact_secrets((string) ($t['error'] ?? 'test failed'))], 400);
    }
    st_json(['ok' => true, 'zabbix_version' => $t['version'] ?? null]);
}

if ($action === 'sync_now') {
    if (! st_zabbix_table_ready($db)) {
        st_json(['ok' => false, 'error' => 'Zabbix tables missing; run database migrations'], 503);
    }
    $c = st_zabbix_connector_get($db);
    if ((int) ($c['enabled'] ?? 0) !== 1) {
        st_json(['ok' => false, 'error' => 'Enable the connector before syncing'], 400);
    }
    $useFpmAsync = in_array(PHP_SAPI, ['fpm-fcgi', 'cgi-fcgi'], true)
        && function_exists('fastcgi_finish_request');

    if ($useFpmAsync) {
        $payload = ['ok' => true, 'async' => true, 'started' => true, 'mode' => 'fpm_background'];
        $enc = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($enc === false) {
            st_json(['ok' => false, 'error' => 'json_encode failed'], 500);
        }
        if (! headers_sent()) {
            http_response_code(200);
            header('Content-Type: application/json; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
            header('Cache-Control: no-store');
        }
        echo $enc;
        flush();
        fastcgi_finish_request();
        @set_time_limit(300);
        ignore_user_abort(true);
        try {
            st_zabbix_run_full_sync(st_db());
        } catch (Throwable $e) {
            $em = st_zabbix_redact_secrets(preg_replace('/[\x00-\x1F\x7F]/u', ' ', $e->getMessage()) ?? '');
            @error_log('SurveyTrace zabbix sync: ' . $em);
        }
        exit(0);
    }

    if (st_zabbix_spawn_worker()) {
        st_json(['ok' => true, 'async' => true, 'started' => true, 'mode' => 'cli_worker']);
    }

    st_json([
        'ok' => false,
        'error' => 'Could not start background sync (exec disabled or worker missing). Use PHP-FPM, set SURVEYTRACE_PHP_CLI to a CLI binary, or run: php api/zabbix_sync_worker.php',
    ], 503);
}

if ($action === 'preview_scope_map') {
    if (! st_zabbix_table_ready($db)) {
        st_json(['ok' => false, 'error' => 'Zabbix tables missing; run database migrations'], 503);
    }
    $rules = $body['rules'] ?? null;
    if (! is_array($rules)) {
        st_json(['ok' => false, 'error' => 'rules array required'], 400);
    }
    $dbg = null;
    if (! empty($body['debug_scope_map'])) {
        $dbg = [];
    }
    try {
        $preview = st_zabbix_preview_scope_map($db, $rules, $dbg);
    } catch (InvalidArgumentException $e) {
        $msg = st_zabbix_redact_secrets($e->getMessage());
        @error_log('SurveyTrace zabbix preview_scope_map validation failed: ' . $msg);
        st_json(['ok' => false, 'error' => $msg, 'validation_failed' => true], 400);
    }
    $note = $rules === []
        ? 'No rules to evaluate — add at least one complete rule (type, pattern, scope).'
        : ($preview === []
            ? 'No assets matched — enable rules, run sync so hosts link to assets, and ensure a linked host’s group/tag matches a rule.'
            : 'Preview only — asset scopes are not modified.');
    $out = ['ok' => true, 'preview' => $preview, 'note' => $note];
    if ($dbg !== null) {
        $out['debug_scope_map'] = $dbg;
    }
    st_json($out);
}

if ($action === 'save_scope_rules') {
    if (! st_zabbix_table_ready($db)) {
        st_json(['ok' => false, 'error' => 'Zabbix tables missing; run database migrations'], 503);
    }
    $rules = $body['rules'] ?? null;
    if (! is_array($rules)) {
        st_json(['ok' => false, 'error' => 'rules array required'], 400);
    }
    try {
        st_zabbix_scope_rules_replace($db, $rules);
    } catch (InvalidArgumentException $e) {
        $msg = st_zabbix_redact_secrets($e->getMessage());
        $pre = st_zabbix_scope_rules_validate($db, $rules);
        @error_log(
            'SurveyTrace zabbix save_scope_rules rejected: errors=' . count($pre['errors'])
            . ' valid_rows=' . $pre['valid_count']
        );
        st_json([
            'ok' => false,
            'error' => $msg,
            'validation_errors' => $pre['errors'],
            'validation_failed' => true,
        ], 400);
    }
    st_json(['ok' => true, 'scope_rules' => st_zabbix_scope_rules_all($db), 'saved_count' => count($rules)]);
}

if ($action === 'preview_scope_apply') {
    if (! st_zabbix_table_ready($db)) {
        st_json(['ok' => false, 'error' => 'Zabbix tables missing; run database migrations'], 503);
    }
    try {
        st_zabbix_assert_no_enabled_stale_scope_rules($db);
    } catch (InvalidArgumentException $e) {
        $msg = st_zabbix_redact_secrets($e->getMessage());
        @error_log('SurveyTrace zabbix preview_scope_apply blocked: ' . $msg);
        st_json(['ok' => false, 'error' => $msg, 'stale_scope_rules' => true], 400);
    }
    $dbRules = $db->query(
        'SELECT r.rule_type, r.pattern, r.scope_id, 1 AS enabled
         FROM zabbix_scope_map_rules r
         INNER JOIN scan_scopes s ON s.id = r.scope_id
         WHERE r.enabled = 1 ORDER BY r.id'
    )->fetchAll(PDO::FETCH_ASSOC);
    $dbRules = is_array($dbRules) ? $dbRules : [];
    if ($dbRules === []) {
        st_json([
            'ok' => true,
            'plan' => [],
            'note' => 'No enabled rules with valid scopes — save at least one enabled rule under Enrichment → Zabbix, or create scan scopes first.',
            'enabled_valid_rule_count' => 0,
        ]);
    }
    $dbg = null;
    if (! empty($body['debug_scope_map'])) {
        $dbg = [];
    }
    try {
        $plan = st_zabbix_preview_scope_map($db, $dbRules, $dbg);
    } catch (InvalidArgumentException $e) {
        $msg = st_zabbix_redact_secrets($e->getMessage());
        @error_log('SurveyTrace zabbix preview_scope_apply failed: ' . $msg);
        st_json(['ok' => false, 'error' => $msg, 'validation_failed' => true], 400);
    }
    $note = $plan === []
        ? 'No assets matched enabled rules — run sync and ensure linked hosts match a rule’s group or tag.'
        : 'Plan only — call apply_scope_map with confirm and the same rows to write scope_id.';
    $out = [
        'ok' => true,
        'plan' => $plan,
        'note' => $note,
        'enabled_valid_rule_count' => count($dbRules),
    ];
    if ($dbg !== null) {
        $out['debug_scope_map'] = $dbg;
    }
    st_json($out);
}

if ($action === 'apply_scope_map') {
    if (! st_zabbix_table_ready($db)) {
        st_json(['ok' => false, 'error' => 'Zabbix tables missing; run database migrations'], 503);
    }
    if (empty($body['confirm'])) {
        st_json(['ok' => false, 'error' => 'confirm is required (explicit operator acknowledgement)'], 400);
    }
    $apply = $body['apply'] ?? null;
    if (! is_array($apply)) {
        st_json(['ok' => false, 'error' => 'apply array required: [{asset_id, old_scope_id, new_scope_id}, ...]'], 400);
    }
    try {
        st_zabbix_assert_no_enabled_stale_scope_rules($db);
    } catch (InvalidArgumentException $e) {
        $msg = st_zabbix_redact_secrets($e->getMessage());
        @error_log('SurveyTrace zabbix apply_scope_map blocked: ' . $msg);
        st_json(['ok' => false, 'error' => $msg, 'stale_scope_rules' => true], 400);
    }
    try {
        $res = st_zabbix_apply_scope_map($db, true, $apply);
    } catch (Throwable $e) {
        st_json(['ok' => false, 'error' => st_zabbix_redact_secrets($e->getMessage())], 400);
    }
    $actor = st_current_user();
    if ($res['applied'] > 0) {
        st_audit_log(
            'zabbix.scope_map_applied',
            (int) ($actor['id'] ?? 0),
            (string) ($actor['username'] ?? ''),
            null,
            null,
            [
                'applied' => $res['applied'],
                'skipped' => $res['skipped'],
                'changes' => $res['changes'],
                'errors' => $res['errors'],
            ]
        );
    }
    st_json(['ok' => true] + $res);
}

if ($action === 'link_manual') {
    if (! st_zabbix_table_ready($db)) {
        st_json(['ok' => false, 'error' => 'Zabbix tables missing; run database migrations'], 503);
    }
    $aid = (int) ($body['asset_id'] ?? 0);
    $hid = trim((string) ($body['zabbix_hostid'] ?? ''));
    $mm = trim((string) ($body['match_method'] ?? 'manual'));
    $conf = (float) ($body['confidence'] ?? 1.0);
    if ($aid <= 0 || $hid === '') {
        st_json(['ok' => false, 'error' => 'asset_id and zabbix_hostid required'], 400);
    }
    try {
        st_zabbix_link_manual($db, $aid, $hid, $mm, $conf);
    } catch (Throwable $e) {
        st_json(['ok' => false, 'error' => st_zabbix_redact_secrets($e->getMessage())], 400);
    }
    $actor = st_current_user();
    st_audit_log('zabbix.link_manual', (int) ($actor['id'] ?? 0), (string) ($actor['username'] ?? ''), null, null, [
        'asset_id' => $aid,
        'zabbix_hostid' => $hid,
        'match_method' => $mm !== '' ? $mm : 'manual',
        'confidence' => $conf,
    ]);
    st_json(['ok' => true]);
}

if ($action === 'unlink_asset') {
    if (! st_zabbix_table_ready($db)) {
        st_json(['ok' => false, 'error' => 'Zabbix tables missing; run database migrations'], 503);
    }
    $aid = (int) ($body['asset_id'] ?? 0);
    if ($aid <= 0) {
        st_json(['ok' => false, 'error' => 'asset_id required'], 400);
    }
    st_zabbix_unlink_asset($db, $aid);
    $actor = st_current_user();
    st_audit_log('zabbix.unlink_asset', (int) ($actor['id'] ?? 0), (string) ($actor['username'] ?? ''), null, null, [
        'asset_id' => $aid,
    ]);
    st_json(['ok' => true]);
}

st_json(['ok' => false, 'error' => 'unknown action'], 400);
