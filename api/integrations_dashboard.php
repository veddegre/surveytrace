<?php
/**
 * GET /api/integrations_dashboard.php?scope_id=N (optional)&trend_limit=20&event_hours=24&event_limit=50
 *
 * Single bounded JSON document for Grafana Infinity (live metrics + scoped trends + recent events).
 *
 * Raw slices for Infinity (no root_selector / no bundle envelope): ?view=trends|events|metrics|compliance
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_integrations_dashboard.php';

$db = st_db();
$pullCtx = st_integrations_pull_require_token_for($db, 'dashboard');

$scopeFilter = null;
if (array_key_exists('scope_id', $_GET)) {
    $scopeFilter = (int) $_GET['scope_id'];
    if ($scopeFilter < 0) {
        st_json(['ok' => false, 'error' => 'invalid scope_id'], 400);
    }
}

$trendLimit = isset($_GET['trend_limit']) ? (int) $_GET['trend_limit'] : 20;
$eventHours = isset($_GET['event_hours']) ? (int) $_GET['event_hours'] : 24;
$eventLimit = isset($_GET['event_limit']) ? (int) $_GET['event_limit'] : 50;

$view = isset($_GET['view']) ? strtolower(trim((string) $_GET['view'])) : '';
if ($view !== '' && ! st_integrations_dashboard_view_valid($view)) {
    st_json(['ok' => false, 'error' => 'invalid view (use trends, events, metrics, or compliance)'], 400);
}

$out = st_integrations_build_dashboard_bundle($db, $scopeFilter, $trendLimit, $eventHours, $eventLimit);

if ($view !== '') {
    st_json_raw(st_integrations_dashboard_raw_payload_for_view($view, $out));
}

$out['pull_client'] = st_integrations_pull_client_public($pullCtx);
st_json($out);
