<?php
/**
 * GET /api/integrations_metrics.php — Prometheus text (default) or JSON (`?format=json`, integration pull token).
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_integrations.php';

$db = st_db();
$fmt = strtolower(trim((string) ($_GET['format'] ?? 'prometheus')));
$pullCtx = st_integrations_pull_require_token_for($db, 'metrics', ['metrics_format' => $fmt]);
header('Cache-Control: no-store');

if ($fmt !== 'json' && $fmt !== 'prometheus') {
    st_json(['ok' => false, 'error' => 'invalid format (use prometheus default or format=json)'], 400);
}

if ($fmt === 'json') {
    $snap = st_integrations_metrics_snapshot($db);
    $ctx = st_reporting_scope_context_for_response($db, null);
    $snap['scope_context'] = $ctx;
    $snap['scope_id'] = $ctx['scope_id'];
    $snap['scope_name'] = $ctx['scope_name'];
    $snap['pull_client'] = st_integrations_pull_client_public($pullCtx);
    st_json($snap);
}

header('Content-Type: text/plain; charset=UTF-8');
echo st_integrations_prometheus_text($db);
