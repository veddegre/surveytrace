<?php
/**
 * GET /api/integrations_events.php?since=ISO8601&limit=200&format=json|jsonl&flat_scope=0|1
 *
 * Bounded export of canonical reporting events (change_alerts + report_artifacts metadata).
 * JSON default adds top-level scope_id/scope_name on each event; pass flat_scope=0 to omit.
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_integrations.php';

$db = st_db();
$pullCtx = st_integrations_pull_require_token_for($db, 'events');

$since = trim((string) ($_GET['since'] ?? ''));
if ($since === '') {
    http_response_code(400);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "# missing since (UTC ISO8601, e.g. 2026-05-01T00:00:00Z)\n";
    exit;
}
try {
    $dt = new DateTimeImmutable($since, new DateTimeZone('UTC'));
} catch (Throwable $e) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "# invalid since\n";
    exit;
}
$sinceSql = $dt->format('Y-m-d H:i:s');

$limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 200;
$limit = max(1, min(500, $limit));

$fmt = strtolower(trim((string) ($_GET['format'] ?? 'json')));
if ($fmt !== 'json' && $fmt !== 'jsonl') {
    http_response_code(400);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "# format must be json or jsonl\n";
    exit;
}

$rows = st_integrations_events_export($db, $sinceSql, $limit);

$flatScope = false;
if ($fmt === 'json') {
    $flatScope = ! isset($_GET['flat_scope']) || (string) $_GET['flat_scope'] !== '0';
} else {
    $flatScope = isset($_GET['flat_scope']) && (string) $_GET['flat_scope'] === '1';
}
if ($flatScope) {
    $rows = array_map(static function (array $ev): array {
        return st_reporting_event_envelope_scope_fields($ev);
    }, $rows);
}

header('Cache-Control: no-store');
if ($fmt === 'jsonl') {
    header('Content-Type: application/x-ndjson; charset=UTF-8');
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    foreach ($rows as $ev) {
        $line = json_encode($ev, $flags);
        echo ($line !== false ? $line : '{}') . "\n";
    }
} else {
    header('Content-Type: application/json; charset=UTF-8');
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    $out = json_encode([
        'ok'             => true,
        'schema_version' => 'surveytrace.integrations.events_envelope.v1',
        'since'          => $sinceSql,
        'since_iso'      => $dt->format('Y-m-d\TH:i:s\Z'),
        'count'          => count($rows),
        'scope_id'       => null,
        'scope_name'     => null,
        'pull_client'    => st_integrations_pull_client_public($pullCtx),
        'events'         => $rows,
    ], $flags);
    echo $out !== false ? $out : '{"ok":false}';
}
