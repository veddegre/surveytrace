<?php
/**
 * Normalized software inventory API (bounded reads; no raw artifacts).
 *
 * GET ?asset_id=N&q=&limit=&offset= — list active packages for one asset (prefix search on normalized_name).
 * GET ?action=assets_with_package&ecosystem=dpkg&name=libc&limit=20 — distinct assets with active name prefix.
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_software_inventory.php';

st_auth();
st_require_role(['viewer', 'scan_editor', 'admin']);

$db = st_db();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET') {
    st_json(['ok' => false, 'error' => 'Method not allowed'], 405);
}

$action = isset($_GET['action']) ? strtolower(trim((string) $_GET['action'])) : '';

if ($action === 'assets_with_package') {
    $eco = isset($_GET['ecosystem']) ? (string) $_GET['ecosystem'] : '';
    $name = isset($_GET['name']) ? (string) $_GET['name'] : '';
    $lim = isset($_GET['limit']) ? (int) $_GET['limit'] : 40;
    if (! st_si_tables_ready($db)) {
        st_json(['ok' => false, 'error' => 'Software inventory schema not available'], 503);
    }
    $hits = st_si_assets_with_package_name_prefix($db, $eco, $name, $lim);
    st_json(['ok' => true, 'assets' => $hits]);
}

$assetId = isset($_GET['asset_id']) ? (int) $_GET['asset_id'] : 0;
if ($assetId < 1) {
    st_json(['ok' => false, 'error' => 'asset_id required'], 400);
}
if (! st_si_tables_ready($db)) {
    st_json(['ok' => false, 'error' => 'Software inventory schema not available'], 503);
}

$q = isset($_GET['q']) ? (string) $_GET['q'] : '';
$limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 80;
$offset = isset($_GET['offset']) ? (int) $_GET['offset'] : 0;
$limit = max(1, min(500, $limit));
$offset = max(0, min(1_000_000, $offset));

$rows = st_si_list_for_asset($db, $assetId, $limit, $offset, $q);
$totalActive = st_si_active_count_for_asset($db, $assetId);
$latest = st_si_latest_last_seen_for_asset($db, $assetId);

st_json([
    'ok'                  => true,
    'asset_id'            => $assetId,
    'active_total'        => $totalActive,
    'latest_last_seen_at' => $latest,
    'limit'               => $limit,
    'offset'              => $offset,
    'packages'            => $rows,
]);
