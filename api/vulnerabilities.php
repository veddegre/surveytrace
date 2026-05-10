<?php
/**
 * Bounded vulnerability / advisory correlation reads (inventory-driven; no raw feeds in default paths).
 *
 * GET ?action=list_for_asset&asset_id=&limit=&offset=
 * GET ?action=assets_for_advisory&advisory_id=&limit=&offset=
 * GET ?action=advisory_detail&id=
 * GET ?action=top_packages&limit=
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_vulnerability_correlation.php';

st_auth();
st_require_role(['viewer', 'scan_editor', 'admin']);

$db = st_db();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET') {
    st_json(['ok' => false, 'error' => 'Method not allowed'], 405);
}

if (! st_vuln_tables_ready($db)) {
    st_json(['ok' => false, 'error' => 'Vulnerability correlation schema not available'], 503);
}

$action = isset($_GET['action']) ? strtolower(trim((string) $_GET['action'])) : '';
if ($action === '') {
    $action = 'list_for_asset';
}
if (! in_array($action, ['list_for_asset', 'assets_for_advisory', 'advisory_detail', 'top_packages'], true)) {
    st_json(['ok' => false, 'error' => 'Unknown action'], 400);
}

if ($action === 'top_packages') {
    $lim = isset($_GET['limit']) ? (int) $_GET['limit'] : 20;
    $rows = st_vuln_top_packages($db, $lim);
    st_json(['ok' => true, 'packages' => $rows]);
}

if ($action === 'advisory_detail') {
    $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
    if ($id < 1) {
        st_json(['ok' => false, 'error' => 'id required'], 400);
    }
    $row = st_vuln_advisory_detail($db, $id);
    if ($row === null) {
        st_json(['ok' => false, 'error' => 'Not found'], 404);
    }
    if (isset($row['description']) && is_string($row['description'])) {
        $row['description'] = strip_tags($row['description']);
        if (strlen($row['description']) > 8000) {
            $row['description'] = substr($row['description'], 0, 8000);
        }
    }
    if (isset($row['references_json']) && is_string($row['references_json'])) {
        if (strlen($row['references_json']) > 24_000) {
            $row['references_json'] = substr($row['references_json'], 0, 24_000);
        }
    }
    $rules = [];
    try {
        $st = $db->prepare(
            'SELECT id, ecosystem, normalized_name, version_operator, version_value, distro_release, architecture, fixed_version
             FROM vulnerability_advisory_packages WHERE advisory_id = ? ORDER BY ecosystem ASC, normalized_name ASC LIMIT 100'
        );
        $st->execute([$id]);
        $rules = array_values(array_filter(array_map(
            static fn ($r) => is_array($r) ? $r : null,
            $st->fetchAll(PDO::FETCH_ASSOC) ?: []
        )));
    } catch (Throwable $e) {
        $rules = [];
    }
    st_json(['ok' => true, 'advisory' => $row, 'package_rules' => $rules]);
}

if ($action === 'assets_for_advisory') {
    $id = isset($_GET['advisory_id']) ? (int) $_GET['advisory_id'] : 0;
    if ($id < 1) {
        st_json(['ok' => false, 'error' => 'advisory_id required'], 400);
    }
    $limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 40;
    $offset = isset($_GET['offset']) ? (int) $_GET['offset'] : 0;
    $rows = st_vuln_assets_for_advisory($db, $id, $limit, $offset);
    st_json(['ok' => true, 'advisory_id' => $id, 'assets' => $rows]);
}

$assetId = isset($_GET['asset_id']) ? (int) $_GET['asset_id'] : 0;
if ($assetId < 1) {
    st_json(['ok' => false, 'error' => 'asset_id required'], 400);
}
$limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 50;
$offset = isset($_GET['offset']) ? (int) $_GET['offset'] : 0;
$rows = st_vuln_list_for_asset($db, $assetId, $limit, $offset);
try {
    $cst = $db->prepare("SELECT COUNT(*) FROM asset_vulnerabilities WHERE asset_id = ? AND status = 'affected'");
    $cst->execute([$assetId]);
    $total = (int) $cst->fetchColumn();
} catch (Throwable $e) {
    $total = count($rows);
}
st_json([
    'ok'         => true,
    'asset_id'   => $assetId,
    'affected_total' => $total,
    'limit'      => max(1, min(200, $limit)),
    'offset'     => max(0, $offset),
    'rows'       => $rows,
]);
