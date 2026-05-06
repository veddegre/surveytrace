<?php
/**
 * SurveyTrace — GET /api/recon_diagnostics.php
 *
 * Admin-only read-only payload for trusted-data debugging:
 * OS/platform recon plus identity (canonical_hostname) detail when requested.
 *
 * Query:
 *   asset_id (required) — assets.id
 *   include_sources — "1" to include assertion_sources rows (capped)
 *
 * Optional maintenance (admin + CSRF POST only):
 *   action=trim_runs — deletes oldest reconciliation_runs beyond retention (see st_recon_trim_reconciliation_runs)
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_reconciliation.php';

st_auth();
st_require_role(['admin']);
st_method('GET', 'POST');

$db = st_db();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    st_require_csrf();
    $body = st_input();
    $action = strtolower(trim((string) ($body['action'] ?? '')));
    if ($action === 'trim_runs') {
        $keepRaw = $body['keep'] ?? 8000;
        $keep = max(1000, min(500000, (int) $keepRaw));
        $removed = st_recon_trim_reconciliation_runs($db, $keep);
        st_json(['ok' => true, 'removed_rows' => $removed, 'keep_newest' => $keep]);
    }
    st_json(['ok' => false, 'error' => 'Unknown action'], 400);
}

$assetId = st_int('asset_id', 0, 1);
if ($assetId <= 0) {
    st_json(['ok' => false, 'error' => 'asset_id required'], 400);
}

$chk = $db->prepare('SELECT 1 FROM assets WHERE id = ? LIMIT 1');
$chk->execute([$assetId]);
if ((int) $chk->fetchColumn() !== 1) {
    st_json(['ok' => false, 'error' => 'Asset not found'], 404);
}

$includeSources = st_str('include_sources') === '1';
$detail = st_recon_build_evidence_detail_for_asset($db, $assetId, 48, 20, $includeSources);
$identityDetail = st_recon_build_identity_recon_detail_for_asset($db, $assetId, 48, 20, $includeSources);

st_json([
    'ok'              => true,
    'asset_id'        => $assetId,
    'recon'           => $detail,
    'identity_recon'  => $identityDetail,
]);