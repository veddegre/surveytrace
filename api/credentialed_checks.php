<?php
/**
 * SurveyTrace — GET /api/credentialed_checks.php
 *
 * Admin-only read-only credentialed-check plugin registry (metadata + manifests).
 * No execution, no credentials, no profile CRUD.
 *
 * Query:
 *   plugins=1 (default when no plugin_key) — list plugins
 *   plugin_key=... — single plugin (latest version if version omitted)
 *   version=... — optional with plugin_key
 *   transport=... — filter list
 *   state=... — filter list (e.g. stable)
 *   include_disabled=1 — include rows with state disabled
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_credentialed_checks.php';

st_auth();
st_require_role(['admin']);
st_method('GET');

$db = st_db();

if (! st_cred_tables_ready($db)) {
    st_json(['ok' => false, 'error' => 'Credentialed checks schema not available'], 503);
}

$pluginKey = trim((string) ($_GET['plugin_key'] ?? ''));
if ($pluginKey !== '') {
    $ver = isset($_GET['version']) ? trim((string) $_GET['version']) : null;
    $ver = ($ver === '') ? null : $ver;
    $one = st_cred_get_plugin($db, $pluginKey, $ver);
    if ($one === null) {
        st_json(['ok' => false, 'error' => 'Plugin not found'], 404);
    }
    st_json(['ok' => true, 'plugin' => $one]);
}

$filters = [];
$t = trim((string) ($_GET['transport'] ?? ''));
if ($t !== '') {
    $filters['transport'] = $t;
}
$s = trim((string) ($_GET['state'] ?? ''));
if ($s !== '') {
    $filters['state'] = $s;
}
if (($_GET['include_disabled'] ?? '') === '1') {
    $filters['include_disabled'] = true;
}

$list = st_cred_list_plugins($db, $filters);
st_json(['ok' => true, 'plugins' => $list, 'count' => count($list)]);
