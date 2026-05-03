<?php
/**
 * SurveyTrace — /api/scopes.php
 *
 * GET  — catalog: scopes, per-scope asset counts, reporting flags (viewer+)
 * POST — action=create|rename|delete (scan_editor+), CSRF required
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_scan_scopes.php';

st_auth();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$db = st_db();

if ($method === 'GET') {
    st_require_role(['viewer', 'scan_editor', 'admin']);
    $getAction = strtolower(trim((string) ($_GET['action'] ?? '')));
    if ($getAction === 'delete_impact') {
        st_require_role(['scan_editor', 'admin']);
        $sid = (int) ($_GET['scope_id'] ?? 0);
        if ($sid <= 0) {
            st_json(['ok' => false, 'error' => 'scope_id is required'], 400);
        }
        $chk = $db->prepare('SELECT 1 FROM scan_scopes WHERE id = ? LIMIT 1');
        $chk->execute([$sid]);
        if ((int) $chk->fetchColumn() !== 1) {
            st_json(['ok' => false, 'error' => 'scope not found'], 404);
        }
        $impact = st_scan_scopes_delete_impact_counts($db, $sid);
        $nm = st_scan_scopes_resolve_name($db, $sid);

        st_json([
            'ok'          => true,
            'scope_id'    => $sid,
            'scope_name'  => $nm,
            'impact'      => $impact,
        ]);
    }
    try {
        $scopes = st_scan_scopes_list($db);
        $defaultId = st_scan_scopes_default_id($db);
        $enabled = st_scan_scopes_table_scan_jobs_has_scope_id($db);
        $assetCounts = st_scan_scopes_asset_counts($db);
        $unscopedAssets = st_scan_scopes_unscoped_asset_count($db);
        $assetsScoped = st_assets_has_scope_id($db);
        /** @var array<string, int> */
        $assetCountsStr = [];
        foreach ($assetCounts as $sid => $cnt) {
            $assetCountsStr[(string) $sid] = $cnt;
        }
        $role = st_current_role();
        $canManage = in_array($role, ['scan_editor', 'admin'], true);
        $jobCountsStr = [];
        $scheduleCountsStr = [];
        if ($canManage) {
            foreach (st_scan_scopes_table_scope_id_group_counts($db, 'scan_jobs') as $k => $v) {
                $jobCountsStr[$k] = $v;
            }
            foreach (st_scan_scopes_table_scope_id_group_counts($db, 'scan_schedules') as $k => $v) {
                $scheduleCountsStr[$k] = $v;
            }
        }
        st_json([
            'ok'                    => true,
            'scopes'                => $scopes,
            'asset_counts'          => $assetCountsStr,
            'job_counts'            => $jobCountsStr,
            'schedule_counts'       => $scheduleCountsStr,
            'unscoped_asset_count'  => $unscopedAssets,
            'assets_scope_column'   => $assetsScoped,
            'default_scope_id'      => $defaultId,
            'scoping_enabled'       => $enabled,
        ]);
    } catch (Throwable $e) {
        @error_log('SurveyTrace scopes GET: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $e->getMessage()));
        $out = [
            'ok'                    => true,
            'scopes'                => [],
            'asset_counts'          => [],
            'job_counts'            => [],
            'schedule_counts'       => [],
            'unscoped_asset_count'  => 0,
            'assets_scope_column'   => false,
            'default_scope_id'      => null,
            'scoping_enabled'       => false,
            'scope_catalog_error'   => 'Scope catalog could not be read (database or migration issue).',
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
$action = strtolower(trim((string) ($_GET['action'] ?? ($body['action'] ?? ''))));

if ($action === 'create') {
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
        st_json(['ok' => false, 'error' => $e->getMessage()], 400);
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
}

if ($action === 'rename') {
    $scopeId = (int) ($body['scope_id'] ?? 0);
    $name = trim((string) ($body['name'] ?? ''));
    if ($scopeId <= 0) {
        st_json(['ok' => false, 'error' => 'scope_id is required'], 400);
    }
    if ($name === '') {
        st_json(['ok' => false, 'error' => 'name is required'], 400);
    }
    $oldName = st_scan_scopes_resolve_name($db, $scopeId) ?? '';
    try {
        st_scan_scopes_rename_row($db, $scopeId, $name);
    } catch (InvalidArgumentException $e) {
        st_json(['ok' => false, 'error' => $e->getMessage()], 400);
    } catch (Throwable $e) {
        st_json(['ok' => false, 'error' => 'Could not rename scope'], 500);
    }
    $actor = st_current_user();
    st_audit_log('scope.renamed', (int) ($actor['id'] ?? 0), (string) ($actor['username'] ?? ''), null, null, [
        'scope_id'   => $scopeId,
        'old_name'   => substr($oldName, 0, 200),
        'new_name'   => substr(trim($name), 0, 200),
    ]);
    st_json(['ok' => true]);
}

if ($action === 'delete') {
    $scopeId = (int) ($body['scope_id'] ?? 0);
    $confirm = $body['confirm'] ?? false;
    if ($scopeId <= 0) {
        st_json(['ok' => false, 'error' => 'scope_id is required'], 400);
    }
    if (! ($confirm === true || $confirm === 1 || $confirm === '1')) {
        st_json(['ok' => false, 'error' => 'confirm must be true to delete a scope'], 400);
    }
    $impact = st_scan_scopes_delete_impact_counts($db, $scopeId);
    $scopeName = st_scan_scopes_resolve_name($db, $scopeId) ?? '';
    try {
        st_scan_scopes_delete_row($db, $scopeId);
    } catch (InvalidArgumentException $e) {
        st_json(['ok' => false, 'error' => $e->getMessage()], 400);
    } catch (Throwable $e) {
        @error_log('SurveyTrace scopes delete: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $e->getMessage()));
        st_json(['ok' => false, 'error' => 'Could not delete scope'], 500);
    }
    $actor = st_current_user();
    st_audit_log('scope.deleted', (int) ($actor['id'] ?? 0), (string) ($actor['username'] ?? ''), null, null, [
        'scope_id'      => $scopeId,
        'scope_name'    => substr($scopeName, 0, 200),
        'assets_cleared' => $impact['assets'],
        'jobs_cleared'   => $impact['jobs'],
        'schedules_cleared' => $impact['schedules'],
        'baselines_removed' => $impact['baselines'],
        'zabbix_rules_removed' => $impact['zabbix_rules'],
    ]);
    st_json(['ok' => true]);
}

st_json(['ok' => false, 'error' => 'unknown action'], 400);
