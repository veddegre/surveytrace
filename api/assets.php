<?php
/**
 * SurveyTrace — GET /api/assets.php
 *
 * Returns the full asset inventory with filtering, sorting, and pagination.
 * Also supports PUT to update asset metadata (category override, notes, scan locks).
 * PUT may include `unlock`: ["hostname","category","vendor"] to allow scans to refresh
 * those fields again, or per-field `hostname_locked` / `category_locked` / `vendor_locked` as booleans.
 * Hostname/category/vendor locks are set to 1 only when that field's value changes in the same request;
 * use explicit `*_locked` to lock without editing the value.
 *
 * GET query params:
 *   q          — free-text search across ip, hostname, vendor, model, mac
 *   category   — srv|ws|net|iot|ot|voi|prn|hv|unk
 *   severity   — critical|high|medium|low|none
 *   port       — filter assets with this port open (integer)
 *   since_days — only assets seen in last N days
 *   new_only   — "1" = only assets first seen in last 24h
 *   device_id  — if > 0, only assets for this logical device
 *   lifecycle_status — active|stale|retired (optional)
 *   sort       — ip|device_id|hostname|category|top_cvss|last_seen|first_seen|vendor|open_findings|zabbix_problem_count|scope_name (default: ip)
 *   order      — asc|desc (default: asc)
 *   page       — 1-based (default: 1)
 *   per_page   — 1–200 (default: 50)
 *   id         — fetch a single asset by ID (returns full detail with findings)
 *
 * Response (list):
 * {
 *   "total": 187, "page": 1, "pages": 4, "per_page": 50,
 *   "assets": [{
 *     "id", "device_id", "ip", "hostname", "mac", "mac_vendor", "category",
 *     "vendor", "model", "os_guess", "cpe",
 *     "open_ports",     // decoded array
 *     "banners",        // decoded object
 *     "top_cve", "top_cvss", "severity",
 *     "open_findings",  // count of unresolved CVEs
 *     "first_seen", "last_seen", "notes"
 *   }]
 * }
 *
 * Single asset (?id=N) adds:
 *   "findings": [{cve_id, cvss, severity, description, published, resolved}]
 *   "port_history": [{ports, seen_at}]
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_zabbix.php';
require_once __DIR__ . '/lib_scan_scopes.php';
st_auth();
st_require_role(['viewer', 'scan_editor', 'admin']);

/**
 * Parse explicit per-field lock from JSON body. Missing key => leave lock unchanged (null).
 *
 * @param array<string,mixed> $body
 */
function st_asset_lock_tristate(array $body, string $key): ?int {
    if (!array_key_exists($key, $body)) {
        return null;
    }
    $v = $body[$key];
    if ($v === true || $v === 1 || $v === '1') {
        return 1;
    }
    if ($v === false || $v === 0 || $v === '0') {
        return 0;
    }
    if (is_string($v)) {
        $s = strtolower(trim($v));
        if ($s === 'true' || $s === 'yes') {
            return 1;
        }
        if ($s === 'false' || $s === 'no' || $s === '') {
            return 0;
        }
    }

    return null;
}

// ---------------------------------------------------------------------------
// PUT — update asset metadata (category, hostname, notes, lock/unlock)
// Body may include:
//   unlock: ["hostname","category","vendor"] — clear per-field scan lock (values unchanged)
//   hostname_locked / category_locked / vendor_locked — explicit 0|1|false|true
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    st_require_csrf();
    st_require_role(['scan_editor', 'admin']);
    $body     = st_input();
    $asset_id = st_int('id', 0, 1);
    if (!$asset_id) st_json(['error' => 'id required for PUT'], 400);

    $db = st_db();
    $curStmt = $db->prepare(
        'SELECT id, ip, hostname, category, vendor, notes, hostname_locked, category_locked, vendor_locked FROM assets WHERE id = ? LIMIT 1'
    );
    $curStmt->execute([$asset_id]);
    $before = $curStmt->fetch(PDO::FETCH_ASSOC);
    if (!$before) {
        st_json(['error' => 'Asset not found'], 404);
    }

    $allowed_cats = ['srv','ws','net','iot','ot','voi','prn','hv','unk'];
    $updates = [];
    $params  = [];

    $unlockFields = [];
    if (array_key_exists('unlock', $body)) {
        if (!is_array($body['unlock'])) {
            st_json(['error' => 'unlock must be a JSON array of field names'], 400);
        }
        foreach ($body['unlock'] as $u) {
            $k = strtolower(trim((string) $u));
            if (in_array($k, ['hostname', 'category', 'vendor'], true)) {
                $unlockFields[$k] = true;
            }
        }
    }

    $lockH = null;
    $lockC = null;
    $lockV = null;

    // Only set scan locks when the operator actually changes the field value (not on unrelated saves).
    if (isset($body['category']) && in_array($body['category'], $allowed_cats, true)) {
        $newCat = (string) $body['category'];
        if ($newCat !== (string) ($before['category'] ?? '')) {
            $updates[]      = 'category = :cat';
            $params[':cat'] = $newCat;
            $lockC          = 1;
        }
    }
    if (array_key_exists('hostname', $body)) {
        $hostTrim = substr(trim((string) $body['hostname']), 0, 253);
        if ($hostTrim !== trim((string) ($before['hostname'] ?? ''))) {
            $updates[]       = 'hostname = :host';
            $params[':host'] = $hostTrim;
            $lockH           = $hostTrim !== '' ? 1 : 0;
        }
    }
    if (isset($body['notes'])) {
        $updates[]           = 'notes = :notes';
        $params[':notes']    = substr(trim($body['notes']), 0, 2000);
    }
    if (array_key_exists('vendor', $body)) {
        $vtrim = substr(trim((string) $body['vendor']), 0, 200);
        if ($vtrim !== trim((string) ($before['vendor'] ?? ''))) {
            $updates[]         = 'vendor = :vendor';
            $params[':vendor'] = $vtrim;
            $lockV             = $vtrim !== '' ? 1 : 0;
        }
    }

    $tH = st_asset_lock_tristate($body, 'hostname_locked');
    if ($tH !== null) {
        $lockH = $tH;
    }
    $tC = st_asset_lock_tristate($body, 'category_locked');
    if ($tC !== null) {
        $lockC = $tC;
    }
    $tV = st_asset_lock_tristate($body, 'vendor_locked');
    if ($tV !== null) {
        $lockV = $tV;
    }

    if (isset($body['owner'])) {
        $updates[]           = 'owner = :owner';
        $params[':owner']    = substr(trim((string)$body['owner']), 0, 200);
    }
    if (isset($body['business_unit'])) {
        $updates[]           = 'business_unit = :bu';
        $params[':bu']       = substr(trim((string)$body['business_unit']), 0, 200);
    }
    if (isset($body['criticality'])) {
        $crit = strtolower(trim((string)$body['criticality']));
        $crit_ok = ['low', 'medium', 'high', 'critical'];
        if (in_array($crit, $crit_ok, true)) {
            $updates[]        = 'criticality = :crit';
            $params[':crit']  = $crit;
        }
    }
    if (isset($body['environment'])) {
        $env = trim((string)$body['environment']);
        $updates[]           = 'environment = :env';
        $params[':env']      = $env !== '' ? substr($env, 0, 120) : 'unknown';
    }

    if (isset($unlockFields['hostname'])) {
        $lockH = 0;
    }
    if (isset($unlockFields['category'])) {
        $lockC = 0;
    }
    if (isset($unlockFields['vendor'])) {
        $lockV = 0;
    }

    if ($lockH !== null) {
        $updates[]        = 'hostname_locked = :lh';
        $params[':lh']    = (int) $lockH;
    }
    if ($lockC !== null) {
        $updates[]        = 'category_locked = :lc';
        $params[':lc']    = (int) $lockC;
    }
    if ($lockV !== null) {
        $updates[]        = 'vendor_locked = :lv';
        $params[':lv']    = (int) $lockV;
    }

    if ($updates === []) {
        st_json(['error' => 'No updatable fields provided'], 400);
    }

    $params[':id'] = $asset_id;
    $db->prepare('UPDATE assets SET ' . implode(', ', $updates) . ' WHERE id = :id')->execute($params);

    $stmt = $db->prepare('SELECT * FROM assets WHERE id = ?');
    $stmt->execute([$asset_id]);
    $asset = $stmt->fetch();
    if (!$asset) st_json(['error' => 'Asset not found'], 404);

    $actor = st_current_user();
    $aidActor = (int) ($actor['id'] ?? 0);
    $anActor = (string) ($actor['username'] ?? '');

    $afterH = (int) ($asset['hostname_locked'] ?? 0);
    $afterC = (int) ($asset['category_locked'] ?? 0);
    $afterV = (int) ($asset['vendor_locked'] ?? 0);
    $beforeH = (int) ($before['hostname_locked'] ?? 0);
    $beforeC = (int) ($before['category_locked'] ?? 0);
    $beforeV = (int) ($before['vendor_locked'] ?? 0);

    $logLockChange = static function (
        PDO $db,
        string $field,
        int $prevLock,
        int $newLock,
        array $beforeRow,
        int $assetId,
        int $actorId,
        string $actorName
    ): void {
        if ($prevLock === $newLock) {
            return;
        }
        $action = $newLock === 1 ? 'locked' : 'unlocked';
        $ip = (string) ($beforeRow['ip'] ?? '');
        st_audit_log('asset.field_lock_change', $actorId, $actorName !== '' ? $actorName : null, null, null, [
            'asset_id'       => $assetId,
            'ip'             => $ip,
            'field'          => $field,
            'action'         => $action,
            'previous_lock'  => $prevLock,
            'new_lock'       => $newLock,
            'previous_value' => substr((string) ($beforeRow[$field] ?? ''), 0, 400),
        ]);
        $msg = sprintf(
            'Asset id=%d ip=%s: %s %s (scan lock %d→%d)',
            $assetId,
            $ip,
            $field,
            $action,
            $prevLock,
            $newLock
        );
        try {
            $db->prepare('INSERT INTO scan_log (job_id, level, ip, message) VALUES (NULL, ?, ?, ?)')
                ->execute(['INFO', $ip, $msg]);
        } catch (Throwable $e) {
            // scan_log may be missing on degenerate installs
        }
    };

    $logLockChange($db, 'hostname', $beforeH, $afterH, $before, $asset_id, $aidActor, $anActor);
    $logLockChange($db, 'category', $beforeC, $afterC, $before, $asset_id, $aidActor, $anActor);
    $logLockChange($db, 'vendor', $beforeV, $afterV, $before, $asset_id, $aidActor, $anActor);

    st_json(['ok' => true, 'asset' => decode_asset($asset)]);
}

// ---------------------------------------------------------------------------
// POST — bulk set inventory scope_id (manual; server validates ids + scope)
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    st_require_csrf();
    st_require_role(['scan_editor', 'admin']);
    $dbPost = st_db();
    $bodyPost = st_input();
    $postAction = strtolower(trim((string) ($_GET['action'] ?? ($bodyPost['action'] ?? ''))));
    if ($postAction !== 'set_scope_bulk') {
        st_json(['ok' => false, 'error' => 'Unsupported POST action'], 400);
    }
    $confirm = $bodyPost['confirm'] ?? false;
    if (! ($confirm === true || $confirm === 1 || $confirm === '1')) {
        st_json(['ok' => false, 'error' => 'confirm must be true to apply bulk scope changes'], 400);
    }
    if (! st_assets_has_scope_id($dbPost)) {
        st_json(['ok' => false, 'error' => 'assets.scope_id is not available (run migrations)'], 400);
    }
    $scopeRaw = $bodyPost['scope_id'] ?? null;
    $clearScope = ($scopeRaw === null || $scopeRaw === '' || $scopeRaw === false);
    $newScopeId = $clearScope ? 0 : (int) $scopeRaw;
    if (! $clearScope && $newScopeId <= 0) {
        st_json(['ok' => false, 'error' => 'scope_id must be a positive catalog id, or omit/null to clear scope'], 400);
    }
    if (! $clearScope) {
        $chkScope = $dbPost->prepare('SELECT 1 FROM scan_scopes WHERE id = ? LIMIT 1');
        $chkScope->execute([$newScopeId]);
        if ((int) $chkScope->fetchColumn() !== 1) {
            st_json(['ok' => false, 'error' => 'scope does not exist'], 400);
        }
    }
    $idsRaw = $bodyPost['asset_ids'] ?? null;
    if (! is_array($idsRaw) || $idsRaw === []) {
        st_json(['ok' => false, 'error' => 'asset_ids must be a non-empty array'], 400);
    }
    $assetIds = [];
    foreach ($idsRaw as $raw) {
        $aid = (int) $raw;
        if ($aid > 0) {
            $assetIds[] = $aid;
        }
    }
    $assetIds = array_values(array_unique($assetIds));
    if ($assetIds === []) {
        st_json(['ok' => false, 'error' => 'no valid asset_ids'], 400);
    }
    if (count($assetIds) > 500) {
        st_json(['ok' => false, 'error' => 'too many asset_ids (max 500 per request)'], 400);
    }
    $selPost = $dbPost->prepare('SELECT 1 FROM assets WHERE id = ? LIMIT 1');
    $selCur = $dbPost->prepare('SELECT COALESCE(scope_id, 0) AS sid FROM assets WHERE id = ? LIMIT 1');
    if ($clearScope) {
        $updPost = $dbPost->prepare('UPDATE assets SET scope_id = NULL WHERE id = ?');
    } else {
        $updPost = $dbPost->prepare('UPDATE assets SET scope_id = ? WHERE id = ?');
    }
    $updated = 0;
    $missing = 0;
    $unchanged = 0;
    foreach ($assetIds as $aid) {
        $selPost->execute([$aid]);
        if ((int) $selPost->fetchColumn() !== 1) {
            ++$missing;

            continue;
        }
        $selCur->execute([$aid]);
        $curSid = (int) $selCur->fetchColumn();
        if ($clearScope) {
            if ($curSid === 0) {
                ++$unchanged;

                continue;
            }
            $updPost->execute([$aid]);
        } else {
            if ($curSid === $newScopeId) {
                ++$unchanged;

                continue;
            }
            $updPost->execute([$newScopeId, $aid]);
        }
        ++$updated;
    }
    $actor = st_current_user();
    $aidActor = (int) ($actor['id'] ?? 0);
    $anActor = (string) ($actor['username'] ?? '');
    if ($updated > 0) {
        if ($clearScope) {
            st_audit_log('scope.assets_cleared', $aidActor, $anActor !== '' ? $anActor : null, null, null, [
                'asset_count' => $updated,
                'requested'   => count($assetIds),
                'missing'     => $missing,
                'unchanged'   => $unchanged,
            ]);
        } else {
            $sn = st_scan_scopes_resolve_name($dbPost, $newScopeId) ?? '';
            st_audit_log('scope.assets_assigned', $aidActor, $anActor !== '' ? $anActor : null, null, null, [
                'scope_id'    => $newScopeId,
                'scope_name'  => substr($sn, 0, 200),
                'asset_count' => $updated,
                'requested'   => count($assetIds),
                'missing'     => $missing,
                'unchanged'   => $unchanged,
            ]);
        }
    }
    st_json(['ok' => true, 'updated' => $updated, 'missing' => $missing, 'unchanged' => $unchanged]);
}

st_method('GET');

$db = st_db();

// ---------------------------------------------------------------------------
// Single asset detail
// ---------------------------------------------------------------------------
$single_id = st_int('id');
if ($single_id > 0) {
    $stmt = $db->prepare("SELECT * FROM assets WHERE id = ?");
    $stmt->execute([$single_id]);
    $asset = $stmt->fetch();
    if (!$asset) st_json(['error' => 'Asset not found'], 404);

    $asset = decode_asset($asset);

    // Findings for this asset
    $fstmt = $db->prepare("
        SELECT cve_id, cvss, severity, description, published, confirmed_at, resolved, notes
        FROM findings
        WHERE asset_id = ?
        ORDER BY cvss DESC, cve_id
    ");
    $fstmt->execute([$single_id]);
    $asset['findings'] = $fstmt->fetchAll();

    // Port history (last 20 snapshots)
    $phstmt = $db->prepare("
        SELECT ports, seen_at FROM port_history
        WHERE asset_id = ?
        ORDER BY seen_at DESC LIMIT 20
    ");
    $phstmt->execute([$single_id]);
    $asset['port_history'] = array_map(function($r) {
        $r['ports'] = json_decode($r['ports'] ?? '[]', true) ?: [];
        return $r;
    }, $phstmt->fetchAll());

    // Per-scan host history with change deltas (ports + CVEs)
    $hstmt = $db->prepare("
        SELECT
            sas.job_id,
            sas.ip,
            sas.hostname,
            sas.category,
            sas.vendor,
            sas.top_cve,
            sas.top_cvss,
            sas.open_ports,
            sj.status,
            sj.label,
            sj.created_at,
            sj.started_at,
            sj.finished_at,
            sj.profile,
            sj.scan_mode
        FROM scan_asset_snapshots sas
        JOIN scan_jobs sj ON sj.id = sas.job_id
        WHERE sas.asset_id = ?
        ORDER BY sas.job_id DESC
        LIMIT 40
    ");
    $hstmt->execute([$single_id]);
    $histRows = $hstmt->fetchAll();

    // Fallback for legacy data before scan_asset_snapshots existed
    if (!$histRows) {
        $hstmt = $db->prepare("
            SELECT
                ph.scan_id AS job_id,
                a.ip,
                a.hostname,
                a.category,
                a.vendor,
                a.top_cve,
                a.top_cvss,
                ph.ports AS open_ports,
                sj.status,
                sj.label,
                sj.created_at,
                sj.started_at,
                sj.finished_at,
                sj.profile,
                sj.scan_mode
            FROM port_history ph
            LEFT JOIN assets a ON a.id = ph.asset_id
            LEFT JOIN scan_jobs sj ON sj.id = ph.scan_id
            WHERE ph.asset_id = ?
              AND ph.scan_id IS NOT NULL
            ORDER BY ph.scan_id DESC, ph.seen_at DESC
            LIMIT 40
        ");
        $hstmt->execute([$single_id]);
        $histRows = $hstmt->fetchAll();
    }

    $scanHistory = [];
    foreach ($histRows as $r) {
        $jid = (int)($r['job_id'] ?? 0);
        if ($jid <= 0) continue;
        if (isset($scanHistory[$jid])) continue;
        $ports = json_decode((string)($r['open_ports'] ?? '[]'), true);
        if (!is_array($ports)) $ports = [];
        $ports = array_values(array_unique(array_map('intval', $ports)));
        sort($ports, SORT_NUMERIC);
        $scanHistory[$jid] = [
            'job_id'      => $jid,
            'status'      => (string)($r['status'] ?? ''),
            'label'       => (string)($r['label'] ?? ''),
            'created_at'  => $r['created_at'] ?? null,
            'started_at'  => $r['started_at'] ?? null,
            'finished_at' => $r['finished_at'] ?? null,
            'profile'     => $r['profile'] ?? null,
            'scan_mode'   => $r['scan_mode'] ?? null,
            'ip'          => (string)($r['ip'] ?? ''),
            'hostname'    => (string)($r['hostname'] ?? ''),
            'category'    => (string)($r['category'] ?? ''),
            'vendor'      => (string)($r['vendor'] ?? ''),
            'top_cve'     => (string)($r['top_cve'] ?? ''),
            'top_cvss'    => $r['top_cvss'] ?? null,
            'ports'       => $ports,
            'cves'        => [],
            'open_findings' => 0,
        ];
    }

    $fhs = $db->prepare("
        SELECT job_id, cve_id, cvss, severity, COALESCE(resolved,0) AS resolved
        FROM scan_finding_snapshots
        WHERE asset_id = ?
        ORDER BY job_id DESC, cvss DESC
        LIMIT 1000
    ");
    $fhs->execute([$single_id]);
    foreach ($fhs->fetchAll() as $fr) {
        $jid = (int)($fr['job_id'] ?? 0);
        if ($jid <= 0) continue;
        if (!isset($scanHistory[$jid])) {
            $scanHistory[$jid] = [
                'job_id' => $jid,
                'status' => '',
                'label' => '',
                'created_at' => null,
                'started_at' => null,
                'finished_at' => null,
                'profile' => null,
                'scan_mode' => null,
                'ip' => (string)($asset['ip'] ?? ''),
                'hostname' => (string)($asset['hostname'] ?? ''),
                'category' => (string)($asset['category'] ?? ''),
                'vendor' => (string)($asset['vendor'] ?? ''),
                'top_cve' => '',
                'top_cvss' => null,
                'ports' => [],
                'cves' => [],
                'open_findings' => 0,
            ];
        }
        $scanHistory[$jid]['cves'][] = [
            'cve_id'   => (string)($fr['cve_id'] ?? ''),
            'cvss'     => $fr['cvss'] ?? null,
            'severity' => (string)($fr['severity'] ?? ''),
            'resolved' => (int)($fr['resolved'] ?? 0),
        ];
    }

    usort($scanHistory, fn($a, $b) => ($b['job_id'] <=> $a['job_id']));
    for ($i = 0; $i < count($scanHistory); $i++) {
        $cur = $scanHistory[$i];
        $prev = $scanHistory[$i + 1] ?? null;
        $curPorts = $cur['ports'] ?? [];
        $prevPorts = $prev['ports'] ?? [];
        $curOpen = array_values(array_unique(array_map(
            fn($x) => (string)$x['cve_id'],
            array_filter($cur['cves'], fn($x) => (int)($x['resolved'] ?? 0) === 0)
        )));
        sort($curOpen, SORT_STRING);
        $prevOpen = $prev ? array_values(array_unique(array_map(
            fn($x) => (string)$x['cve_id'],
            array_filter($prev['cves'], fn($x) => (int)($x['resolved'] ?? 0) === 0)
        ))) : [];
        sort($prevOpen, SORT_STRING);
        $scanHistory[$i]['open_findings'] = count($curOpen);
        $scanHistory[$i]['changes'] = [
            'new_ports'      => array_values(array_diff($curPorts, $prevPorts)),
            'closed_ports'   => array_values(array_diff($prevPorts, $curPorts)),
            'new_cves'       => array_values(array_diff($curOpen, $prevOpen)),
            'resolved_cves'  => array_values(array_diff($prevOpen, $curOpen)),
        ];
        // Keep payload compact
        $scanHistory[$i]['cves'] = array_slice($scanHistory[$i]['cves'], 0, 20);
    }
    $asset['scan_history'] = array_slice($scanHistory, 0, 20);

    if (st_zabbix_table_ready($db)) {
        try {
            $zbx = st_zabbix_enrichment_for_asset($db, $single_id);
            if (is_array($zbx)) {
                $asset['zabbix'] = $zbx;
            }
        } catch (Throwable $e) {
            @error_log('SurveyTrace assets.php zabbix: ' . st_zabbix_redact_secrets($e->getMessage()));
        }
    }

    if (st_assets_has_scope_id($db)) {
        $sid = (int) ($asset['scope_id'] ?? 0);
        if ($sid > 0) {
            $nm = st_scan_scopes_resolve_name($db, $sid);
            $asset['scope_name'] = ($nm !== null && $nm !== '') ? $nm : ('Scope #' . $sid);
        } else {
            $asset['scope_name'] = null;
        }
    } else {
        $asset['scope_name'] = null;
    }

    st_json([
        'asset'                  => $asset,
        'asset_scope_assignable' => st_assets_has_scope_id($db),
    ]);
}

// ---------------------------------------------------------------------------
// List mode — build WHERE clause
// ---------------------------------------------------------------------------
$q          = st_str('q');
$category   = st_str('category', '', ['','srv','ws','net','iot','ot','voi','prn','hv','unk']);
$severity   = st_str('severity', '', ['','critical','high','medium','low','none']);
$port_filter= st_int('port');
$since_days = st_int('since_days');
$new_only   = st_str('new_only') === '1';
$ai_review  = st_str('ai_review') === '1';
$page       = st_int('page',     1,  1);
$per_page   = st_int('per_page', 50, 1, 200);
$offset     = ($page - 1) * $per_page;

$sort_order  = st_str('order', 'asc', ['asc','desc']) === 'desc' ? 'DESC' : 'ASC';

// Severity → CVSS range map
$sev_ranges = [
    'critical' => [9.0, 10.1],
    'high'     => [7.0,  9.0],
    'medium'   => [4.0,  7.0],
    'low'      => [0.1,  4.0],
];

$where  = ['1=1'];
$params = [];

if ($q !== '') {
    $where[]      = "(a.ip LIKE :q OR a.hostname LIKE :q OR a.vendor LIKE :q OR a.model LIKE :q OR a.mac LIKE :q OR a.cpe LIKE :q)";
    $params[':q'] = '%' . $q . '%';
}

if ($category !== '') {
    $where[]         = 'a.category = :cat';
    $params[':cat']  = $category;
}

if ($severity !== '') {
    if ($severity === 'none') {
        $where[] = '(a.top_cvss IS NULL OR a.top_cvss = 0)';
    } elseif (isset($sev_ranges[$severity])) {
        [$lo, $hi]      = $sev_ranges[$severity];
        $where[]        = 'a.top_cvss >= :slo AND a.top_cvss < :shi';
        $params[':slo'] = $lo;
        $params[':shi'] = $hi;
    }
}

if ($port_filter > 0) {
    // open_ports is JSON array — use LIKE as a simple substring match
    $where[]          = "a.open_ports LIKE :port";
    $params[':port']  = '%' . $port_filter . '%';
}

if ($since_days > 0) {
    $where[]          = "a.last_seen >= datetime('now', :days)";
    $params[':days']  = "-{$since_days} days";
}

if ($new_only) {
    $where[]          = "a.first_seen >= datetime('now', '-1 day')";
}
if ($ai_review) {
    $where[] = "(COALESCE(a.ai_last_attempted,0)=1 AND (COALESCE(a.ai_last_applied,0)=1 OR COALESCE(a.ai_last_confidence,0) < 0.80))";
}

$device_filter = st_int('device_id', 0, 0, PHP_INT_MAX);
if ($device_filter > 0) {
    $where[]           = 'a.device_id = :devid';
    $params[':devid']  = $device_filter;
}

$lifecycle_status = st_str('lifecycle_status', '', ['', 'active', 'stale', 'retired']);
if ($lifecycle_status !== '') {
    $where[]          = "COALESCE(a.lifecycle_status,'active') = :lfs";
    $params[':lfs']  = $lifecycle_status;
}

$zbxFilters = st_zabbix_filters_available_for_assets($db);
$zabbix_monitored = st_str('zabbix_monitored', '', ['', '0', '1']);
$zabbix_unavailable = st_str('zabbix_unavailable') === '1';
$zabbix_has_problems = st_str('zabbix_has_problems') === '1';
$zabbix_group = trim(st_str('zabbix_group'));
$zabbix_tag = trim(st_str('zabbix_tag'));
if ($zbxFilters) {
    if ($zabbix_monitored === '1') {
        $where[] = 'EXISTS (SELECT 1 FROM zabbix_asset_links lz1 WHERE lz1.asset_id = a.id)
            AND COALESCE(a.monitored_by_zabbix, 0) = 1';
    } elseif ($zabbix_monitored === '0') {
        $where[] = '(NOT EXISTS (SELECT 1 FROM zabbix_asset_links lz0 WHERE lz0.asset_id = a.id)
            OR (EXISTS (SELECT 1 FROM zabbix_asset_links lz0b WHERE lz0b.asset_id = a.id)
                AND COALESCE(a.monitored_by_zabbix, 0) = 0))';
    }
    if ($zabbix_unavailable) {
        $where[] = 'EXISTS (SELECT 1 FROM zabbix_asset_links lzu WHERE lzu.asset_id = a.id)
            AND COALESCE(a.monitored_by_zabbix, 0) = 1
            AND TRIM(COALESCE(a.zabbix_availability, \'\')) != \'\'
            AND LOWER(TRIM(COALESCE(a.zabbix_availability, \'\'))) != \'available\'';
    }
    if ($zabbix_has_problems) {
        $where[] = 'EXISTS (SELECT 1 FROM zabbix_asset_links lzp WHERE lzp.asset_id = a.id)
            AND COALESCE(a.zabbix_problem_count, 0) > 0';
    }
    if ($zabbix_group !== '') {
        $where[] = 'EXISTS (
            SELECT 1 FROM zabbix_asset_links lgg
            JOIN zabbix_host_groups gg ON gg.hostid = lgg.zabbix_hostid
            WHERE lgg.asset_id = a.id AND LOWER(gg.group_name) = LOWER(:zabbix_group)
        )';
        $params[':zabbix_group'] = $zabbix_group;
    }
    if ($zabbix_tag !== '') {
        if (str_contains($zabbix_tag, '=')) {
            [$tk, $tv] = array_map('trim', explode('=', $zabbix_tag, 2));
            if ($tk !== '') {
                $where[] = 'EXISTS (
                    SELECT 1 FROM zabbix_asset_links ltt
                    JOIN zabbix_host_tags tg ON tg.hostid = ltt.zabbix_hostid
                    WHERE ltt.asset_id = a.id
                      AND LOWER(tg.tag) = LOWER(:zabbix_tag_k)
                      AND LOWER(tg.value) = LOWER(:zabbix_tag_v)
                )';
                $params[':zabbix_tag_k'] = $tk;
                $params[':zabbix_tag_v'] = $tv;
            }
        } else {
            $where[] = 'EXISTS (
                SELECT 1 FROM zabbix_asset_links ltn
                JOIN zabbix_host_tags tn ON tn.hostid = ltn.zabbix_hostid
                WHERE ltn.asset_id = a.id AND LOWER(tn.tag) = LOWER(:zabbix_tag_name)
            )';
            $params[':zabbix_tag_name'] = $zabbix_tag;
        }
    }
}

$where_sql = implode(' AND ', $where);

$scopeSelectSql = '';
$scopeJoinSql = '';
if (st_assets_has_scope_id($db) && st_sqlite_table_exists($db, 'scan_scopes')) {
    $scopeSelectSql = ', sc.name AS scope_name';
    $scopeJoinSql = ' LEFT JOIN scan_scopes sc ON sc.id = a.scope_id ';
}

// For open_findings sort, we need the subquery in ORDER BY
$findings_subq = "(SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id AND f.resolved = 0)";

// Numeric IP sort — split into 4 integer octets, no REVERSE() needed
// Works by progressively stripping octets from left
$o1 = "CAST(substr(a.ip, 1, instr(a.ip,'.')-1) AS INTEGER)";
$s2 = "substr(a.ip, instr(a.ip,'.')+1)";
$o2 = "CAST(substr($s2, 1, instr($s2,'.')-1) AS INTEGER)";
$s3 = "substr($s2, instr($s2,'.')+1)";
$o3 = "CAST(substr($s3, 1, instr($s3,'.')-1) AS INTEGER)";
$o4 = "CAST(substr($s3, instr($s3,'.')+1) AS INTEGER)";
$ip_sort = "$o1 $sort_order, $o2 $sort_order, $o3 $sort_order, $o4 $sort_order";

$valid_sorts = ['ip', 'device_id', 'hostname', 'category', 'top_cvss', 'last_seen', 'first_seen', 'vendor', 'open_findings', 'zabbix_problem_count', 'scope_name'];
$sort_col    = st_str('sort', 'ip', $valid_sorts);
if ($sort_col === 'scope_name' && $scopeJoinSql === '') {
    $sort_col = 'ip';
}
if ($sort_col === 'zabbix_problem_count' && ! $zbxFilters) {
    $sort_col = 'ip';
}

$order_expr = match ($sort_col) {
    'ip'            => $ip_sort,
    'top_cvss'      => "a.top_cvss $sort_order NULLS LAST",
    'open_findings' => "$findings_subq $sort_order",
    'zabbix_problem_count' => "COALESCE(a.zabbix_problem_count, 0) $sort_order",
    'scope_name'    => "LOWER(COALESCE(sc.name, '')) $sort_order, a.id ASC",
    default         => "a.$sort_col $sort_order",
};

// ---------------------------------------------------------------------------
// Count
// ---------------------------------------------------------------------------
$count_stmt = $db->prepare("SELECT COUNT(*) FROM assets a WHERE $where_sql");
$count_stmt->execute($params);
$total = (int)$count_stmt->fetchColumn();

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------
$sql = "
    SELECT
        a.*,
        $findings_subq AS open_findings
        $scopeSelectSql
    FROM assets a
    $scopeJoinSql
    WHERE $where_sql
    ORDER BY $order_expr
    LIMIT :lim OFFSET :off
";

$stmt = $db->prepare($sql);
foreach ($params as $k => $v) $stmt->bindValue($k, $v);
$stmt->bindValue(':lim', $per_page, PDO::PARAM_INT);
$stmt->bindValue(':off', $offset,   PDO::PARAM_INT);
$stmt->execute();
$rows = array_map('decode_asset', $stmt->fetchAll());

// ---------------------------------------------------------------------------
// Category breakdown counts (for UI filter badges)
// ---------------------------------------------------------------------------
$cat_counts_raw = $db->query("SELECT category, COUNT(*) AS cnt FROM assets GROUP BY category")->fetchAll();
$cat_counts = [];
foreach ($cat_counts_raw as $r) $cat_counts[$r['category']] = (int)$r['cnt'];

st_json([
    'total'      => $total,
    'page'       => $page,
    'per_page'   => $per_page,
    'pages'      => (int)ceil(max(1, $total) / $per_page),
    'cat_counts' => $cat_counts,
    'assets'     => $rows,
    'zabbix_filters_available' => $zbxFilters,
    'assets_scope_column'      => st_assets_has_scope_id($db),
]);

// ---------------------------------------------------------------------------
// Helper: decode JSON columns and add derived fields
// ---------------------------------------------------------------------------
function decode_asset(array $a): array {
    if (isset($a['device_id']) && $a['device_id'] !== null && $a['device_id'] !== '') {
        $a['device_id'] = (int)$a['device_id'];
    }
    $a['open_ports']    = json_decode($a['open_ports'] ?? '[]', true) ?: [];
    $a['banners']       = json_decode($a['banners']    ?? '{}', true) ?: [];
    $a['ipv6_addrs']    = json_decode($a['ipv6_addrs'] ?? '[]', true) ?: [];
    $a['discovery_sources'] = json_decode($a['discovery_sources'] ?? '[]', true) ?: [];
    $a['open_findings'] = (int)($a['open_findings'] ?? 0);
    $a['top_cvss']      = $a['top_cvss'] ? (float)$a['top_cvss'] : null;
    $a['severity']      = $a['top_cvss'] ? st_severity($a['top_cvss']) : 'none';
    $a['ai_last_confidence'] = isset($a['ai_last_confidence']) ? (float)$a['ai_last_confidence'] : null;
    $a['ai_last_applied'] = isset($a['ai_last_applied']) ? (int)$a['ai_last_applied'] : 0;
    $a['ai_last_attempted'] = isset($a['ai_last_attempted']) ? (int)$a['ai_last_attempted'] : 0;
    $a['ai_last_rationale'] = (string)($a['ai_last_rationale'] ?? '');
    $a['ai_last_suggested_category'] = (string)($a['ai_last_suggested_category'] ?? '');
    $a['ai_last_reason'] = (string)($a['ai_last_reason'] ?? '');
    $a['lifecycle_status'] = (string)($a['lifecycle_status'] ?? 'active');
    $lr = $a['lifecycle_reason'] ?? null;
    $a['lifecycle_reason'] = $lr !== null && $lr !== '' ? (string)$lr : null;
    $a['missed_scan_count'] = (int)($a['missed_scan_count'] ?? 0);
    $a['retired_at'] = isset($a['retired_at']) && $a['retired_at'] !== '' ? $a['retired_at'] : null;
    $a['owner'] = isset($a['owner']) && $a['owner'] !== '' ? (string)$a['owner'] : null;
    $a['business_unit'] = isset($a['business_unit']) && $a['business_unit'] !== '' ? (string)$a['business_unit'] : null;
    $a['criticality'] = (string)($a['criticality'] ?? 'medium');
    $a['environment'] = (string)($a['environment'] ?? 'unknown');
    $a['hostname_locked'] = (int)($a['hostname_locked'] ?? 0);
    $a['category_locked'] = (int)($a['category_locked'] ?? 0);
    $a['vendor_locked'] = (int)($a['vendor_locked'] ?? 0);
    $ic = $a['identity_confidence'] ?? null;
    $a['identity_confidence'] = $ic !== null && $ic !== '' ? (float)$ic : null;
    $icr = $a['identity_confidence_reason'] ?? null;
    $a['identity_confidence_reason'] = $icr !== null && $icr !== '' ? (string)$icr : null;
    $a['last_expected_scan_id'] = isset($a['last_expected_scan_id']) && $a['last_expected_scan_id'] !== ''
        ? (int)$a['last_expected_scan_id'] : null;
    $a['last_expected_scan_at'] = isset($a['last_expected_scan_at']) && $a['last_expected_scan_at'] !== ''
        ? $a['last_expected_scan_at'] : null;
    $a['last_missed_scan_id'] = isset($a['last_missed_scan_id']) && $a['last_missed_scan_id'] !== ''
        ? (int)$a['last_missed_scan_id'] : null;
    $a['last_missed_scan_at'] = isset($a['last_missed_scan_at']) && $a['last_missed_scan_at'] !== ''
        ? $a['last_missed_scan_at'] : null;
    $fgRaw = $a['ai_findings_guidance_cache'] ?? null;
    $a['ai_findings_guidance'] = is_string($fgRaw) && $fgRaw !== ''
        ? (json_decode($fgRaw, true) ?: null)
        : null;
    $exRaw = $a['ai_host_explain_cache'] ?? null;
    $a['ai_host_explain'] = is_string($exRaw) && $exRaw !== ''
        ? (json_decode($exRaw, true) ?: null)
        : null;
    if (array_key_exists('monitored_by_zabbix', $a)) {
        $a['monitored_by_zabbix'] = ((int) ($a['monitored_by_zabbix'] ?? 0)) === 1;
    }
    if (array_key_exists('zabbix_availability', $a)) {
        $a['zabbix_availability'] = (string) ($a['zabbix_availability'] ?? '');
    }
    if (array_key_exists('zabbix_problem_count', $a)) {
        $a['zabbix_problem_count'] = (int) ($a['zabbix_problem_count'] ?? 0);
    }
    if (array_key_exists('scope_id', $a)) {
        $sv = $a['scope_id'];
        $a['scope_id'] = ($sv !== null && $sv !== '') ? (int) $sv : null;
    }
    if (array_key_exists('scope_name', $a)) {
        $sn = trim((string) ($a['scope_name'] ?? ''));
        $a['scope_name'] = $sn !== '' ? $sn : null;
    }
    return $a;
}
