<?php
/**
 * SurveyTrace — /api/credential_profiles.php
 *
 * Admin-only credential profile metadata (CRUD) + optional encrypted secrets (slice 4 envelope).
 * Transport handshake test (slice 5) — SSH / SNMPv3 only; no plugin execution.
 *
 * GET  — list profiles or ?id=N for one; includes `encryption` status (no key material).
 * POST — JSON body: action create | update | set_enabled | delete | set_secret | clear_secret | test
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_secrets.php';
require_once __DIR__ . '/lib_credential_profiles.php';
require_once __DIR__ . '/lib_cred_secret_helper.php';

st_auth();
st_require_role(['admin']);
st_ensure_user_audit_schema();

$db = st_db();

if (! st_cred_profile_tables_ready($db)) {
    st_json(['ok' => false, 'error' => 'Credential profiles schema not available'], 503);
}

$actor = st_current_user();
$actorId = (int) ($actor['id'] ?? 0) > 0 ? (int) $actor['id'] : null;
$actorName = trim((string) ($actor['username'] ?? '')) !== '' ? trim((string) $actor['username']) : null;

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'GET') {
    $enc = st_cred_secret_status_via_helper();
    $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
    if ($id > 0) {
        $one = st_cred_profile_get_active($db, $id);
        if ($one === null) {
            st_json(['ok' => false, 'error' => 'Profile not found'], 404);
        }
        st_json(['ok' => true, 'profile' => $one, 'encryption' => $enc]);
    }
    st_json(['ok' => true, 'profiles' => st_cred_profile_list_active($db), 'encryption' => $enc]);
}

if ($method !== 'POST') {
    st_json(['ok' => false, 'error' => 'Method not allowed'], 405);
}

st_require_csrf();
$in = st_input();
if (isset($in['secret_ciphertext'])) {
    st_json(['ok' => false, 'error' => 'Do not send raw secret_ciphertext; use action set_secret with secret_material.'], 400);
}

$action = strtolower(trim((string) ($in['action'] ?? '')));
if (! in_array($action, ['set_secret', 'clear_secret', 'test'], true)) {
    if (isset($in['secret']) || isset($in['password'])) {
        st_json(['ok' => false, 'error' => 'Use action set_secret with a secret_material object (transport-specific keys).'], 400);
    }
}

if ($action === 'create') {
    $name = substr(trim((string) ($in['name'] ?? '')), 0, 200);
    $transport = strtolower(trim((string) ($in['transport'] ?? '')));
    if ($name === '' || ! in_array($transport, ST_CRED_PROFILE_TRANSPORTS, true)) {
        st_json(['ok' => false, 'error' => 'name and valid transport (ssh|snmpv3|winrm) required'], 400);
    }
    [$pj, $e1] = st_cred_profile_encode_json_field($in['principal_json'] ?? null, 'principal_json');
    if ($e1 !== null) {
        st_json(['ok' => false, 'error' => $e1], 400);
    }
    if ($pj !== null) {
        $dec = st_cred_profile_decode_json($pj);
        [$okP, $errP] = st_cred_profile_principal_allowed($dec);
        if (! $okP) {
            st_json(['ok' => false, 'error' => $errP ?? 'principal_json rejected'], 400);
        }
    }
    [$sj, $e2] = st_cred_profile_encode_json_field($in['scope_json'] ?? null, 'scope_json');
    if ($e2 !== null) {
        st_json(['ok' => false, 'error' => $e2], 400);
    }
    $en = isset($in['enabled']) ? ((bool) $in['enabled'] ? 1 : 0) : 1;
    try {
        $ins = $db->prepare(
            'INSERT INTO credential_profiles (name, transport, principal_json, scope_json, secret_ciphertext, enabled, created_by, created_at, updated_at)
             VALUES (?, ?, ?, ?, NULL, ?, ?, datetime(\'now\'), datetime(\'now\'))'
        );
        $ins->execute([$name, $transport, $pj, $sj, $en, $actorId > 0 ? $actorId : null]);
        $newId = (int) $db->lastInsertId();
    } catch (Throwable) {
        st_json(['ok' => false, 'error' => 'Could not create profile'], 500);
    }
    st_audit_log('credential_profile.created', $actorId, $actorName, null, null, [
        'credential_profile_id' => $newId,
        'name'                    => $name,
        'transport'               => $transport,
    ]);
    $row = st_cred_profile_get_active($db, $newId);
    st_json(['ok' => true, 'profile' => $row, 'encryption' => st_cred_secret_status_via_helper()]);
}

if ($action === 'update') {
    $id = (int) ($in['id'] ?? 0);
    if ($id < 1) {
        st_json(['ok' => false, 'error' => 'id required'], 400);
    }
    $cur = st_cred_profile_get_active($db, $id);
    if ($cur === null) {
        st_json(['ok' => false, 'error' => 'Profile not found'], 404);
    }
    $name = array_key_exists('name', $in) ? substr(trim((string) $in['name']), 0, 200) : (string) ($cur['name'] ?? '');
    $transport = array_key_exists('transport', $in)
        ? strtolower(trim((string) $in['transport']))
        : (string) ($cur['transport'] ?? '');
    if ($name === '' || ! in_array($transport, ST_CRED_PROFILE_TRANSPORTS, true)) {
        st_json(['ok' => false, 'error' => 'invalid name or transport'], 400);
    }
    $pj = null;
    $sj = null;
    if (array_key_exists('principal_json', $in)) {
        [$pj, $e1] = st_cred_profile_encode_json_field($in['principal_json'], 'principal_json');
        if ($e1 !== null) {
            st_json(['ok' => false, 'error' => $e1], 400);
        }
        if ($pj !== null) {
            [$okP, $errP] = st_cred_profile_principal_allowed(st_cred_profile_decode_json($pj));
            if (! $okP) {
                st_json(['ok' => false, 'error' => $errP ?? 'principal_json rejected'], 400);
            }
        }
    } else {
        $pj = json_encode($cur['principal_json'] ?? [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '{}';
    }
    if (array_key_exists('scope_json', $in)) {
        [$sj, $e2] = st_cred_profile_encode_json_field($in['scope_json'], 'scope_json');
        if ($e2 !== null) {
            st_json(['ok' => false, 'error' => $e2], 400);
        }
    } else {
        $sj = json_encode($cur['scope_json'] ?? [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '{}';
    }
    $en = array_key_exists('enabled', $in) ? ((bool) $in['enabled'] ? 1 : 0) : ((bool) ($cur['enabled'] ?? true) ? 1 : 0);
    try {
        $up = $db->prepare(
            'UPDATE credential_profiles SET name=?, transport=?, principal_json=?, scope_json=?, enabled=?, updated_at=datetime(\'now\') WHERE id=? AND deleted_at IS NULL'
        );
        $up->execute([$name, $transport, $pj, $sj, $en, $id]);
    } catch (Throwable) {
        st_json(['ok' => false, 'error' => 'Could not update profile'], 500);
    }
    st_audit_log('credential_profile.updated', $actorId, $actorName, null, null, [
        'credential_profile_id' => $id,
        'name'                    => $name,
        'transport'               => $transport,
    ]);
    st_json(['ok' => true, 'profile' => st_cred_profile_get_active($db, $id), 'encryption' => st_cred_secret_status_via_helper()]);
}

if ($action === 'set_secret') {
    $id = (int) ($in['id'] ?? 0);
    if ($id < 1) {
        st_json(['ok' => false, 'error' => 'id required'], 400);
    }
    $enc = st_cred_secret_status_via_helper();
    if (empty($enc['available'])) {
        st_json(['ok' => false, 'error' => 'Credential helper unavailable; configure sudoers helper.'], 503);
    }
    $cur = st_cred_profile_get_active($db, $id);
    if ($cur === null) {
        st_json(['ok' => false, 'error' => 'Profile not found'], 404);
    }
    $mat = $in['secret_material'] ?? null;
    if (! is_array($mat)) {
        st_audit_log('credential_profile.secret_set_failed', $actorId, $actorName, null, null, [
            'credential_profile_id' => $id,
            'reason'                => 'secret_material_invalid',
        ]);
        st_json(['ok' => false, 'error' => 'secret_material must be a JSON object with transport-specific keys'], 400);
    }
    $transport = (string) ($cur['transport'] ?? '');
    [$norm, $normErr] = st_cred_profile_normalize_secret_material($transport, $mat);
    if ($normErr !== null || $norm === []) {
        st_audit_log('credential_profile.secret_set_failed', $actorId, $actorName, null, null, [
            'credential_profile_id' => $id,
            'reason'                => 'normalize_failed',
        ]);
        st_json(['ok' => false, 'error' => $normErr ?? 'Invalid secret material'], 400);
    }
    $hadSecret = false;
    try {
        $chk = $db->prepare('SELECT length(COALESCE(secret_ciphertext, \'\')) AS n FROM credential_profiles WHERE id = ? AND deleted_at IS NULL LIMIT 1');
        $chk->execute([$id]);
        $hadSecret = (int) $chk->fetchColumn() > 0;
    } catch (Throwable) {
        // treat as no prior secret
    }
    $h = st_cred_secret_helper_call([
        'action' => 'encrypt_for_profile',
        'profile_id' => $id,
        'transport' => $transport,
        'secret_material' => $norm,
    ], 12);
    if (!$h['ok']) {
        $hc = (string) ($h['error_code'] ?? 'helper_error');
        st_audit_log('credential_profile.secret_set_failed', $actorId, $actorName, null, null, [
            'credential_profile_id' => $id,
            'reason'                => 'helper_encrypt_failed',
            'detail'                => $hc,
        ]);
        $safe = $hc === 'helper_unavailable' ? 'Credential helper unavailable; configure sudoers helper.' : 'Could not encrypt secret.';
        st_json(['ok' => false, 'error' => $safe, 'code' => $hc], 500);
    }
    $hp = is_array($h['payload'] ?? null) ? $h['payload'] : [];
    $envelope = isset($hp['envelope']) ? (string) $hp['envelope'] : '';
    if ($envelope === '') {
        st_json(['ok' => false, 'error' => 'Could not encrypt secret.', 'code' => 'protocol_error'], 500);
    }
    try {
        $up = $db->prepare('UPDATE credential_profiles SET secret_ciphertext = ?, updated_at = datetime(\'now\') WHERE id = ? AND deleted_at IS NULL');
        $up->execute([$envelope, $id]);
    } catch (Throwable) {
        st_audit_log('credential_profile.secret_set_failed', $actorId, $actorName, null, null, [
            'credential_profile_id' => $id,
            'reason'                => 'db_update_failed',
        ]);
        st_json(['ok' => false, 'error' => 'Could not store encrypted secret'], 500);
    }
    $logEv = $hadSecret ? 'credential_profile.secret_replaced' : 'credential_profile.secret_set';
    st_audit_log($logEv, $actorId, $actorName, null, null, [
        'credential_profile_id' => $id,
        'transport'             => $transport,
    ]);
    st_json(['ok' => true, 'profile' => st_cred_profile_get_active($db, $id), 'encryption' => st_cred_secret_status_via_helper()]);
}

if ($action === 'clear_secret') {
    $id = (int) ($in['id'] ?? 0);
    if ($id < 1) {
        st_json(['ok' => false, 'error' => 'id required'], 400);
    }
    if (st_cred_profile_get_active($db, $id) === null) {
        st_json(['ok' => false, 'error' => 'Profile not found'], 404);
    }
    $hadSecret = false;
    try {
        $chk = $db->prepare('SELECT length(COALESCE(secret_ciphertext, \'\')) AS n FROM credential_profiles WHERE id = ? AND deleted_at IS NULL LIMIT 1');
        $chk->execute([$id]);
        $hadSecret = (int) $chk->fetchColumn() > 0;
    } catch (Throwable) {
        // ignore
    }
    try {
        $db->prepare('UPDATE credential_profiles SET secret_ciphertext = NULL, updated_at = datetime(\'now\') WHERE id = ? AND deleted_at IS NULL')->execute([$id]);
    } catch (Throwable) {
        st_json(['ok' => false, 'error' => 'Could not clear secret'], 500);
    }
    if ($hadSecret) {
        st_audit_log('credential_profile.secret_cleared', $actorId, $actorName, null, null, [
            'credential_profile_id' => $id,
        ]);
    }
    st_json(['ok' => true, 'profile' => st_cred_profile_get_active($db, $id), 'encryption' => st_cred_secret_status_via_helper()]);
}

if ($action === 'test') {
    require_once __DIR__ . '/lib_credential_profile_transport_test.php';
    $out = st_cred_profile_transport_test_run($db, $in, $actorId, $actorName);
    st_json($out['payload'], $out['http_status']);
}

if ($action === 'set_enabled') {
    $id = (int) ($in['id'] ?? 0);
    $en = isset($in['enabled']) ? ((bool) $in['enabled'] ? 1 : 0) : -1;
    if ($id < 1 || $en < 0) {
        st_json(['ok' => false, 'error' => 'id and enabled required'], 400);
    }
    if (st_cred_profile_get_active($db, $id) === null) {
        st_json(['ok' => false, 'error' => 'Profile not found'], 404);
    }
    try {
        $db->prepare('UPDATE credential_profiles SET enabled=?, updated_at=datetime(\'now\') WHERE id=? AND deleted_at IS NULL')->execute([$en, $id]);
    } catch (Throwable) {
        st_json(['ok' => false, 'error' => 'Could not update enabled flag'], 500);
    }
    $logAction = $en ? 'credential_profile.enabled' : 'credential_profile.disabled';
    st_audit_log($logAction, $actorId, $actorName, null, null, ['credential_profile_id' => $id]);
    st_json(['ok' => true, 'profile' => st_cred_profile_get_active($db, $id), 'encryption' => st_cred_secret_status_via_helper()]);
}

if ($action === 'delete') {
    $id = (int) ($in['id'] ?? 0);
    if ($id < 1) {
        st_json(['ok' => false, 'error' => 'id required'], 400);
    }
    if (st_cred_profile_get_active($db, $id) === null) {
        st_json(['ok' => false, 'error' => 'Profile not found'], 404);
    }
    $refs = st_cred_profile_job_ref_count($db, $id);
    try {
        if ($refs === 0) {
            $db->prepare('DELETE FROM credential_profiles WHERE id = ? AND deleted_at IS NULL')->execute([$id]);
            st_audit_log('credential_profile.deleted', $actorId, $actorName, null, null, [
                'credential_profile_id' => $id,
            ]);
            st_json(['ok' => true, 'deleted' => true, 'archived' => false]);
        }
        $db->prepare(
            "UPDATE credential_profiles SET deleted_at = datetime('now'), enabled = 0, updated_at = datetime('now') WHERE id = ? AND deleted_at IS NULL"
        )->execute([$id]);
        st_audit_log('credential_profile.archived', $actorId, $actorName, null, null, [
            'credential_profile_id' => $id,
            'credential_check_jobs' => $refs,
        ]);
        st_json(['ok' => true, 'deleted' => false, 'archived' => true, 'credential_check_jobs' => $refs]);
    } catch (Throwable) {
        st_json(['ok' => false, 'error' => 'Could not delete or archive profile'], 500);
    }
}

st_json(['ok' => false, 'error' => 'Unknown action'], 400);
