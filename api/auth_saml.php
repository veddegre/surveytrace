<?php
/**
 * SurveyTrace — /api/auth_saml.php
 *
 * Header-based SAML bridge mode:
 * - GET ?start=1: redirects to configured SAML login URL (if present)
 * - GET ?callback=1 (or no query): trusts upstream-authenticated headers and creates session
 *
 * Intended for deployments where Apache/Nginx/Shibboleth/SSO gateway already validates SAML.
 */
require_once __DIR__ . '/db.php';

st_session_start();
st_session_touch_idle();

if (st_config('saml_enabled', '0') !== '1') {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'SAML is disabled'], 400);
}

$mode = strtolower(trim((string)st_config('auth_mode', 'session')));
if ($mode !== 'saml') {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'Auth mode is not SAML'], 400);
}

function st_saml_role_from_groups(array $groups): string {
    $mapRaw = trim((string)st_config('saml_role_map', ''));
    $normGroups = array_map(fn($g) => strtolower(trim((string)$g)), $groups);
    $fallback = 'viewer';
    foreach (array_filter(array_map('trim', explode(',', $mapRaw))) as $pair) {
        $parts = array_map('trim', explode(':', $pair, 2));
        if (count($parts) !== 2) continue;
        $ext = strtolower($parts[0]);
        $role = st_normalize_role($parts[1]);
        if ($ext === '*') $fallback = $role;
        if (in_array($ext, $normGroups, true)) return $role;
    }
    return $fallback;
}

if (isset($_GET['start'])) {
    $loginUrl = trim((string)st_config('saml_login_url', ''));
    st_release_session_lock();
    if ($loginUrl !== '') {
        header('Location: ' . $loginUrl, true, 302);
        exit;
    }
    st_json([
        'ok' => false,
        'error' => 'SAML login URL is not configured',
        'hint' => 'Configure saml_login_url in Settings or send users directly to your SAML-protected app URL.',
    ], 400);
}

$userHeader = trim((string)st_config('saml_username_header', 'X-Remote-User'));
$groupsHeader = trim((string)st_config('saml_groups_header', 'X-Remote-Groups'));
if ($userHeader === '') $userHeader = 'X-Remote-User';
if ($groupsHeader === '') $groupsHeader = 'X-Remote-Groups';

$serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $userHeader));
$groupKey = 'HTTP_' . strtoupper(str_replace('-', '_', $groupsHeader));
$username = trim((string)($_SERVER[$serverKey] ?? ''));
$groupsRaw = trim((string)($_SERVER[$groupKey] ?? ''));

if ($username === '') {
    st_release_session_lock();
    st_json([
        'ok' => false,
        'error' => 'SAML identity header missing',
        'required_header' => $userHeader,
    ], 401);
}

$groups = array_values(array_filter(array_map('trim', preg_split('/[,;|]/', $groupsRaw ?: '') ?: [])));
$role = st_saml_role_from_groups($groups);

$db = st_db();
$sel = $db->prepare("SELECT id, username, role, disabled FROM users WHERE auth_source='saml' AND lower(username)=lower(?) LIMIT 1");
$sel->execute([$username]);
$row = $sel->fetch();
if ($row) {
    if ((int)$row['disabled'] === 1) {
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'SAML user is disabled'], 403);
    }
    $db->prepare("UPDATE users SET role=?, updated_at=datetime('now'), last_login_at=datetime('now') WHERE id=?")
       ->execute([$role, (int)$row['id']]);
    st_set_session_user((int)$row['id'], (string)$row['username'], $role);
} else {
    $ins = $db->prepare("
        INSERT INTO users (username, role, auth_source, last_login_at)
        VALUES (?, ?, 'saml', datetime('now'))
    ");
    $ins->execute([$username, $role]);
    st_set_session_user((int)$db->lastInsertId(), $username, $role);
}

st_release_session_lock();
header('Location: /', true, 302);
exit;
