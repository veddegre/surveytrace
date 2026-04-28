<?php
/**
 * SurveyTrace — /api/auth_oidc.php
 *
 * GET /api/auth_oidc.php?start=1    -> redirects to provider authorize URL
 * GET /api/auth_oidc.php?callback=1 -> handles provider code callback
 */
require_once __DIR__ . '/db.php';

st_session_start();
st_session_touch_idle();

function st_http_json(string $url, array $headers = []): array {
    $ctx = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => implode("\r\n", array_merge(['Accept: application/json'], $headers)),
            'timeout' => 15,
        ],
    ]);
    $raw = @file_get_contents($url, false, $ctx);
    if ($raw === false) return [];
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
}

function st_http_form_post(string $url, array $form): array {
    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json",
            'content' => http_build_query($form),
            'timeout' => 20,
        ],
    ]);
    $raw = @file_get_contents($url, false, $ctx);
    if ($raw === false) return [];
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
}

function st_jwt_payload(string $jwt): array {
    $parts = explode('.', $jwt);
    if (count($parts) < 2) return [];
    $payload = strtr($parts[1], '-_', '+/');
    $payload .= str_repeat('=', (4 - (strlen($payload) % 4)) % 4);
    $raw = base64_decode($payload, true);
    if ($raw === false) return [];
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
}

function st_jwt_aud_matches(array $claims, string $clientId): bool {
    $aud = $claims['aud'] ?? null;
    if (is_array($aud)) return in_array($clientId, $aud, true);
    return is_string($aud) && hash_equals($aud, $clientId);
}

function st_role_from_claims(array $claims): string {
    $claimKey = trim((string)st_config('oidc_role_claim', 'groups'));
    $mapRaw = trim((string)st_config('oidc_role_map', ''));
    $items = $claims[$claimKey] ?? [];
    if (!is_array($items)) $items = [$items];
    $items = array_map(fn($v) => strtolower(trim((string)$v)), $items);
    $fallback = 'viewer';
    foreach (array_filter(array_map('trim', explode(',', $mapRaw))) as $pair) {
        $parts = array_map('trim', explode(':', $pair, 2));
        if (count($parts) !== 2) continue;
        $ext = strtolower($parts[0]);
        $role = st_normalize_role($parts[1]);
        if ($ext === '*') $fallback = $role;
        if (in_array($ext, $items, true)) return $role;
    }
    return $fallback;
}

if (st_config('oidc_enabled', '0') !== '1') {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'OIDC is disabled'], 400);
}

$issuer = rtrim(trim((string)st_config('oidc_issuer_url', '')), '/');
$clientId = trim((string)st_config('oidc_client_id', ''));
$clientSecret = trim((string)st_config('oidc_client_secret', ''));
$redirectUri = trim((string)st_config('oidc_redirect_uri', ''));
if ($issuer === '' || $clientId === '' || $clientSecret === '' || $redirectUri === '') {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'OIDC is not fully configured'], 400);
}

$discovery = st_http_json($issuer . '/.well-known/openid-configuration');
$authzEndpoint = (string)($discovery['authorization_endpoint'] ?? '');
$tokenEndpoint = (string)($discovery['token_endpoint'] ?? '');
$userInfoEndpoint = (string)($discovery['userinfo_endpoint'] ?? '');
if ($authzEndpoint === '' || $tokenEndpoint === '') {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'OIDC discovery failed'], 400);
}

if (isset($_GET['start'])) {
    $state = bin2hex(random_bytes(16));
    $nonce = bin2hex(random_bytes(16));
    $_SESSION['oidc_state'] = $state;
    $_SESSION['oidc_nonce'] = $nonce;
    st_release_session_lock();
    $url = $authzEndpoint . '?' . http_build_query([
        'client_id' => $clientId,
        'response_type' => 'code',
        'scope' => 'openid profile email',
        'redirect_uri' => $redirectUri,
        'state' => $state,
        'nonce' => $nonce,
    ]);
    header('Location: ' . $url, true, 302);
    exit;
}

if (isset($_GET['callback'])) {
    $state = (string)($_GET['state'] ?? '');
    $code = (string)($_GET['code'] ?? '');
    $savedState = (string)($_SESSION['oidc_state'] ?? '');
    $savedNonce = (string)($_SESSION['oidc_nonce'] ?? '');
    if ($state === '' || $code === '' || $savedState === '' || !hash_equals($savedState, $state)) {
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC state validation failed'], 400);
    }

    $token = st_http_form_post($tokenEndpoint, [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => $redirectUri,
        'client_id' => $clientId,
        'client_secret' => $clientSecret,
    ]);
    $idToken = (string)($token['id_token'] ?? '');
    if ($idToken === '') {
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC token exchange failed'], 400);
    }

    $claims = st_jwt_payload($idToken);
    $iss = (string)($claims['iss'] ?? '');
    $exp = (int)($claims['exp'] ?? 0);
    if ($iss !== '' && !hash_equals(rtrim($iss, '/'), $issuer)) {
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC issuer mismatch'], 400);
    }
    if ($exp > 0 && $exp < time()) {
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC token expired'], 400);
    }
    if (!st_jwt_aud_matches($claims, $clientId)) {
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC audience mismatch'], 400);
    }
    if (($claims['nonce'] ?? '') !== $savedNonce) {
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC nonce validation failed'], 400);
    }
    $sub = trim((string)($claims['sub'] ?? ''));
    if ($sub === '') {
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC subject missing'], 400);
    }

    if ($userInfoEndpoint !== '' && !empty($token['access_token'])) {
        $ui = st_http_json($userInfoEndpoint, ['Authorization: Bearer ' . $token['access_token']]);
        if ($ui) $claims = array_merge($claims, $ui);
    }
    $username = trim((string)($claims['preferred_username'] ?? ($claims['email'] ?? $sub)));
    $role = st_role_from_claims($claims);

    $db = st_db();
    $sel = $db->prepare("SELECT id, username, role, disabled FROM users WHERE auth_source='oidc' AND oidc_issuer=? AND oidc_sub=? LIMIT 1");
    $sel->execute([$issuer, $sub]);
    $row = $sel->fetch();
    if ($row) {
        if ((int)$row['disabled'] === 1) {
            st_release_session_lock();
            st_json(['ok' => false, 'error' => 'OIDC user is disabled'], 403);
        }
        $db->prepare("UPDATE users SET username=?, role=?, updated_at=datetime('now'), last_login_at=datetime('now') WHERE id=?")
           ->execute([$username, $role, (int)$row['id']]);
        st_set_session_user((int)$row['id'], $username, $role);
    } else {
        $ins = $db->prepare("
            INSERT INTO users (username, role, auth_source, oidc_issuer, oidc_sub, last_login_at)
            VALUES (?, ?, 'oidc', ?, ?, datetime('now'))
        ");
        $ins->execute([$username, $role, $issuer, $sub]);
        st_set_session_user((int)$db->lastInsertId(), $username, $role);
    }
    unset($_SESSION['oidc_state'], $_SESSION['oidc_nonce']);
    st_release_session_lock();
    header('Location: /', true, 302);
    exit;
}

st_release_session_lock();
st_json(['ok' => false, 'error' => 'unsupported operation'], 400);
