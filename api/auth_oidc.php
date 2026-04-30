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

function st_ip_is_public(string $ip): bool {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

function st_allow_private_outbound_targets(): bool {
    $env = strtolower(trim((string)(getenv('SURVEYTRACE_ALLOW_PRIVATE_OUTBOUND') ?: '')));
    if (in_array($env, ['1', 'true', 'yes', 'on'], true)) {
        return true;
    }
    return st_config('security_allow_private_outbound_targets', '0') === '1';
}

function st_url_host_allowed(string $url, bool $httpsOnly = true, string $pinnedHost = '', bool $allowPrivate = false): bool {
    $u = trim($url);
    if ($u === '') return false;
    $parts = @parse_url($u);
    if (!is_array($parts)) return false;
    $scheme = strtolower((string)($parts['scheme'] ?? ''));
    $host = strtolower((string)($parts['host'] ?? ''));
    if ($host === '') return false;
    if ($httpsOnly && $scheme !== 'https') return false;
    if (!$httpsOnly && !in_array($scheme, ['http', 'https'], true)) return false;
    if ($pinnedHost !== '' && !hash_equals(strtolower($pinnedHost), $host)) return false;
    if (in_array($host, ['localhost'], true)) return $allowPrivate;
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return $allowPrivate ? true : st_ip_is_public($host);
    }
    $ips = [];
    $a = @dns_get_record($host, DNS_A);
    if (is_array($a)) {
        foreach ($a as $row) {
            $ip = (string)($row['ip'] ?? '');
            if ($ip !== '') $ips[] = $ip;
        }
    }
    if (defined('DNS_AAAA')) {
        $aaaa = @dns_get_record($host, DNS_AAAA);
        if (is_array($aaaa)) {
            foreach ($aaaa as $row) {
                $ip6 = (string)($row['ipv6'] ?? '');
                if ($ip6 !== '') $ips[] = $ip6;
            }
        }
    }
    if (!$ips) return false;
    foreach ($ips as $ip) {
        if (!$allowPrivate && !st_ip_is_public($ip)) return false;
    }
    return true;
}

function st_http_json(string $url, array $headers = [], bool $httpsOnly = true, string $pinnedHost = '', bool $allowPrivate = false): array {
    if (!st_url_host_allowed($url, $httpsOnly, $pinnedHost, $allowPrivate)) {
        return [];
    }
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

function st_http_form_post(string $url, array $form, bool $httpsOnly = true, string $pinnedHost = '', bool $allowPrivate = false): array {
    if (!st_url_host_allowed($url, $httpsOnly, $pinnedHost, $allowPrivate)) {
        return [];
    }
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

function st_b64url_decode(string $s): string {
    $t = strtr($s, '-_', '+/');
    $t .= str_repeat('=', (4 - (strlen($t) % 4)) % 4);
    $raw = base64_decode($t, true);
    return ($raw === false) ? '' : $raw;
}

function st_jwt_header(string $jwt): array {
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) return [];
    $raw = st_b64url_decode($parts[0]);
    if ($raw === '') return [];
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
}

function st_jwt_payload(string $jwt): array {
    $parts = explode('.', $jwt);
    if (count($parts) < 2) return [];
    $raw = st_b64url_decode($parts[1]);
    if ($raw === '') return [];
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
    if (strlen($mapRaw) > 8192) {
        $mapRaw = substr($mapRaw, 0, 8192);
    }
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

function st_der_len(int $len): string {
    if ($len < 0x80) return chr($len);
    $out = '';
    while ($len > 0) {
        $out = chr($len & 0xFF) . $out;
        $len >>= 8;
    }
    return chr(0x80 | strlen($out)) . $out;
}

function st_der_int(string $bytes): string {
    $bytes = ltrim($bytes, "\x00");
    if ($bytes === '') $bytes = "\x00";
    if ((ord($bytes[0]) & 0x80) !== 0) $bytes = "\x00" . $bytes;
    return "\x02" . st_der_len(strlen($bytes)) . $bytes;
}

function st_jwk_rsa_to_pem(array $jwk): ?string {
    if (($jwk['kty'] ?? '') !== 'RSA') return null;
    $n = st_b64url_decode((string)($jwk['n'] ?? ''));
    $e = st_b64url_decode((string)($jwk['e'] ?? ''));
    if ($n === '' || $e === '') return null;
    $seq = st_der_int($n) . st_der_int($e);
    $rsaPub = "\x30" . st_der_len(strlen($seq)) . $seq;
    $algo = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
    $bitString = "\x03" . st_der_len(strlen($rsaPub) + 1) . "\x00" . $rsaPub;
    $spki = "\x30" . st_der_len(strlen($algo) + strlen($bitString)) . $algo . $bitString;
    return "-----BEGIN PUBLIC KEY-----\n" .
        chunk_split(base64_encode($spki), 64, "\n") .
        "-----END PUBLIC KEY-----\n";
}

function st_jwk_to_pem(array $jwk): ?string {
    $x5c = $jwk['x5c'] ?? null;
    if (is_array($x5c) && !empty($x5c[0])) {
        $certBody = chunk_split((string)$x5c[0], 64, "\n");
        $pemCert = "-----BEGIN CERTIFICATE-----\n{$certBody}-----END CERTIFICATE-----\n";
        $pub = @openssl_pkey_get_public($pemCert);
        if ($pub !== false) {
            $details = openssl_pkey_get_details($pub);
            if (is_array($details) && !empty($details['key'])) {
                return (string)$details['key'];
            }
        }
    }
    return st_jwk_rsa_to_pem($jwk);
}

function st_jwt_alg_map(string $alg): int {
    return match ($alg) {
        'RS256' => OPENSSL_ALGO_SHA256,
        'RS384' => OPENSSL_ALGO_SHA384,
        'RS512' => OPENSSL_ALGO_SHA512,
        default => 0,
    };
}

function st_verify_oidc_id_token(string $jwt, array $discovery): bool {
    $jwksUri = trim((string)($discovery['jwks_uri'] ?? ''));
    if ($jwksUri === '') return false;
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) return false;
    $header = st_jwt_header($jwt);
    $alg = (string)($header['alg'] ?? '');
    $kid = (string)($header['kid'] ?? '');
    $opensslAlg = st_jwt_alg_map($alg);
    if ($opensslAlg === 0) return false;
    $sig = st_b64url_decode($parts[2]);
    if ($sig === '') return false;
    $signed = $parts[0] . '.' . $parts[1];
    $issuerHost = strtolower((string)parse_url((string)($discovery['issuer'] ?? ''), PHP_URL_HOST));
    $jwks = st_http_json($jwksUri, [], true, $issuerHost, st_allow_private_outbound_targets());
    $keys = is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [];
    if (!$keys) return false;
    foreach ($keys as $jwk) {
        if (!is_array($jwk)) continue;
        if (($jwk['kty'] ?? '') !== 'RSA') continue;
        if ($kid !== '' && isset($jwk['kid']) && (string)$jwk['kid'] !== $kid) continue;
        $pem = st_jwk_to_pem($jwk);
        if (!$pem) continue;
        $ok = @openssl_verify($signed, $sig, $pem, $opensslAlg);
        if ($ok === 1) return true;
    }
    return false;
}

if (st_config('oidc_enabled', '0') !== '1') {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'OIDC is disabled'], 400);
}

$issuer = rtrim(trim((string)st_config('oidc_issuer_url', '')), '/');
$roleSource = strtolower(trim((string)st_config('sso_role_source', 'surveytrace')));
$clientId = trim((string)st_config('oidc_client_id', ''));
$clientSecret = trim((string)st_config('oidc_client_secret', ''));
$redirectUri = trim((string)st_config('oidc_redirect_uri', ''));
if ($issuer === '' || $clientId === '' || $clientSecret === '' || $redirectUri === '') {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'OIDC is not fully configured'], 400);
}

$issuerHost = strtolower((string)parse_url($issuer, PHP_URL_HOST));
$allowPrivateOutbound = st_allow_private_outbound_targets();
if (!st_url_host_allowed($issuer, true, '', $allowPrivateOutbound)) {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'OIDC issuer URL must be public https'], 400);
}
$discovery = st_http_json($issuer . '/.well-known/openid-configuration', [], true, $issuerHost, $allowPrivateOutbound);
$authzEndpoint = (string)($discovery['authorization_endpoint'] ?? '');
$tokenEndpoint = (string)($discovery['token_endpoint'] ?? '');
$userInfoEndpoint = (string)($discovery['userinfo_endpoint'] ?? '');
if ($authzEndpoint === '' || $tokenEndpoint === '' || empty($discovery['jwks_uri'])) {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'OIDC discovery failed'], 400);
}
if (
    !st_url_host_allowed($authzEndpoint, true, $issuerHost, $allowPrivateOutbound)
    || !st_url_host_allowed($tokenEndpoint, true, $issuerHost, $allowPrivateOutbound)
    || !st_url_host_allowed((string)$discovery['jwks_uri'], true, $issuerHost, $allowPrivateOutbound)
    || ($userInfoEndpoint !== '' && !st_url_host_allowed($userInfoEndpoint, true, $issuerHost, $allowPrivateOutbound))
) {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'OIDC discovery returned unsafe endpoint URL(s)'], 400);
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
        st_audit_log('auth.oidc_login_failure', null, null, null, null, ['reason' => 'state_validation_failed']);
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC state validation failed'], 400);
    }

    $token = st_http_form_post($tokenEndpoint, [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => $redirectUri,
        'client_id' => $clientId,
        'client_secret' => $clientSecret,
    ], true, $issuerHost, $allowPrivateOutbound);
    $idToken = (string)($token['id_token'] ?? '');
    if ($idToken === '') {
        st_audit_log('auth.oidc_login_failure', null, null, null, null, ['reason' => 'token_exchange_failed']);
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC token exchange failed'], 400);
    }
    if (!st_verify_oidc_id_token($idToken, $discovery)) {
        st_audit_log('auth.oidc_login_failure', null, null, null, null, ['reason' => 'token_signature_validation_failed']);
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC token signature validation failed'], 400);
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
        st_audit_log('auth.oidc_login_failure', null, null, null, null, ['reason' => 'subject_missing']);
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'OIDC subject missing'], 400);
    }

    if ($userInfoEndpoint !== '' && !empty($token['access_token'])) {
        $ui = st_http_json($userInfoEndpoint, ['Authorization: Bearer ' . $token['access_token']], true, $issuerHost, $allowPrivateOutbound);
        if ($ui) $claims = array_merge($claims, $ui);
    }
    $username = trim((string)($claims['preferred_username'] ?? ($claims['email'] ?? $sub)));
    $role = ($roleSource === 'idp') ? st_role_from_claims($claims) : 'viewer';

    $db = st_db();
    $sel = $db->prepare("SELECT id, username, role, disabled FROM users WHERE auth_source='oidc' AND oidc_issuer=? AND oidc_sub=? LIMIT 1");
    $sel->execute([$issuer, $sub]);
    $row = $sel->fetch();
    if ($row) {
        if ((int)$row['disabled'] === 1) {
            st_audit_log('auth.oidc_login_failure', null, null, (int)$row['id'], (string)$row['username'], ['reason' => 'user_disabled']);
            st_release_session_lock();
            st_json(['ok' => false, 'error' => 'OIDC user is disabled'], 403);
        }
        $effectiveRole = ($roleSource === 'idp') ? $role : (string)$row['role'];
        if ($roleSource === 'idp') {
            $db->prepare("UPDATE users SET username=?, role=?, updated_at=datetime('now'), last_login_at=datetime('now') WHERE id=?")
               ->execute([$username, $effectiveRole, (int)$row['id']]);
        } else {
            $db->prepare("UPDATE users SET username=?, updated_at=datetime('now'), last_login_at=datetime('now') WHERE id=?")
               ->execute([$username, (int)$row['id']]);
        }
        st_set_session_user((int)$row['id'], $username, $effectiveRole);
        st_audit_log('auth.oidc_login_success', (int)$row['id'], $username, (int)$row['id'], $username, [
            'role' => $effectiveRole,
            'role_source' => $roleSource,
        ]);
    } else {
        $ins = $db->prepare("
            INSERT INTO users (username, role, auth_source, oidc_issuer, oidc_sub, last_login_at)
            VALUES (?, ?, 'oidc', ?, ?, datetime('now'))
        ");
        $ins->execute([$username, $role, $issuer, $sub]);
        $newId = (int)$db->lastInsertId();
        st_set_session_user($newId, $username, $role);
        st_audit_log('auth.oidc_user_create', $newId, $username, $newId, $username, [
            'role' => $role,
            'role_source' => $roleSource,
        ]);
        st_audit_log('auth.oidc_login_success', $newId, $username, $newId, $username, [
            'role' => $role,
            'role_source' => $roleSource,
        ]);
    }
    unset($_SESSION['oidc_state'], $_SESSION['oidc_nonce']);
    st_release_session_lock();
    header('Location: /', true, 302);
    exit;
}

st_release_session_lock();
st_json(['ok' => false, 'error' => 'unsupported operation'], 400);
