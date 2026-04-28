<?php
/**
 * SurveyTrace — /api/settings.php
 *
 * GET  — UI settings (requires auth when password is configured)
 * POST — update settings
 *   body may include:
 *   - session_timeout_minutes: int (5..10080)
 *   - extra_safe_ports: comma/space separated ports (1..65535)
 *   - nvd_api_key: string (optional; NIST UUID key, 30–128 chars) — saved only when no key exists yet; never returned on GET
 *   - nvd_api_key_remove: truthy — clears stored key (required before saving a replacement from the UI)
 */

require_once __DIR__ . '/db.php';

st_auth();
st_require_role(['admin']);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    $mode = strtolower(trim(st_config('auth_mode', 'session')));
    if ($mode === 'saml') {
        $mode = 'oidc';
    }
    if (!in_array($mode, ['basic', 'session', 'oidc'], true)) {
        $mode = 'session';
    }
    $m = max(5, min(10080, (int)st_config('session_timeout_minutes', '480')));
    $extra = trim((string)st_config('extra_safe_ports', ''));
    $nvdKey = trim((string)st_config('nvd_api_key', ''));
    st_json([
        'ok' => true,
        'session_timeout_minutes' => $m,
        'extra_safe_ports' => $extra,
        'auth_mode' => $mode,
        'oidc_enabled' => st_config('oidc_enabled', '0') === '1',
        'oidc_issuer_url' => (string)st_config('oidc_issuer_url', ''),
        'oidc_client_id' => (string)st_config('oidc_client_id', ''),
        'oidc_redirect_uri' => (string)st_config('oidc_redirect_uri', ''),
        'oidc_role_claim' => (string)st_config('oidc_role_claim', 'groups'),
        'oidc_role_map' => (string)st_config('oidc_role_map', ''),
        'sso_role_source' => (string)st_config('sso_role_source', 'surveytrace'),
        'breakglass_enabled' => st_config('breakglass_enabled', '1') === '1',
        'breakglass_username' => (string)st_config('breakglass_username', 'admin'),
        'password_policy' => st_password_policy(),
        'password_hash_algo' => st_password_hash_algo(),
        'login_max_attempts' => st_login_max_attempts(),
        'login_lockout_minutes' => st_login_lockout_minutes(),
        'nvd_api_key_configured' => $nvdKey !== '',
    ]);
}

st_method('POST');
$body = st_input();
$changed = [];

if (array_key_exists('session_timeout_minutes', $body)) {
    $m = (int)$body['session_timeout_minutes'];
    $m = max(5, min(10080, $m));
    st_config_set('session_timeout_minutes', (string)$m);
    $changed['session_timeout_minutes'] = $m;
}

if (array_key_exists('extra_safe_ports', $body)) {
    $raw = (string)$body['extra_safe_ports'];
    $tokens = preg_split('/[\s,]+/', $raw) ?: [];
    $ports = [];
    foreach ($tokens as $t) {
        $t = trim($t);
        if ($t === '') continue;
        if (!preg_match('/^\d+$/', $t)) {
            st_json(['error' => "invalid port token: $t"], 400);
        }
        $p = (int)$t;
        if ($p < 1 || $p > 65535) {
            st_json(['error' => "port out of range: $p"], 400);
        }
        $ports[$p] = true; // dedupe
    }
    $norm = implode(',', array_keys($ports));
    st_config_set('extra_safe_ports', $norm);
    $changed['extra_safe_ports'] = $norm;
}

if (array_key_exists('auth_mode', $body)) {
    $mode = strtolower(trim((string)$body['auth_mode']));
    if ($mode === 'saml') {
        $mode = 'oidc';
    }
    if (!in_array($mode, ['basic', 'session', 'oidc'], true)) {
        st_json(['error' => 'auth_mode must be one of basic, session, oidc'], 400);
    }
    st_config_set('auth_mode', $mode);
    $changed['auth_mode'] = $mode;
}

if (array_key_exists('oidc_enabled', $body)) {
    $changed['oidc_enabled'] = !empty($body['oidc_enabled']);
    st_config_set('oidc_enabled', $changed['oidc_enabled'] ? '1' : '0');
}
foreach (['oidc_issuer_url', 'oidc_client_id', 'oidc_client_secret', 'oidc_redirect_uri', 'oidc_role_claim', 'oidc_role_map'] as $k) {
    if (array_key_exists($k, $body)) {
        $v = trim((string)$body[$k]);
        st_config_set($k, $v);
        if ($k !== 'oidc_client_secret') {
            $changed[$k] = $v;
        } else {
            $changed['oidc_client_secret_configured'] = ($v !== '');
        }
    }
}
if (array_key_exists('sso_role_source', $body)) {
    $v = strtolower(trim((string)$body['sso_role_source']));
    if (!in_array($v, ['surveytrace', 'idp'], true)) {
        st_json(['error' => 'sso_role_source must be surveytrace or idp'], 400);
    }
    st_config_set('sso_role_source', $v);
    $changed['sso_role_source'] = $v;
}

if (array_key_exists('breakglass_enabled', $body)) {
    $changed['breakglass_enabled'] = !empty($body['breakglass_enabled']);
    st_config_set('breakglass_enabled', $changed['breakglass_enabled'] ? '1' : '0');
}
if (array_key_exists('breakglass_username', $body)) {
    $v = trim((string)$body['breakglass_username']);
    if ($v === '') $v = 'admin';
    st_config_set('breakglass_username', $v);
    $changed['breakglass_username'] = $v;
}

if (array_key_exists('password_policy', $body)) {
    $pp = is_array($body['password_policy']) ? $body['password_policy'] : [];
    $minLen = (int)($pp['min_length'] ?? st_password_policy()['min_length']);
    $minLen = max(8, min(128, $minLen));
    $reqUpper = !empty($pp['require_upper']);
    $reqLower = !empty($pp['require_lower']);
    $reqNumber = !empty($pp['require_number']);
    $reqSymbol = !empty($pp['require_symbol']);
    st_config_set('password_min_length', (string)$minLen);
    st_config_set('password_require_upper', $reqUpper ? '1' : '0');
    st_config_set('password_require_lower', $reqLower ? '1' : '0');
    st_config_set('password_require_number', $reqNumber ? '1' : '0');
    st_config_set('password_require_symbol', $reqSymbol ? '1' : '0');
    $changed['password_policy'] = st_password_policy();
}

if (array_key_exists('password_hash_algo', $body)) {
    $algo = strtolower(trim((string)$body['password_hash_algo']));
    if (!in_array($algo, ['argon2id', 'bcrypt'], true)) {
        st_json(['error' => 'password_hash_algo must be argon2id or bcrypt'], 400);
    }
    if ($algo === 'argon2id' && !defined('PASSWORD_ARGON2ID')) {
        st_json(['error' => 'Argon2id is not available on this PHP build'], 400);
    }
    st_config_set('password_hash_algo', $algo);
    $changed['password_hash_algo'] = st_password_hash_algo();
}

if (array_key_exists('login_max_attempts', $body)) {
    $v = (int)$body['login_max_attempts'];
    $v = max(3, min(20, $v));
    st_config_set('login_max_attempts', (string)$v);
    $changed['login_max_attempts'] = $v;
}
if (array_key_exists('login_lockout_minutes', $body)) {
    $v = (int)$body['login_lockout_minutes'];
    $v = max(1, min(1440, $v));
    st_config_set('login_lockout_minutes', (string)$v);
    $changed['login_lockout_minutes'] = $v;
}

if (!empty($body['nvd_api_key_remove'])) {
    st_config_set('nvd_api_key', '');
    $changed['nvd_api_key_configured'] = false;
} elseif (array_key_exists('nvd_api_key', $body)) {
    $existing = trim((string)st_config('nvd_api_key', ''));
    if ($existing !== '') {
        st_json([
            'error' => 'An NVD API key is already saved. Remove it first, then save a new key.',
        ], 409);
    }
    $nk = trim((string)$body['nvd_api_key']);
    if ($nk === '') {
        st_json(['error' => 'nvd_api_key is empty — use nvd_api_key_remove to clear, or paste a key.'], 400);
    }
    if (!preg_match('/^[A-Za-z0-9\-]{30,128}$/', $nk)) {
        st_json(['error' => 'NVD API key format looks wrong (use the UUID from NIST; 30–128 letters, digits, hyphens).'], 400);
    }
    st_config_set('nvd_api_key', $nk);
    $changed['nvd_api_key_configured'] = true;
}

if (!$changed) {
    st_json(['error' => 'no supported settings supplied'], 400);
}

st_json(array_merge(['ok' => true], $changed));
