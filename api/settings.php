<?php
/**
 * SurveyTrace — /api/settings.php
 *
 * GET  — UI settings (requires auth when password is configured)
 * POST — update settings
 *   body may include:
 *   - session_timeout_minutes: int (5..10080)
 *   - extra_safe_ports: comma/space separated ports (1..65535)
 *   - nvd_api_key: string (optional; NIST UUID key, 30–128 chars) — saved to config; never returned on GET
 *   - nvd_api_key_remove: truthy — clears stored key
 */

require_once __DIR__ . '/db.php';

st_auth();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    $m = max(5, min(10080, (int)st_config('session_timeout_minutes', '480')));
    $extra = trim((string)st_config('extra_safe_ports', ''));
    $nvdKey = trim((string)st_config('nvd_api_key', ''));
    st_json([
        'ok' => true,
        'session_timeout_minutes' => $m,
        'extra_safe_ports' => $extra,
        'auth_mode' => strtolower(trim(st_config('auth_mode', 'basic'))),
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

if (!empty($body['nvd_api_key_remove'])) {
    st_config_set('nvd_api_key', '');
    $changed['nvd_api_key_configured'] = false;
} elseif (array_key_exists('nvd_api_key', $body)) {
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
