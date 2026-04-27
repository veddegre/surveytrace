<?php
/**
 * SurveyTrace — /api/settings.php
 *
 * GET  — UI settings (requires auth when password is configured)
 * POST — update settings
 *   body may include:
 *   - session_timeout_minutes: int (5..10080)
 *   - extra_safe_ports: comma/space separated ports (1..65535)
 */

require_once __DIR__ . '/db.php';

st_auth();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    $m = max(5, min(10080, (int)st_config('session_timeout_minutes', '480')));
    $extra = trim((string)st_config('extra_safe_ports', ''));
    st_json([
        'ok' => true,
        'session_timeout_minutes' => $m,
        'extra_safe_ports' => $extra,
        'auth_mode' => strtolower(trim(st_config('auth_mode', 'basic'))),
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

if (!$changed) {
    st_json(['error' => 'no supported settings supplied'], 400);
}

st_json(array_merge(['ok' => true], $changed));
