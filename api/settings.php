<?php
/**
 * SurveyTrace — /api/settings.php
 *
 * GET  — UI settings (requires auth when password is configured)
 * POST — update settings (body: { "session_timeout_minutes": <int> })
 */

require_once __DIR__ . '/db.php';

st_auth();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    $m = max(5, min(10080, (int)st_config('session_timeout_minutes', '480')));
    st_json([
        'ok' => true,
        'session_timeout_minutes' => $m,
        'auth_mode' => strtolower(trim(st_config('auth_mode', 'basic'))),
    ]);
}

st_method('POST');
$body = st_input();
if (!array_key_exists('session_timeout_minutes', $body)) {
    st_json(['error' => 'session_timeout_minutes required'], 400);
}
$m = (int)$body['session_timeout_minutes'];
$m = max(5, min(10080, $m));
st_config_set('session_timeout_minutes', (string)$m);
st_json(['ok' => true, 'session_timeout_minutes' => $m]);
