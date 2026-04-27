<?php
/**
 * SurveyTrace — /api/auth.php
 *
 * GET  /api/auth.php?status=1   -> session status + auth mode
 * POST /api/auth.php?login=1    -> session login with {"username","password"}
 */

require_once __DIR__ . '/db.php';

st_session_start();
st_session_touch_idle();

$db = st_db();
$mode = strtolower(trim(st_config('auth_mode', 'basic')));
if (!in_array($mode, ['basic', 'session'], true)) {
    $mode = 'basic';
}
$hash = st_config('auth_hash');
$has_auth = !empty($hash);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && isset($_GET['status'])) {
    $timeoutMin = max(5, min(10080, (int)st_config('session_timeout_minutes', '480')));
    $authed = !empty($_SESSION['st_authed']) || (!$has_auth);
    st_release_session_lock();
    st_json([
        'ok' => true,
        'auth_mode' => $mode,
        'requires_auth' => $has_auth,
        'authed' => $authed,
        'session_timeout_minutes' => $timeoutMin,
    ]);
}

st_method('POST');
$body = st_input();

if (!isset($_GET['login'])) {
    st_release_session_lock();
    st_json(['error' => 'unsupported operation'], 400);
}
if ($mode !== 'session') {
    st_release_session_lock();
    st_json(['error' => 'Login endpoint available only in session mode', 'auth_mode' => $mode], 400);
}
if (!$has_auth) {
    $_SESSION['st_authed'] = true;
    $_SESSION['st_authed_at'] = time();
    st_release_session_lock();
    st_json(['ok' => true, 'authed' => true]);
}

$user = trim((string)($body['username'] ?? ''));
$pass = (string)($body['password'] ?? '');
if ($user === '' || $pass === '') {
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'username and password required'], 400);
}
if ($user === 'admin' && password_verify($pass, $hash)) {
    $_SESSION['st_authed'] = true;
    $_SESSION['st_authed_at'] = time();
    st_release_session_lock();
    st_json(['ok' => true, 'authed' => true]);
}
st_release_session_lock();
st_json(['ok' => false, 'error' => 'Invalid credentials'], 403);
