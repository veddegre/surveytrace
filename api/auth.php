<?php
/**
 * SurveyTrace — /api/auth.php
 *
 * GET  /api/auth.php?status=1   -> session status + auth mode
 * POST /api/auth.php?login=1    -> session login with {"username","password"}
 */

require_once __DIR__ . '/db.php';

session_name('st_sess');
session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'use_strict_mode' => true,
]);

$db = st_db();
$mode = strtolower(trim(st_config('auth_mode', 'basic')));
if (!in_array($mode, ['basic', 'session'], true)) {
    $mode = 'basic';
}
$hash = st_config('auth_hash');
$has_auth = !empty($hash);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && isset($_GET['status'])) {
    st_json([
        'ok' => true,
        'auth_mode' => $mode,
        'requires_auth' => $has_auth,
        'authed' => !empty($_SESSION['st_authed']) || (!$has_auth),
    ]);
}

st_method('POST');
$body = st_input();

if (!isset($_GET['login'])) {
    st_json(['error' => 'unsupported operation'], 400);
}
if ($mode !== 'session') {
    st_json(['error' => 'Login endpoint available only in session mode', 'auth_mode' => $mode], 400);
}
if (!$has_auth) {
    $_SESSION['st_authed'] = true;
    $_SESSION['st_authed_at'] = time();
    st_json(['ok' => true, 'authed' => true]);
}

$user = trim((string)($body['username'] ?? ''));
$pass = (string)($body['password'] ?? '');
if ($user === '' || $pass === '') {
    st_json(['ok' => false, 'error' => 'username and password required'], 400);
}
if ($user === 'admin' && password_verify($pass, $hash)) {
    $_SESSION['st_authed'] = true;
    $_SESSION['st_authed_at'] = time();
    st_json(['ok' => true, 'authed' => true]);
}
st_json(['ok' => false, 'error' => 'Invalid credentials'], 401);
