<?php
/**
 * SurveyTrace — POST /api/logout.php
 *
 * Destroys the current PHP session cookie so stale sessions can be reset
 * without clearing browser storage manually.
 */

require_once __DIR__ . '/db.php';
st_method('POST');

if (PHP_SAPI !== 'cli') {
    st_session_start();

    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'] ?? '/',
            $params['domain'] ?? '',
            (bool)($params['secure'] ?? false),
            (bool)($params['httponly'] ?? true)
        );
    }
    @session_destroy();
}

st_json(['ok' => true]);
