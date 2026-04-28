<?php
/**
 * SurveyTrace — /api/auth.php
 *
 * GET  /api/auth.php?status=1      -> auth mode + current user status
 * POST /api/auth.php?login=1       -> session login with {"username","password","otp","recovery_code"}
 * POST /api/auth.php?mfa_setup=1   -> create TOTP secret for current user (admin)
 * POST /api/auth.php?mfa_enable=1  -> enable TOTP with {"secret","otp"} (admin)
 * POST /api/auth.php?mfa_disable=1 -> disable TOTP with {"otp"} (admin)
 * GET  /api/auth.php?users=1       -> list local users (admin)
 * POST /api/auth.php?users=1       -> create/update local users (admin)
 */

require_once __DIR__ . '/db.php';

st_session_start();
st_session_touch_idle();
$db = st_db();

function st_auth_mode(): string {
    $mode = strtolower(trim(st_config('auth_mode', 'session')));
    if ($mode === 'saml') {
        return 'oidc';
    }
    if (!in_array($mode, ['basic', 'session', 'oidc'], true)) {
        return 'session';
    }
    return $mode;
}

function st_find_local_user(PDO $db, string $username): ?array {
    $stmt = $db->prepare("
        SELECT id, username, password_hash, role, disabled, mfa_enabled, mfa_totp_secret, must_change_password
        FROM users
        WHERE auth_source='local' AND lower(username)=lower(?)
        LIMIT 1
    ");
    $stmt->execute([$username]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function st_consume_recovery_code(PDO $db, int $userId, string $code): bool {
    $norm = strtoupper(trim($code));
    if ($norm === '') return false;
    $rows = $db->prepare("SELECT id, code_hash FROM user_recovery_codes WHERE user_id=? AND used_at IS NULL");
    $rows->execute([$userId]);
    foreach ($rows->fetchAll() as $r) {
        if (password_verify($norm, (string)$r['code_hash'])) {
            $db->prepare("UPDATE user_recovery_codes SET used_at=datetime('now') WHERE id=?")->execute([(int)$r['id']]);
            return true;
        }
    }
    return false;
}

function st_replace_recovery_codes(PDO $db, int $userId): array {
    $codes = st_generate_recovery_codes(8);
    $db->prepare("DELETE FROM user_recovery_codes WHERE user_id=?")->execute([$userId]);
    $ins = $db->prepare("INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (?, ?)");
    foreach ($codes as $c) {
        $ins->execute([$userId, password_hash($c, PASSWORD_DEFAULT)]);
    }
    return $codes;
}

function st_login_ip(): string {
    return trim((string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}

$mode = st_auth_mode();
$legacyHash = st_config('auth_hash');
$breakglassEnabled = st_config('breakglass_enabled', '1') === '1';
$breakglassUser = trim((string)st_config('breakglass_username', 'admin'));
$hasLocalUsers = (int)$db->query("SELECT COUNT(*) FROM users WHERE auth_source='local' AND disabled=0")->fetchColumn() > 0;
$requiresAuth = $hasLocalUsers || !empty($legacyHash);
$current = st_current_user();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && isset($_GET['status'])) {
    $timeoutMin = max(5, min(10080, (int)st_config('session_timeout_minutes', '480')));
    $authed = !empty($_SESSION['st_authed']) || (!$requiresAuth);
    $currentMfaEnabled = false;
    $mustChangePassword = !empty($current['must_change_password']);
    if ($authed && $current['id'] > 0) {
        $mfaStmt = $db->prepare("SELECT mfa_enabled, must_change_password FROM users WHERE id=? LIMIT 1");
        $mfaStmt->execute([(int)$current['id']]);
        $flags = $mfaStmt->fetch() ?: [];
        $currentMfaEnabled = ((int)($flags['mfa_enabled'] ?? 0) === 1);
        $mustChangePassword = ((int)($flags['must_change_password'] ?? 0) === 1);
        $current['must_change_password'] = $mustChangePassword;
    }
    st_release_session_lock();
    st_json([
        'ok' => true,
        'auth_mode' => $mode,
        'requires_auth' => $requiresAuth,
        'authed' => $authed,
        'session_timeout_minutes' => $timeoutMin,
        'user' => $authed ? $current : null,
        'roles' => ['viewer', 'scan_editor', 'admin'],
        'oidc_enabled' => st_config('oidc_enabled', '0') === '1',
        'breakglass_enabled' => $breakglassEnabled,
        'breakglass_username' => $breakglassUser,
        'security_controls' => [
            'password_hash_algo' => st_password_hash_algo(),
            'login_max_attempts' => st_login_max_attempts(),
            'login_lockout_minutes' => st_login_lockout_minutes(),
        ],
        'current_mfa_enabled' => $currentMfaEnabled,
    ]);
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && isset($_GET['users'])) {
    st_auth();
    st_require_role(['admin']);
    $rows = $db->query("
        SELECT id, username, role, auth_source, disabled, mfa_enabled, must_change_password, created_at, updated_at, last_login_at
        FROM users
        ORDER BY lower(username) ASC
    ")->fetchAll();
    st_release_session_lock();
    st_json(['ok' => true, 'users' => $rows]);
}

st_method('POST');
$body = st_input();

if (isset($_GET['login'])) {
    if (!in_array($mode, ['session', 'oidc'], true)) {
        st_release_session_lock();
        st_json(['error' => 'Login endpoint available only in session/SSO modes', 'auth_mode' => $mode], 400);
    }
    if (!$requiresAuth) {
        st_set_session_user(0, 'admin', 'admin', false);
        st_release_session_lock();
        st_json(['ok' => true, 'authed' => true, 'user' => st_current_user()]);
    }

    $username = trim((string)($body['username'] ?? ''));
    $password = (string)($body['password'] ?? '');
    $otp = trim((string)($body['otp'] ?? ''));
    $recoveryCode = trim((string)($body['recovery_code'] ?? ''));
    if ($username === '' || $password === '') {
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'username and password required'], 400);
    }
    if ($mode === 'oidc') {
        if (!$breakglassEnabled) {
            st_release_session_lock();
            st_json(['ok' => false, 'error' => 'Local sign-in is disabled in SSO mode'], 403);
        }
        if ($breakglassUser !== '' && strcasecmp($username, $breakglassUser) !== 0) {
            st_release_session_lock();
            st_json(['ok' => false, 'error' => 'Use SSO for normal sign-in; breakglass is limited to the emergency account'], 403);
        }
    }
    $ip = st_login_ip();
    $lock = st_login_lock_state($username, $ip);
    if (!empty($lock['locked'])) {
        st_release_session_lock();
        st_json([
            'ok' => false,
            'error' => 'Too many failed sign-in attempts. Try again later.',
            'retry_after_sec' => (int)$lock['retry_after_sec'],
        ], 429);
    }

    $urow = st_find_local_user($db, $username);
    if ($urow && (int)$urow['disabled'] === 0 && password_verify($password, (string)$urow['password_hash'])) {
        $mfaEnabled = (int)($urow['mfa_enabled'] ?? 0) === 1;
        if ($mfaEnabled) {
            $secret = (string)($urow['mfa_totp_secret'] ?? '');
            $otpOk = ($otp !== '' && st_verify_totp($secret, $otp));
            $recoveryOk = (!$otpOk && $recoveryCode !== '' && st_consume_recovery_code($db, (int)$urow['id'], $recoveryCode));
            if (!$otpOk && !$recoveryOk) {
                st_login_register_failure($username, $ip);
                st_release_session_lock();
                st_json(['ok' => false, 'mfa_required' => true, 'error' => 'MFA code required'], 401);
            }
        }
        if (st_password_needs_rehash((string)$urow['password_hash'])) {
            $db->prepare("UPDATE users SET password_hash=?, updated_at=datetime('now') WHERE id=?")
               ->execute([st_password_hash($password), (int)$urow['id']]);
        }
        $mustChange = (int)($urow['must_change_password'] ?? 0) === 1;
        st_set_session_user((int)$urow['id'], (string)$urow['username'], (string)$urow['role'], $mustChange);
        $db->prepare("UPDATE users SET last_login_at=datetime('now'), updated_at=datetime('now') WHERE id=?")->execute([(int)$urow['id']]);
        st_login_register_success($username, $ip);
        st_release_session_lock();
        st_json(['ok' => true, 'authed' => true, 'user' => st_current_user(), 'must_change_password' => $mustChange]);
    }

    // Legacy fallback while old auth_hash may still exist
    if ($username === 'admin' && !empty($legacyHash) && password_verify($password, $legacyHash)) {
        st_set_session_user(0, 'admin', 'admin', false);
        st_login_register_success($username, $ip);
        st_release_session_lock();
        st_json(['ok' => true, 'authed' => true, 'user' => st_current_user()]);
    }
    st_login_register_failure($username, $ip);
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'Invalid credentials'], 403);
}

if (isset($_GET['mfa_setup'])) {
    st_auth();
    st_require_role(['admin']);
    $u = st_current_user();
    if ($u['id'] <= 0) st_json(['error' => 'MFA setup unavailable for legacy account; create a local admin user first'], 400);
    $secret = st_generate_mfa_secret();
    $issuer = rawurlencode('SurveyTrace');
    $label = rawurlencode('SurveyTrace:' . $u['username']);
    $otpUri = "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer}&algorithm=SHA1&digits=6&period=30";
    st_release_session_lock();
    st_json(['ok' => true, 'secret' => $secret, 'otpauth_uri' => $otpUri]);
}

if (isset($_GET['mfa_enable'])) {
    st_auth();
    st_require_role(['admin']);
    $u = st_current_user();
    if ($u['id'] <= 0) st_json(['error' => 'MFA enable unavailable for legacy account'], 400);
    $secret = trim((string)($body['secret'] ?? ''));
    $otp = trim((string)($body['otp'] ?? ''));
    if ($secret === '' || $otp === '') st_json(['error' => 'secret and otp required'], 400);
    if (!st_verify_totp($secret, $otp)) st_json(['error' => 'invalid OTP code'], 400);
    $db->prepare("UPDATE users SET mfa_enabled=1, mfa_totp_secret=?, updated_at=datetime('now') WHERE id=?")->execute([$secret, $u['id']]);
    $codes = st_replace_recovery_codes($db, $u['id']);
    st_release_session_lock();
    st_json(['ok' => true, 'recovery_codes' => $codes]);
}

if (isset($_GET['password_change'])) {
    st_auth();
    $u = st_current_user();
    if ($u['id'] <= 0) st_json(['error' => 'Password change unavailable for legacy account'], 400);
    $currentPassword = (string)($body['current_password'] ?? '');
    $newPassword = (string)($body['new_password'] ?? '');
    if ($newPassword === '') st_json(['error' => 'new_password required'], 400);
    $pwErrors = st_validate_password_strength($newPassword);
    if ($pwErrors) st_json(['error' => implode(' ', $pwErrors)], 400);
    $row = $db->prepare("SELECT password_hash FROM users WHERE id=? AND auth_source='local' LIMIT 1");
    $row->execute([$u['id']]);
    $hash = (string)$row->fetchColumn();
    if ($hash === '' || !password_verify($currentPassword, $hash)) {
        st_json(['error' => 'Current password is incorrect'], 400);
    }
    $db->prepare("UPDATE users SET password_hash=?, must_change_password=0, updated_at=datetime('now') WHERE id=?")
       ->execute([st_password_hash($newPassword), $u['id']]);
    st_release_session_lock();
    st_json(['ok' => true]);
}

if (isset($_GET['mfa_disable'])) {
    st_auth();
    st_require_role(['admin']);
    $u = st_current_user();
    if ($u['id'] <= 0) st_json(['error' => 'MFA disable unavailable for legacy account'], 400);
    $otp = trim((string)($body['otp'] ?? ''));
    $recoveryCode = trim((string)($body['recovery_code'] ?? ''));
    $row = $db->prepare("SELECT mfa_totp_secret FROM users WHERE id=?");
    $row->execute([$u['id']]);
    $secret = (string)$row->fetchColumn();
    $otpOk = ($secret !== '' && $otp !== '' && st_verify_totp($secret, $otp));
    $recoveryOk = (!$otpOk && $recoveryCode !== '' && st_consume_recovery_code($db, (int)$u['id'], $recoveryCode));
    if (!$otpOk && !$recoveryOk) {
        st_json(['error' => 'invalid OTP or recovery code'], 400);
    }
    $db->prepare("UPDATE users SET mfa_enabled=0, mfa_totp_secret=NULL, updated_at=datetime('now') WHERE id=?")->execute([$u['id']]);
    $db->prepare("DELETE FROM user_recovery_codes WHERE user_id=?")->execute([$u['id']]);
    st_release_session_lock();
    st_json(['ok' => true]);
}

if (isset($_GET['users'])) {
    st_auth();
    st_require_role(['admin']);
    $id = (int)($body['id'] ?? 0);
    $username = trim((string)($body['username'] ?? ''));
    $role = st_normalize_role((string)($body['role'] ?? 'viewer'));
    $password = (string)($body['password'] ?? '');
    $resetMfa = !empty($body['reset_mfa']);
    $disabled = !empty($body['disabled']) ? 1 : 0;
    if ($username === '') st_json(['error' => 'username required'], 400);
    if ($id > 0) {
        $stmt = $db->prepare("UPDATE users SET username=?, role=?, disabled=?, updated_at=datetime('now') WHERE id=?");
        $stmt->execute([$username, $role, $disabled, $id]);
        if ($password !== '') {
            $pwErrors = st_validate_password_strength($password);
            if ($pwErrors) {
                st_json(['error' => implode(' ', $pwErrors)], 400);
            }
            $db->prepare("UPDATE users SET password_hash=?, must_change_password=1, updated_at=datetime('now') WHERE id=?")
               ->execute([st_password_hash($password), $id]);
        }
        if ($resetMfa) {
            $db->prepare("UPDATE users SET mfa_enabled=0, mfa_totp_secret=NULL, updated_at=datetime('now') WHERE id=?")->execute([$id]);
            $db->prepare("DELETE FROM user_recovery_codes WHERE user_id=?")->execute([$id]);
        }
        st_release_session_lock();
        st_json(['ok' => true, 'id' => $id]);
    }
    if ($password === '') st_json(['error' => 'password required for new user'], 400);
    $pwErrors = st_validate_password_strength($password);
    if ($pwErrors) {
        st_json(['error' => implode(' ', $pwErrors)], 400);
    }
    $ins = $db->prepare("
        INSERT INTO users (username, password_hash, role, auth_source, disabled, must_change_password)
        VALUES (?, ?, ?, 'local', ?, 1)
    ");
    $ins->execute([$username, st_password_hash($password), $role, $disabled]);
    st_release_session_lock();
    st_json(['ok' => true, 'id' => (int)$db->lastInsertId()]);
}

st_release_session_lock();
st_json(['error' => 'unsupported operation'], 400);
