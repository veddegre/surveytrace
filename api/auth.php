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
 * GET  /api/auth.php?audit_live=1  -> current sign-in state (admin, non-historical)
 * POST /api/auth.php?users=1       -> create/update local users (admin)
 * GET  /api/auth.php?audit=1       -> recent auth/admin audit entries (admin)
 */

require_once __DIR__ . '/db.php';

st_session_start();
st_session_touch_idle();
$db = st_db();
st_ensure_user_audit_schema();

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
        SELECT id, username, password_hash, role, auth_source, display_name, email, disabled, mfa_enabled, mfa_totp_secret, must_change_password
        FROM users
        WHERE auth_source='local' AND lower(username)=lower(?)
        LIMIT 1
    ");
    $stmt->execute([$username]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function st_auth_ensure_audit_table(PDO $db): void {
    $db->exec(
        "CREATE TABLE IF NOT EXISTS user_audit_log (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
            actor_username   TEXT,
            target_user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
            target_username  TEXT,
            action           TEXT NOT NULL,
            details_json     TEXT,
            source_ip        TEXT,
            created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );
    $db->exec('CREATE INDEX IF NOT EXISTS idx_user_audit_log_actor ON user_audit_log(actor_user_id, created_at DESC)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_user_audit_log_target ON user_audit_log(target_user_id, created_at DESC)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_user_audit_log_created ON user_audit_log(created_at DESC)');
}

function st_auth_endpoint_error(Throwable $e): never {
    $msg = trim((string)$e->getMessage());
    $lower = strtolower($msg);
    if (str_contains($lower, 'database is locked') || str_contains($lower, 'database busy')) {
        st_release_session_lock();
        st_json(['error' => 'Database is busy. Please retry in a few seconds.'], 503);
    }
    @error_log('SurveyTrace auth endpoint error: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', $msg));
    st_release_session_lock();
    st_json(['error' => 'Authentication operation failed'], 500);
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
    $currentAuthSource = 'local';
    $currentDisplayName = '';
    $currentEmail = '';
    if ($authed && $current['id'] > 0) {
        $mfaStmt = $db->prepare("SELECT mfa_enabled, must_change_password, auth_source, display_name, email FROM users WHERE id=? LIMIT 1");
        $mfaStmt->execute([(int)$current['id']]);
        $flags = $mfaStmt->fetch() ?: [];
        $currentMfaEnabled = ((int)($flags['mfa_enabled'] ?? 0) === 1);
        $mustChangePassword = ((int)($flags['must_change_password'] ?? 0) === 1);
        $currentAuthSource = (string)($flags['auth_source'] ?? 'local');
        $currentDisplayName = trim((string)($flags['display_name'] ?? ''));
        $currentEmail = trim((string)($flags['email'] ?? ''));
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
        'current_auth_source' => $currentAuthSource,
        'profile' => [
            'display_name' => $currentDisplayName,
            'email' => $currentEmail,
        ],
        'csrf_token' => st_csrf_token(),
    ]);
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && isset($_GET['users'])) {
    st_auth();
    st_require_role(['admin']);
    $rows = $db->query("
        SELECT id, username, role, auth_source, display_name, email, disabled, mfa_enabled, must_change_password, created_at, updated_at, last_login_at
        FROM users
        ORDER BY lower(username) ASC
    ")->fetchAll();
    st_release_session_lock();
    st_json(['ok' => true, 'users' => $rows]);
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && isset($_GET['audit'])) {
    try {
        st_auth();
        st_require_role(['admin']);
        st_auth_ensure_audit_table($db);
        if (function_exists('st_ensure_user_audit_schema')) {
            st_ensure_user_audit_schema();
        }
        $limit = (int)($_GET['limit'] ?? 100);
        $limit = max(10, min(500, $limit));
        $targetUserId = (int)($_GET['target_user_id'] ?? 0);
        $sql = "
            SELECT id, actor_user_id, actor_username, target_user_id, target_username, action, details_json, source_ip, created_at
            FROM user_audit_log
        ";
        $params = [];
        if ($targetUserId > 0) {
            $sql .= " WHERE target_user_id = ? OR actor_user_id = ?";
            $params[] = $targetUserId;
            $params[] = $targetUserId;
        }
        $sql .= " ORDER BY id DESC LIMIT " . $limit;
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll();
        st_release_session_lock();
        st_json(['ok' => true, 'audit' => $rows]);
    } catch (Throwable $e) {
        @error_log('SurveyTrace auth audit read failed: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string)$e->getMessage()));
        st_release_session_lock();
        st_json(['ok' => true, 'audit' => [], 'warning' => 'audit_unavailable']);
    }
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && isset($_GET['audit_live'])) {
    try {
        st_auth();
        st_require_role(['admin']);
        $rows = $db->query("
            SELECT
                actor_key,
                username_norm,
                source_ip,
                failed_count,
                first_failed_at,
                last_failed_at,
                locked_until
            FROM auth_login_state
            WHERE failed_count > 0 OR (locked_until IS NOT NULL AND locked_until <> '')
            ORDER BY
                CASE WHEN locked_until IS NOT NULL AND locked_until > datetime('now') THEN 0 ELSE 1 END,
                last_failed_at DESC
            LIMIT 200
        ")->fetchAll();
        st_release_session_lock();
        st_json(['ok' => true, 'live' => $rows]);
    } catch (Throwable $e) {
        @error_log('SurveyTrace auth live read failed: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string)$e->getMessage()));
        st_release_session_lock();
        st_json(['ok' => true, 'live' => [], 'warning' => 'live_unavailable']);
    }
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
        st_audit_log('auth.login_rejected', null, null, null, $username, ['reason' => 'missing_username_or_password']);
        st_release_session_lock();
        st_json(['ok' => false, 'error' => 'username and password required'], 400);
    }
    if ($mode === 'oidc') {
        if (!$breakglassEnabled) {
            st_audit_log('auth.login_rejected', null, null, null, $username, ['reason' => 'breakglass_disabled']);
            st_release_session_lock();
            st_json(['ok' => false, 'error' => 'Local sign-in is disabled in SSO mode'], 403);
        }
        if ($breakglassUser !== '' && strcasecmp($username, $breakglassUser) !== 0) {
            st_audit_log('auth.login_rejected', null, null, null, $username, ['reason' => 'not_breakglass_user']);
            st_release_session_lock();
            st_json(['ok' => false, 'error' => 'Use SSO for normal sign-in; breakglass is limited to the emergency account'], 403);
        }
    }
    $ip = st_login_ip();
    $lock = st_login_lock_state($username, $ip);
    if (!empty($lock['locked'])) {
        st_audit_log('auth.login_rejected', null, null, null, $username, [
            'reason' => 'locked_out',
            'retry_after_sec' => (int)$lock['retry_after_sec'],
        ]);
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
                st_audit_log('auth.login_failure', null, null, (int)$urow['id'], (string)$urow['username'], ['reason' => 'mfa_required_or_invalid']);
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
        st_audit_log('auth.login_success', (int)$urow['id'], (string)$urow['username'], (int)$urow['id'], (string)$urow['username'], [
            'auth_source' => (string)$urow['auth_source'],
            'mfa_used' => ((int)($urow['mfa_enabled'] ?? 0) === 1),
        ]);
        st_release_session_lock();
        st_json(['ok' => true, 'authed' => true, 'user' => st_current_user(), 'must_change_password' => $mustChange]);
    }

    // Legacy fallback while old auth_hash may still exist
    if ($username === 'admin' && !empty($legacyHash) && password_verify($password, $legacyHash)) {
        st_set_session_user(0, 'admin', 'admin', false);
        st_login_register_success($username, $ip);
        st_audit_log('auth.login_success_legacy_admin', null, 'admin', null, 'admin');
        st_release_session_lock();
        st_json(['ok' => true, 'authed' => true, 'user' => st_current_user()]);
    }
    st_login_register_failure($username, $ip);
    st_audit_log('auth.login_failure', null, null, null, $username, ['reason' => 'invalid_credentials']);
    st_release_session_lock();
    st_json(['ok' => false, 'error' => 'Invalid credentials'], 403);
}

if (isset($_GET['mfa_setup'])) {
    try {
        st_auth();
        $u = st_current_user();
        if ($u['id'] <= 0) st_json(['error' => 'MFA setup unavailable for legacy account; create a local admin user first'], 400);
        $srcStmt = $db->prepare("SELECT auth_source FROM users WHERE id=? LIMIT 1");
        $srcStmt->execute([$u['id']]);
        if ((string)$srcStmt->fetchColumn() !== 'local') st_json(['error' => 'MFA setup is available only for local accounts'], 400);
        $secret = st_generate_mfa_secret();
        $issuer = rawurlencode('SurveyTrace');
        $label = rawurlencode('SurveyTrace:' . $u['username']);
        $otpUri = "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer}&algorithm=SHA1&digits=6&period=30";
        st_release_session_lock();
        st_json(['ok' => true, 'secret' => $secret, 'otpauth_uri' => $otpUri]);
    } catch (Throwable $e) {
        st_auth_endpoint_error($e);
    }
}

if (isset($_GET['mfa_enable'])) {
    try {
        st_auth();
        $u = st_current_user();
        if ($u['id'] <= 0) st_json(['error' => 'MFA enable unavailable for legacy account'], 400);
        $srcStmt = $db->prepare("SELECT auth_source FROM users WHERE id=? LIMIT 1");
        $srcStmt->execute([$u['id']]);
        if ((string)$srcStmt->fetchColumn() !== 'local') st_json(['error' => 'MFA enable is available only for local accounts'], 400);
        $secret = trim((string)($body['secret'] ?? ''));
        $otp = trim((string)($body['otp'] ?? ''));
        if ($secret === '' || $otp === '') st_json(['error' => 'secret and otp required'], 400);
        if (!st_verify_totp($secret, $otp)) st_json(['error' => 'invalid OTP code'], 400);
        $db->prepare("UPDATE users SET mfa_enabled=1, mfa_totp_secret=?, updated_at=datetime('now') WHERE id=?")->execute([$secret, $u['id']]);
        $codes = st_replace_recovery_codes($db, $u['id']);
        st_audit_log('auth.mfa_enable', (int)$u['id'], (string)$u['username'], (int)$u['id'], (string)$u['username']);
        st_release_session_lock();
        st_json(['ok' => true, 'recovery_codes' => $codes]);
    } catch (Throwable $e) {
        st_auth_endpoint_error($e);
    }
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
    if ($hash === '') st_json(['error' => 'Password change is available only for local accounts'], 400);
    if ($hash === '' || !password_verify($currentPassword, $hash)) {
        st_json(['error' => 'Current password is incorrect'], 400);
    }
    $db->prepare("UPDATE users SET password_hash=?, must_change_password=0, updated_at=datetime('now') WHERE id=?")
       ->execute([st_password_hash($newPassword), $u['id']]);
    // Rotate session id + CSRF token after credential change.
    st_set_session_user((int)$u['id'], (string)$u['username'], (string)$u['role'], false);
    st_audit_log('auth.password_change_self', (int)$u['id'], (string)$u['username'], (int)$u['id'], (string)$u['username']);
    st_release_session_lock();
    st_json(['ok' => true]);
}

if (isset($_GET['mfa_disable'])) {
    st_auth();
    $u = st_current_user();
    if ($u['id'] <= 0) st_json(['error' => 'MFA disable unavailable for legacy account'], 400);
    $srcStmt = $db->prepare("SELECT auth_source FROM users WHERE id=? LIMIT 1");
    $srcStmt->execute([$u['id']]);
    if ((string)$srcStmt->fetchColumn() !== 'local') st_json(['error' => 'MFA disable is available only for local accounts'], 400);
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
    st_audit_log('auth.mfa_disable_self', (int)$u['id'], (string)$u['username'], (int)$u['id'], (string)$u['username']);
    st_release_session_lock();
    st_json(['ok' => true]);
}

if (isset($_GET['profile'])) {
    st_auth();
    $u = st_current_user();
    if ($u['id'] <= 0) st_json(['error' => 'Profile update unavailable for legacy account'], 400);
    $displayName = substr(trim((string)($body['display_name'] ?? '')), 0, 120);
    $email = substr(trim((string)($body['email'] ?? '')), 0, 254);
    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        st_json(['error' => 'Invalid email address'], 400);
    }
    $db->prepare("UPDATE users SET display_name=?, email=?, updated_at=datetime('now') WHERE id=?")
       ->execute([$displayName, $email, $u['id']]);
    st_audit_log('auth.profile_update_self', (int)$u['id'], (string)$u['username'], (int)$u['id'], (string)$u['username']);
    st_release_session_lock();
    st_json(['ok' => true, 'display_name' => $displayName, 'email' => $email]);
}

if (isset($_GET['users'])) {
    st_auth();
    st_require_role(['admin']);
    $id = (int)($body['id'] ?? 0);
    $username = trim((string)($body['username'] ?? ''));
    $role = st_normalize_role((string)($body['role'] ?? 'viewer'));
    $password = (string)($body['password'] ?? '');
    $resetMfa = !empty($body['reset_mfa']);
    $deleteUser = !empty($body['delete_user']);
    $displayName = substr(trim((string)($body['display_name'] ?? '')), 0, 120);
    $email = substr(trim((string)($body['email'] ?? '')), 0, 254);
    $mustChangePassword = !empty($body['must_change_password']) ? 1 : 0;
    $disabled = !empty($body['disabled']) ? 1 : 0;
    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        st_json(['error' => 'Invalid email address'], 400);
    }
    if ($deleteUser) {
        if ($id <= 0) st_json(['error' => 'id required for delete'], 400);
        $existingStmt = $db->prepare("SELECT id, username, role, auth_source FROM users WHERE id=? LIMIT 1");
        $existingStmt->execute([$id]);
        $existing = $existingStmt->fetch();
        if (!$existing) st_json(['error' => 'User not found'], 404);
        $actor = st_current_user();
        if ((int)$actor['id'] === (int)$id) {
            st_json(['error' => 'You cannot delete your own account'], 400);
        }
        if ((string)$existing['role'] === 'admin') {
            $activeAdmins = (int)$db->query("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0")->fetchColumn();
            if ($activeAdmins <= 1) {
                st_json(['error' => 'Cannot delete the last active admin'], 400);
            }
        }
        $db->prepare("DELETE FROM users WHERE id=?")->execute([$id]);
        st_audit_log('admin.user_delete', (int)$actor['id'], (string)$actor['username'], (int)$existing['id'], (string)$existing['username'], [
            'target_role' => (string)$existing['role'],
            'target_auth_source' => (string)$existing['auth_source'],
        ]);
        st_release_session_lock();
        st_json(['ok' => true, 'id' => $id]);
    }
    if ($username === '') st_json(['error' => 'username required'], 400);
    if ($id > 0) {
        $existingStmt = $db->prepare("SELECT username, role, disabled, display_name, email, must_change_password FROM users WHERE id=? LIMIT 1");
        $existingStmt->execute([$id]);
        $existing = $existingStmt->fetch();
        if (!$existing) st_json(['error' => 'User not found'], 404);
        if ((string)$existing['role'] === 'admin' && ($role !== 'admin' || $disabled === 1)) {
            $cStmt = $db->prepare("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0 AND id<>?");
            $cStmt->execute([$id]);
            if ((int)$cStmt->fetchColumn() <= 0) {
                st_json(['error' => 'Cannot remove or disable the last active admin'], 400);
            }
        }
        $stmt = $db->prepare("UPDATE users SET username=?, role=?, display_name=?, email=?, disabled=?, must_change_password=?, updated_at=datetime('now') WHERE id=?");
        $stmt->execute([$username, $role, $displayName, $email, $disabled, $mustChangePassword, $id]);
        $actor = st_current_user();
        st_audit_log('admin.user_update', (int)$actor['id'], (string)$actor['username'], $id, $username, [
            'prev_username' => (string)$existing['username'],
            'prev_role' => (string)$existing['role'],
            'prev_display_name' => (string)($existing['display_name'] ?? ''),
            'prev_email' => (string)($existing['email'] ?? ''),
            'prev_disabled' => (int)$existing['disabled'],
            'prev_must_change_password' => (int)($existing['must_change_password'] ?? 0),
            'new_role' => $role,
            'new_display_name' => $displayName,
            'new_email' => $email,
            'new_disabled' => $disabled,
            'new_must_change_password' => $mustChangePassword,
        ]);
        if ($password !== '') {
            $pwErrors = st_validate_password_strength($password);
            if ($pwErrors) {
                st_json(['error' => implode(' ', $pwErrors)], 400);
            }
            $db->prepare("UPDATE users SET password_hash=?, must_change_password=1, updated_at=datetime('now') WHERE id=?")
               ->execute([st_password_hash($password), $id]);
            st_audit_log('admin.user_password_reset', (int)$actor['id'], (string)$actor['username'], $id, $username);
        }
        if ($resetMfa) {
            $db->prepare("UPDATE users SET mfa_enabled=0, mfa_totp_secret=NULL, updated_at=datetime('now') WHERE id=?")->execute([$id]);
            $db->prepare("DELETE FROM user_recovery_codes WHERE user_id=?")->execute([$id]);
            st_audit_log('admin.user_mfa_reset', (int)$actor['id'], (string)$actor['username'], $id, $username);
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
    $actor = st_current_user();
    $newId = (int)$db->lastInsertId();
    st_audit_log('admin.user_create', (int)$actor['id'], (string)$actor['username'], $newId, $username, [
        'role' => $role,
        'disabled' => $disabled,
    ]);
    st_release_session_lock();
    st_json(['ok' => true, 'id' => $newId]);
}

st_release_session_lock();
st_json(['error' => 'unsupported operation'], 400);
