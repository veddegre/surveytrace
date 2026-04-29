<?php
/**
 * SurveyTrace — core database + auth helper
 * Included by every API endpoint.
 */

// Always use UTC for all date/time operations regardless of server timezone
date_default_timezone_set('UTC');

define('ST_VERSION',  '0.7.0');
define('ST_DB_PATH',  dirname(__DIR__) . '/data/surveytrace.db');
define('ST_SCHEMA',   dirname(__DIR__) . '/sql/schema.sql');
define('ST_DATA_DIR', dirname(__DIR__) . '/data');

// ---------------------------------------------------------------------------
// Database connection (singleton PDO)
// ---------------------------------------------------------------------------
function st_db(): PDO {
    if (!empty($GLOBALS['st_surveytrace_pdo']) && $GLOBALS['st_surveytrace_pdo'] instanceof PDO) {
        return $GLOBALS['st_surveytrace_pdo'];
    }

    $dir = ST_DATA_DIR;
    if (!is_dir($dir)) {
        mkdir($dir, 0770, true);
    }

    try {
        $pdo = new PDO('sqlite:' . ST_DB_PATH, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    } catch (PDOException $e) {
        st_json(['error' => 'Database unavailable: ' . $e->getMessage()], 503);
    }

    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA busy_timeout = 8000');
    $pdo->exec('PRAGMA synchronous = NORMAL');

    // Auto-bootstrap schema on first run
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    if (!in_array('assets', $tables)) {
        if (!file_exists(ST_SCHEMA)) {
            st_json(['error' => 'Schema file missing: ' . ST_SCHEMA], 500);
        }
        $pdo->exec(file_get_contents(ST_SCHEMA));
    }

    // Default for DBs created before session_timeout was added (no-op if row exists)
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('session_timeout_minutes', '480')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('extra_safe_ports', '')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('scan_trash_retention_days', '30')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_enrichment_enabled', '0')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_provider', 'ollama')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_model', 'phi3:mini')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_timeout_ms', '700')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_max_hosts_per_scan', '40')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_ambiguous_only', '1')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_suggest_only', '0')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_conflict_only', '1')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_conf_threshold', '0.72')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_conf_threshold_net_srv', '0.82')"
    );

    // Lightweight schema migration for newer scan history snapshot support
    try {
        $pdo->exec("ALTER TABLE scan_jobs ADD COLUMN summary_json TEXT");
    } catch (Throwable $e) {
        // no-op: column already exists
    }
    try {
        $pdo->exec("ALTER TABLE scan_jobs ADD COLUMN deleted_at DATETIME");
    } catch (Throwable $e) {
        // no-op: column already exists
    }
    foreach ([
        "ALTER TABLE scan_jobs ADD COLUMN batch_id INTEGER DEFAULT 0",
        "ALTER TABLE scan_jobs ADD COLUMN batch_index INTEGER DEFAULT 0",
        "ALTER TABLE scan_jobs ADD COLUMN batch_total INTEGER DEFAULT 0",
    ] as $sql) {
        try {
            $pdo->exec($sql);
        } catch (Throwable $e) {
            // no-op: column already exists
        }
    }
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_scan_jobs_deleted_at ON scan_jobs(deleted_at, id DESC)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_scan_jobs_batch ON scan_jobs(batch_id, status, id)");
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS scan_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT,
            created_by TEXT DEFAULT 'web',
            status TEXT DEFAULT 'active',
            total_targets INTEGER DEFAULT 0,
            pending_targets TEXT DEFAULT '[]',
            exclusions TEXT,
            phases TEXT,
            rate_pps INTEGER DEFAULT 5,
            inter_delay INTEGER DEFAULT 200,
            scan_mode TEXT DEFAULT 'auto',
            profile TEXT DEFAULT 'standard_inventory',
            priority INTEGER DEFAULT 10,
            enrichment_source_ids TEXT,
            auto_split_24 INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_scan_batches_status ON scan_batches(status, id)");
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS scan_asset_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id      INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
            asset_id    INTEGER REFERENCES assets(id) ON DELETE SET NULL,
            ip          TEXT,
            hostname    TEXT,
            category    TEXT,
            vendor      TEXT,
            top_cve     TEXT,
            top_cvss    REAL,
            open_ports  TEXT,
            device_id   INTEGER REFERENCES devices(id),
            captured_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_scan_asset_snapshots_job ON scan_asset_snapshots(job_id)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_scan_asset_snapshots_asset ON scan_asset_snapshots(asset_id, job_id DESC)');
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS scan_finding_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id      INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
            asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            cve_id      TEXT NOT NULL,
            cvss        REAL,
            severity    TEXT,
            resolved    INTEGER DEFAULT 0,
            captured_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_scan_finding_snapshots_job ON scan_finding_snapshots(job_id)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_scan_finding_snapshots_asset ON scan_finding_snapshots(asset_id, job_id DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_scan_finding_snapshots_asset_cve ON scan_finding_snapshots(asset_id, cve_id, job_id DESC)');
    try {
        $pdo->exec("ALTER TABLE assets ADD COLUMN ipv6_addrs TEXT DEFAULT '[]'");
    } catch (Throwable $e) {
        // no-op: column already exists
    }
    foreach ([
        "ALTER TABLE assets ADD COLUMN ai_last_confidence REAL",
        "ALTER TABLE assets ADD COLUMN ai_last_rationale TEXT",
        "ALTER TABLE assets ADD COLUMN ai_last_applied INTEGER DEFAULT 0",
        "ALTER TABLE assets ADD COLUMN ai_last_suggested_category TEXT",
        "ALTER TABLE assets ADD COLUMN ai_last_reason TEXT",
        "ALTER TABLE assets ADD COLUMN ai_last_attempted INTEGER DEFAULT 0",
        "ALTER TABLE assets ADD COLUMN ai_last_decision_ts DATETIME",
        "ALTER TABLE assets ADD COLUMN ai_findings_guidance_cache TEXT",
        "ALTER TABLE assets ADD COLUMN ai_host_explain_cache TEXT",
    ] as $sql) {
        try {
            $pdo->exec($sql);
        } catch (Throwable $e) {
            // no-op: column already exists
        }
    }

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS users (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            username         TEXT NOT NULL UNIQUE,
            password_hash    TEXT,
            display_name     TEXT,
            email            TEXT,
            role             TEXT NOT NULL DEFAULT 'admin',
            auth_source      TEXT NOT NULL DEFAULT 'local',
            oidc_issuer      TEXT,
            oidc_sub         TEXT,
            disabled         INTEGER DEFAULT 0,
            mfa_enabled      INTEGER DEFAULT 0,
            mfa_totp_secret  TEXT,
            must_change_password INTEGER DEFAULT 0,
            created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login_at    DATETIME
        )"
    );
    $userCols = array_column($pdo->query("PRAGMA table_info(users)")->fetchAll(), 'name');
    if (!in_array('must_change_password', $userCols, true)) {
        try {
            $pdo->exec("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0");
        } catch (Throwable $e) {
            // no-op if already added concurrently
        }
    }
    if (!in_array('display_name', $userCols, true)) {
        try {
            $pdo->exec("ALTER TABLE users ADD COLUMN display_name TEXT");
        } catch (Throwable $e) {
            // no-op
        }
    }
    if (!in_array('email', $userCols, true)) {
        try {
            $pdo->exec("ALTER TABLE users ADD COLUMN email TEXT");
        } catch (Throwable $e) {
            // no-op
        }
    }
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_users_oidc ON users(auth_source, oidc_issuer, oidc_sub)');
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS user_recovery_codes (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash    TEXT NOT NULL,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            used_at      DATETIME
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_user ON user_recovery_codes(user_id, used_at)');
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS auth_login_state (
            actor_key        TEXT PRIMARY KEY,
            username_norm    TEXT,
            source_ip        TEXT,
            failed_count     INTEGER DEFAULT 0,
            first_failed_at  DATETIME,
            last_failed_at   DATETIME,
            locked_until     DATETIME
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_auth_login_state_user ON auth_login_state(username_norm)');
    $pdo->exec(
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
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_user_audit_log_actor ON user_audit_log(actor_user_id, created_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_user_audit_log_target ON user_audit_log(target_user_id, created_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_user_audit_log_created ON user_audit_log(created_at DESC)');

    // Migrate single legacy password hash into local admin user.
    $userCount = (int)$pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
    if ($userCount === 0) {
        $legacyHash = (string)$pdo->query("SELECT value FROM config WHERE key='auth_hash'")->fetchColumn();
        if ($legacyHash !== '') {
            $insAdmin = $pdo->prepare(
                "INSERT INTO users (username, password_hash, role, auth_source) VALUES ('admin', ?, 'admin', 'local')"
            );
            $insAdmin->execute([$legacyHash]);
        }
    }
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('rbac_enabled', '1')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('oidc_enabled', '0')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('sso_role_source', 'surveytrace')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('breakglass_enabled', '1')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('breakglass_username', 'admin')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('password_min_length', '12')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('password_require_upper', '1')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('password_require_lower', '1')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('password_require_number', '1')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('password_require_symbol', '1')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('password_hash_algo', 'argon2id')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('login_max_attempts', '5')");
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('login_lockout_minutes', '15')");

    st_migrate_device_identity_v1($pdo);

    $GLOBALS['st_surveytrace_pdo'] = $pdo;
    return $pdo;
}

/**
 * Close the shared PDO so SQLite does not keep a connection busy across slow local I/O
 * (Ollama, CLI curl, etc.). The next st_db() opens a new connection.
 *
 * Callers must drop all references to the old PDO first: assign $db = null and set any
 * PDOStatement variables to null (statements keep a reference to the parent PDO until
 * destroyed, which would otherwise prevent SQLite from closing).
 */
function st_db_release_connection(): void {
    unset($GLOBALS['st_surveytrace_pdo']);
}

/**
 * Device-centric identity: devices table, assets.device_id, backfill from legacy rows.
 * Idempotent; completion recorded in config.migration_device_identity_v1 = 1.
 */
function st_normalize_mac(string $m): ?string {
    $m = strtolower(str_replace([':', '-', '.', ' '], '', trim($m)));
    if (strlen($m) !== 12) {
        return null;
    }
    if (strspn($m, '0123456789abcdef') !== 12) {
        return null;
    }
    return $m;
}

function st_migrate_device_identity_v1(PDO $pdo): void {
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_device_identity_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS devices (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
            primary_mac_norm   TEXT,
            label              TEXT
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(primary_mac_norm)');

    $cols = array_column($pdo->query('PRAGMA table_info(assets)')->fetchAll(), 'name');
    if (!in_array('device_id', $cols, true)) {
        try {
            $pdo->exec('ALTER TABLE assets ADD COLUMN device_id INTEGER REFERENCES devices(id)');
        } catch (Throwable $e) {
            // column may already exist from concurrent migration
        }
    }
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_assets_device_id ON assets(device_id)');

    $orphans = $pdo->query('SELECT id, mac FROM assets WHERE device_id IS NULL')->fetchAll();
    if ($orphans) {
        $ins = $pdo->prepare(
            "INSERT INTO devices (created_at, updated_at, primary_mac_norm) VALUES
             (datetime('now'), datetime('now'), :macn)"
        );
        $upd = $pdo->prepare('UPDATE assets SET device_id = :did WHERE id = :aid');
        foreach ($orphans as $o) {
            $macn = st_normalize_mac((string)($o['mac'] ?? '')) ?: null;
            $ins->execute([':macn' => $macn]);
            $did  = (int)$pdo->lastInsertId();
            $upd->execute([':did' => $did, ':aid' => (int)$o['id']]);
        }
    }

    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_device_identity_v1', '1')"
    );
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------
function st_config(string $key, string $default = ''): string {
    static $cache = [];
    if (isset($cache[$key])) return $cache[$key];
    $row = st_db()->prepare("SELECT value FROM config WHERE key = ?")->execute([$key])
        ? st_db()->prepare("SELECT value FROM config WHERE key = ?")->execute([$key]) && false
        : null;
    // Re-query cleanly
    $stmt = st_db()->prepare("SELECT value FROM config WHERE key = ?");
    $stmt->execute([$key]);
    $val = $stmt->fetchColumn();
    $cache[$key] = ($val !== false) ? $val : $default;
    return $cache[$key];
}

function st_config_set(string $key, string $value): void {
    st_db()->prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)")
           ->execute([$key, $value]);
}

// ---------------------------------------------------------------------------
// PHP session (cookie lifetime + idle timeout)
// ---------------------------------------------------------------------------
function st_session_lifetime_seconds(): int {
    $min = (int)st_config('session_timeout_minutes', '480');
    return max(5, min(10080, $min)) * 60;
}

/**
 * Start the SurveyTrace session with cookie + gc lifetime from config.
 * Call before reading $_SESSION (except CLI).
 */
function st_session_start(): void {
    if (PHP_SAPI === 'cli' || session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $life = st_session_lifetime_seconds();
    $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    session_set_cookie_params([
        'lifetime' => $life,
        'path'     => '/',
        'secure'   => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    ini_set('session.gc_maxlifetime', (string)$life);
    session_name('st_sess');
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax',
        'use_strict_mode' => true,
        'gc_maxlifetime'  => $life,
    ]);
}

/**
 * Sliding idle timeout: drop auth if inactive longer than configured lifetime.
 * Refreshes last-activity time on each request while authenticated.
 */
function st_session_touch_idle(): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return;
    }
    if (empty($_SESSION['st_authed']) && empty($_SESSION['st_uid'])) {
        return;
    }
    $life = st_session_lifetime_seconds();
    $at   = (int)($_SESSION['st_authed_at'] ?? 0);
    if ($at <= 0) {
        $_SESSION['st_authed_at'] = time();
        return;
    }
    if ((time() - $at) > $life) {
        $_SESSION = [];
        session_regenerate_id(true);
        return;
    }
    $_SESSION['st_authed_at'] = time();
}

/**
 * Persist session data and release the session file lock.
 * Call after authentication is settled so long-running work (e.g. feed sync)
 * does not block other browser tabs hitting the API with the same session cookie.
 */
function st_release_session_lock(): void {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
}

// ---------------------------------------------------------------------------
// JSON response helper — always exits
// ---------------------------------------------------------------------------
function st_json(mixed $data, int $status = 200): never {
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
    }
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
        | JSON_INVALID_UTF8_SUBSTITUTE;
    $out = json_encode($data, $flags);
    if ($out === false) {
        $out = json_encode([
            'ok'    => false,
            'error' => 'Response serialization failed',
            'detail'=> json_last_error_msg(),
        ], $flags) ?: '{"ok":false,"error":"json encode failed"}';
    }
    echo $out;
    exit;
}

// ---------------------------------------------------------------------------
// Input helpers
// ---------------------------------------------------------------------------
function st_input(): array {
    static $body = null;
    if ($body !== null) return $body;
    $raw = file_get_contents('php://input');
    $body = $raw ? (json_decode($raw, true) ?? []) : [];
    return $body;
}

function st_get(string $key, mixed $default = null): mixed {
    return $_GET[$key] ?? $default;
}

function st_int(string $key, int $default = 0, int $min = 0, int $max = PHP_INT_MAX): int {
    $v = isset($_GET[$key]) ? (int)$_GET[$key] : ((st_input()[$key] ?? null) !== null ? (int)st_input()[$key] : $default);
    return max($min, min($max, $v));
}

function st_str(string $key, string $default = '', ?array $allowed = null): string {
    $v = isset($_GET[$key]) ? trim($_GET[$key]) : trim((string)(st_input()[$key] ?? $default));
    if ($allowed !== null && !in_array($v, $allowed, true)) return $default;
    return $v;
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------
function st_auth(): void {
    // Allow same-host requests from CLI (daemon health checks)
    if (PHP_SAPI === 'cli') return;

    st_session_start();
    st_session_touch_idle();

    // Already authenticated this session
    if (!empty($_SESSION['st_authed']) || !empty($_SESSION['st_uid'])) {
        if (empty($_SESSION['st_role'])) {
            $_SESSION['st_role'] = 'admin';
        }
        st_release_session_lock();
        return;
    }

    $hash = st_config('auth_hash');
    $mode = strtolower(trim(st_config('auth_mode', 'session')));
    if ($mode === 'saml') {
        $mode = 'oidc';
    }
    if (!in_array($mode, ['basic', 'session', 'oidc'], true)) {
        $mode = 'session';
    }
    $hasLocalUsers = (int)st_db()->query("SELECT COUNT(*) FROM users WHERE auth_source='local' AND disabled=0")->fetchColumn() > 0;

    // No password configured → open access (first-run / dev)
    if (!$hasLocalUsers && empty($hash)) {
        $_SESSION['st_role'] = 'admin';
        st_release_session_lock();
        return;
    }

    if ($mode === 'basic') {
        // Check Basic auth credentials
        $user = $_SERVER['PHP_AUTH_USER'] ?? '';
        $pass = $_SERVER['PHP_AUTH_PW']   ?? '';
        if ($user !== '' && $pass !== '') {
            $stmt = st_db()->prepare("
                SELECT id, username, password_hash, role, disabled
                FROM users
                WHERE auth_source='local' AND lower(username)=lower(?)
                LIMIT 1
            ");
            $stmt->execute([$user]);
            $urow = $stmt->fetch();
            if ($urow && (int)$urow['disabled'] === 0 && password_verify($pass, (string)$urow['password_hash'])) {
                st_set_session_user((int)$urow['id'], (string)$urow['username'], (string)$urow['role']);
                st_release_session_lock();
                return;
            }
            if ($user === 'admin' && !empty($hash) && password_verify($pass, $hash)) {
                st_set_session_user(0, 'admin', 'admin');
                st_release_session_lock();
                return;
            }
        }
        st_release_session_lock();
        header('WWW-Authenticate: Basic realm="SurveyTrace"');
        st_json(['error' => 'Authentication required', 'auth_mode' => 'basic'], 401);
    }

    // Session/OIDC modes require explicit login.
    st_release_session_lock();
    st_json(['error' => 'Authentication required', 'auth_mode' => $mode], 401);
}

function st_set_session_user(int $id, string $username, string $role, bool $mustChangePassword = false): void {
    $_SESSION['st_authed'] = true;
    $_SESSION['st_authed_at'] = time();
    $_SESSION['st_uid'] = $id;
    $_SESSION['st_user'] = $username;
    $_SESSION['st_role'] = st_normalize_role($role);
    $_SESSION['st_must_change_password'] = $mustChangePassword ? 1 : 0;
}

function st_normalize_role(string $role): string {
    $r = strtolower(trim($role));
    if (!in_array($r, ['viewer', 'scan_editor', 'admin'], true)) {
        return 'viewer';
    }
    return $r;
}

function st_current_role(): string {
    return st_normalize_role((string)($_SESSION['st_role'] ?? 'admin'));
}

function st_current_user(): array {
    return [
        'id' => (int)($_SESSION['st_uid'] ?? 0),
        'username' => (string)($_SESSION['st_user'] ?? 'admin'),
        'role' => st_current_role(),
        'must_change_password' => !empty($_SESSION['st_must_change_password']),
    ];
}

function st_is_valid_ip(string $ip): bool {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function st_is_private_or_loopback_ip(string $ip): bool {
    if (!st_is_valid_ip($ip)) return false;
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
}

function st_parse_header_ips(string $raw): array {
    $vals = [];
    foreach (explode(',', $raw) as $part) {
        $v = trim($part);
        if ($v === '') continue;
        // XFF may include port (IPv4:port). Keep IPv6 literals untouched.
        if (strpos($v, ':') !== false && substr_count($v, ':') === 1 && strpos($v, '.') !== false) {
            [$host, $port] = explode(':', $v, 2);
            if (ctype_digit($port)) $v = $host;
        }
        $v = trim($v, " \t\n\r\0\x0B\"'[]");
        if (st_is_valid_ip($v)) $vals[] = $v;
    }
    return $vals;
}

function st_request_ip(): string {
    $remote = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    if (!st_is_valid_ip($remote)) return 'unknown';

    // Trust forwarded headers only when request appears to come from a proxy
    // (loopback/private range). This avoids easy spoofing on direct connections.
    if (st_is_private_or_loopback_ip($remote)) {
        $xff = trim((string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
        if ($xff !== '') {
            $ips = st_parse_header_ips($xff);
            if ($ips) return $ips[0]; // left-most = original client
        }
        $xri = trim((string)($_SERVER['HTTP_X_REAL_IP'] ?? ''));
        if (st_is_valid_ip($xri)) return $xri;
        $cf = trim((string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''));
        if (st_is_valid_ip($cf)) return $cf;
    }
    return $remote;
}

function st_audit_log(
    string $action,
    ?int $actorUserId = null,
    ?string $actorUsername = null,
    ?int $targetUserId = null,
    ?string $targetUsername = null,
    array $details = []
): void {
    try {
        st_ensure_user_audit_schema();
        $actor = st_current_user();
        $actorId = $actorUserId ?? (($actor['id'] ?? 0) > 0 ? (int)$actor['id'] : null);
        $actorName = $actorUsername ?? (($actor['username'] ?? '') !== '' ? (string)$actor['username'] : null);
        $payload = $details ? json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null;
        st_db()->prepare(
            "INSERT INTO user_audit_log
             (actor_user_id, actor_username, target_user_id, target_username, action, details_json, source_ip)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )->execute([
            $actorId,
            $actorName,
            $targetUserId,
            $targetUsername,
            $action,
            $payload,
            st_request_ip(),
        ]);
    } catch (Throwable $e) {
        // Keep auth paths resilient even if logging fails, but emit diagnostics.
        @error_log('SurveyTrace audit log write failed: ' . (string)$e->getMessage());
    }
}

function st_ensure_user_audit_schema(): void {
    static $ready = false;
    if ($ready) return;
    $pdo = st_db();
    $pdo->exec(
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
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_user_audit_log_actor ON user_audit_log(actor_user_id, created_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_user_audit_log_target ON user_audit_log(target_user_id, created_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_user_audit_log_created ON user_audit_log(created_at DESC)');
    $ready = true;
}

function st_require_role(array $allowed): void {
    $role = st_current_role();
    $norm = array_values(array_unique(array_map('st_normalize_role', $allowed)));
    if (!in_array($role, $norm, true)) {
        st_json([
            'ok' => false,
            'error' => 'Permission denied',
            'required_roles' => $norm,
            'role' => $role,
        ], 403);
    }
}

function st_generate_mfa_secret(int $bytes = 20): string {
    return st_base32_encode(random_bytes(max(10, $bytes)));
}

function st_base32_encode(string $raw): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    $out = '';
    $len = strlen($raw);
    for ($i = 0; $i < $len; $i++) {
        $bits .= str_pad(decbin(ord($raw[$i])), 8, '0', STR_PAD_LEFT);
    }
    $pad = strlen($bits) % 5;
    if ($pad !== 0) $bits .= str_repeat('0', 5 - $pad);
    for ($i = 0; $i < strlen($bits); $i += 5) {
        $out .= $alphabet[bindec(substr($bits, $i, 5))];
    }
    return $out;
}

function st_base32_decode(string $input): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $s = strtoupper(preg_replace('/[^A-Z2-7]/', '', $input) ?? '');
    $bits = '';
    $out = '';
    $len = strlen($s);
    for ($i = 0; $i < $len; $i++) {
        $p = strpos($alphabet, $s[$i]);
        if ($p === false) continue;
        $bits .= str_pad(decbin((int)$p), 5, '0', STR_PAD_LEFT);
    }
    for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
        $out .= chr(bindec(substr($bits, $i, 8)));
    }
    return $out;
}

function st_totp_code(string $base32Secret, ?int $unixTime = null, int $period = 30, int $digits = 6): string {
    $key = st_base32_decode($base32Secret);
    if ($key === '') return '';
    $t = intdiv($unixTime ?? time(), $period);
    $msg = pack('N*', 0, $t);
    $hash = hash_hmac('sha1', $msg, $key, true);
    $offset = ord(substr($hash, -1)) & 0x0F;
    $bin = ((ord($hash[$offset]) & 0x7F) << 24)
         | ((ord($hash[$offset + 1]) & 0xFF) << 16)
         | ((ord($hash[$offset + 2]) & 0xFF) << 8)
         | (ord($hash[$offset + 3]) & 0xFF);
    $mod = (int)pow(10, $digits);
    return str_pad((string)($bin % $mod), $digits, '0', STR_PAD_LEFT);
}

function st_verify_totp(string $base32Secret, string $otp, int $window = 1): bool {
    $otp = preg_replace('/\s+/', '', $otp) ?? '';
    if (!preg_match('/^\d{6}$/', $otp)) return false;
    $now = time();
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(st_totp_code($base32Secret, $now + ($i * 30)), $otp)) {
            return true;
        }
    }
    return false;
}

function st_generate_recovery_codes(int $count = 8): array {
    $out = [];
    for ($i = 0; $i < $count; $i++) {
        $n = strtoupper(bin2hex(random_bytes(4)));
        $out[] = substr($n, 0, 4) . '-' . substr($n, 4, 4);
    }
    return $out;
}

function st_password_policy(): array {
    $minLen = (int)st_config('password_min_length', '12');
    return [
        'min_length' => max(8, min(128, $minLen)),
        'require_upper' => st_config('password_require_upper', '1') === '1',
        'require_lower' => st_config('password_require_lower', '1') === '1',
        'require_number' => st_config('password_require_number', '1') === '1',
        'require_symbol' => st_config('password_require_symbol', '1') === '1',
    ];
}

function st_validate_password_strength(string $password, ?array $policy = null): array {
    $p = $policy ?: st_password_policy();
    $errors = [];
    if (strlen($password) < (int)$p['min_length']) {
        $errors[] = 'Password must be at least ' . (int)$p['min_length'] . ' characters.';
    }
    if (!empty($p['require_upper']) && !preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Password must include an uppercase letter.';
    }
    if (!empty($p['require_lower']) && !preg_match('/[a-z]/', $password)) {
        $errors[] = 'Password must include a lowercase letter.';
    }
    if (!empty($p['require_number']) && !preg_match('/[0-9]/', $password)) {
        $errors[] = 'Password must include a number.';
    }
    if (!empty($p['require_symbol']) && !preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = 'Password must include a symbol.';
    }
    return $errors;
}

function st_password_hash_algo(): string {
    $algo = strtolower(trim(st_config('password_hash_algo', 'argon2id')));
    if (!in_array($algo, ['argon2id', 'bcrypt'], true)) {
        $algo = 'argon2id';
    }
    if ($algo === 'argon2id' && !defined('PASSWORD_ARGON2ID')) {
        return 'bcrypt';
    }
    return $algo;
}

function st_password_hash(string $password): string {
    $algo = st_password_hash_algo();
    if ($algo === 'argon2id' && defined('PASSWORD_ARGON2ID')) {
        return password_hash($password, PASSWORD_ARGON2ID);
    }
    return password_hash($password, PASSWORD_BCRYPT);
}

function st_password_needs_rehash(string $hash): bool {
    $algo = st_password_hash_algo();
    if ($algo === 'argon2id' && defined('PASSWORD_ARGON2ID')) {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID);
    }
    return password_needs_rehash($hash, PASSWORD_BCRYPT);
}

function st_login_max_attempts(): int {
    return max(3, min(20, (int)st_config('login_max_attempts', '5')));
}

function st_login_lockout_minutes(): int {
    return max(1, min(1440, (int)st_config('login_lockout_minutes', '15')));
}

function st_login_actor_key(string $username, string $ip): string {
    return hash('sha256', strtolower(trim($username)) . '|' . trim($ip));
}

function st_login_lock_state(string $username, string $ip): array {
    $userNorm = strtolower(trim($username));
    $actorKey = st_login_actor_key($username, $ip);
    $stmt = st_db()->prepare("SELECT failed_count, locked_until FROM auth_login_state WHERE actor_key=? LIMIT 1");
    $stmt->execute([$actorKey]);
    $row = $stmt->fetch() ?: ['failed_count' => 0, 'locked_until' => null];
    $lockedUntil = (string)($row['locked_until'] ?? '');
    $locked = false;
    $retryAfter = 0;
    if ($lockedUntil !== '') {
        $retryAfter = strtotime($lockedUntil) - time();
        if ($retryAfter > 0) {
            $locked = true;
        } else {
            $retryAfter = 0;
        }
    }
    return [
        'actor_key' => $actorKey,
        'username_norm' => $userNorm,
        'failed_count' => (int)($row['failed_count'] ?? 0),
        'locked' => $locked,
        'retry_after_sec' => $retryAfter,
    ];
}

function st_login_register_failure(string $username, string $ip): array {
    $db = st_db();
    $state = st_login_lock_state($username, $ip);
    $failed = $state['failed_count'] + 1;
    $maxAttempts = st_login_max_attempts();
    $lockMinutes = st_login_lockout_minutes();
    $lockedUntilSql = ($failed >= $maxAttempts)
        ? "datetime('now','+" . $lockMinutes . " minutes')"
        : "NULL";
    $sql = "
        INSERT INTO auth_login_state (actor_key, username_norm, source_ip, failed_count, first_failed_at, last_failed_at, locked_until)
        VALUES (:k, :u, :ip, 1, datetime('now'), datetime('now'), $lockedUntilSql)
        ON CONFLICT(actor_key) DO UPDATE SET
            failed_count = failed_count + 1,
            last_failed_at = datetime('now'),
            locked_until = CASE WHEN (failed_count + 1) >= :mx THEN datetime('now','+" . $lockMinutes . " minutes') ELSE NULL END
    ";
    $stmt = $db->prepare($sql);
    $stmt->execute([
        ':k' => $state['actor_key'],
        ':u' => $state['username_norm'],
        ':ip' => trim($ip),
        ':mx' => $maxAttempts,
    ]);
    return st_login_lock_state($username, $ip);
}

function st_login_register_success(string $username, string $ip): void {
    $actorKey = st_login_actor_key($username, $ip);
    $stmt = st_db()->prepare("DELETE FROM auth_login_state WHERE actor_key=?");
    $stmt->execute([$actorKey]);
}

// ---------------------------------------------------------------------------
// Severity helper (CVSS score → label)
// ---------------------------------------------------------------------------
function st_severity(float $cvss): string {
    if ($cvss >= 9.0) return 'critical';
    if ($cvss >= 7.0) return 'high';
    if ($cvss >= 4.0) return 'medium';
    if ($cvss >  0.0) return 'low';
    return 'none';
}

// ---------------------------------------------------------------------------
// CORS / request method guard
// ---------------------------------------------------------------------------
function st_method(string ...$allowed): void {
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, $allowed, true)) {
        st_json(['error' => "Method $method not allowed"], 405);
    }
    if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        st_require_csrf();
    }
}

function st_csrf_token(): string {
    st_session_start();
    $tok = (string)($_SESSION['st_csrf'] ?? '');
    if ($tok === '') {
        $tok = bin2hex(random_bytes(32));
        $_SESSION['st_csrf'] = $tok;
    }
    return $tok;
}

function st_require_csrf(): void {
    if (PHP_SAPI === 'cli') return;
    st_session_start();
    st_require_same_origin();
    $expected = st_csrf_token();
    $provided = trim((string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''));
    if ($provided === '' || !hash_equals($expected, $provided)) {
        st_json(['error' => 'CSRF validation failed'], 403);
    }
}

function st_same_origin_ok(?string $url): bool {
    $u = trim((string)$url);
    if ($u === '') return false;
    $parts = @parse_url($u);
    if (!is_array($parts)) return false;
    $srcHost = strtolower((string)($parts['host'] ?? ''));
    if ($srcHost === '') return false;
    $srcScheme = strtolower((string)($parts['scheme'] ?? 'http'));
    $srcPort = (int)($parts['port'] ?? (($srcScheme === 'https') ? 443 : 80));

    $hostHdr = strtolower(trim((string)($_SERVER['HTTP_HOST'] ?? '')));
    if ($hostHdr === '') {
        $hostHdr = strtolower(trim((string)($_SERVER['SERVER_NAME'] ?? '')));
    }
    if ($hostHdr === '') return false;
    $hostParts = explode(':', $hostHdr, 2);
    $reqHost = $hostParts[0];
    $xfProto = strtolower(trim((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
    if (str_contains($xfProto, ',')) {
        $xfProto = strtolower(trim(explode(',', $xfProto, 2)[0]));
    }
    $reqScheme = in_array($xfProto, ['http', 'https'], true)
        ? $xfProto
        : ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
    $xfPort = trim((string)($_SERVER['HTTP_X_FORWARDED_PORT'] ?? ''));
    $reqPort = isset($hostParts[1]) && ctype_digit($hostParts[1])
        ? (int)$hostParts[1]
        : ((ctype_digit($xfPort) && (int)$xfPort > 0) ? (int)$xfPort : (($reqScheme === 'https') ? 443 : 80));

    return $srcHost === $reqHost && $srcScheme === $reqScheme && $srcPort === $reqPort;
}

function st_require_same_origin(): void {
    if (PHP_SAPI === 'cli') return;
    $origin = trim((string)($_SERVER['HTTP_ORIGIN'] ?? ''));
    if ($origin !== '') {
        if (!st_same_origin_ok($origin)) {
            st_json(['error' => 'Cross-origin request rejected'], 403);
        }
        return;
    }
    $referer = trim((string)($_SERVER['HTTP_REFERER'] ?? ''));
    if ($referer !== '' && !st_same_origin_ok($referer)) {
        st_json(['error' => 'Cross-origin request rejected'], 403);
    }
}
