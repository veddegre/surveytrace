<?php
/**
 * SurveyTrace — core database + auth helper
 * Included by every API endpoint.
 */

// Always use UTC for all date/time operations regardless of server timezone
date_default_timezone_set('UTC');

define('ST_VERSION',  '0.5.0');
define('ST_DB_PATH',  dirname(__DIR__) . '/data/surveytrace.db');
define('ST_SCHEMA',   dirname(__DIR__) . '/sql/schema.sql');
define('ST_DATA_DIR', dirname(__DIR__) . '/data');

// ---------------------------------------------------------------------------
// Database connection (singleton PDO)
// ---------------------------------------------------------------------------
function st_db(): PDO {
    static $pdo = null;
    if ($pdo !== null) return $pdo;

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

    // Lightweight schema migration for newer scan history snapshot support
    try {
        $pdo->exec("ALTER TABLE scan_jobs ADD COLUMN summary_json TEXT");
    } catch (Throwable $e) {
        // no-op: column already exists
    }
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

    st_migrate_device_identity_v1($pdo);

    return $pdo;
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
    if (empty($_SESSION['st_authed'])) {
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
    if (!empty($_SESSION['st_authed'])) {
        st_release_session_lock();
        return;
    }

    $hash = st_config('auth_hash');
    $mode = strtolower(trim(st_config('auth_mode', 'basic')));
    if (!in_array($mode, ['basic', 'session'], true)) {
        $mode = 'basic';
    }

    // No password configured → open access (first-run / dev)
    if (empty($hash)) {
        st_release_session_lock();
        return;
    }

    if ($mode === 'basic') {
        // Check Basic auth credentials
        $user = $_SERVER['PHP_AUTH_USER'] ?? '';
        $pass = $_SERVER['PHP_AUTH_PW']   ?? '';
        if ($user === 'admin' && password_verify($pass, $hash)) {
            $_SESSION['st_authed']  = true;
            $_SESSION['st_authed_at'] = time();
            st_release_session_lock();
            return;
        }
        st_release_session_lock();
        header('WWW-Authenticate: Basic realm="SurveyTrace"');
        st_json(['error' => 'Authentication required', 'auth_mode' => 'basic'], 401);
    }

    // Session mode requires explicit login via /api/auth.php
    st_release_session_lock();
    st_json(['error' => 'Authentication required', 'auth_mode' => 'session'], 401);
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
}
