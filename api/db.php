<?php
/**
 * SurveyTrace — core database + auth helper
 * Included by every API endpoint.
 */

// Always use UTC for all date/time operations regardless of server timezone
date_default_timezone_set('UTC');

define('ST_VERSION',  '0.2.0');
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

    return $pdo;
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
// JSON response helper — always exits
// ---------------------------------------------------------------------------
function st_json(mixed $data, int $status = 200): never {
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
    }
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
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

    session_name('st_sess');
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax',
        'use_strict_mode' => true,
    ]);

    // Already authenticated this session
    if (!empty($_SESSION['st_authed'])) return;

    $hash = st_config('auth_hash');
    $mode = strtolower(trim(st_config('auth_mode', 'basic')));
    if (!in_array($mode, ['basic', 'session'], true)) {
        $mode = 'basic';
    }

    // No password configured → open access (first-run / dev)
    if (empty($hash)) return;

    if ($mode === 'basic') {
        // Check Basic auth credentials
        $user = $_SERVER['PHP_AUTH_USER'] ?? '';
        $pass = $_SERVER['PHP_AUTH_PW']   ?? '';
        if ($user === 'admin' && password_verify($pass, $hash)) {
            $_SESSION['st_authed']  = true;
            $_SESSION['st_authed_at'] = time();
            return;
        }
        header('WWW-Authenticate: Basic realm="SurveyTrace"');
        st_json(['error' => 'Authentication required', 'auth_mode' => 'basic'], 401);
    }

    // Session mode requires explicit login via /api/auth.php
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
