-- NetTrace database schema
-- SQLite 3.x

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- -------------------------------------------------------
-- Devices: stable logical identity; assets remain one row per IP (address).
-- See docs/DEVICE_IDENTITY.md.
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    primary_mac_norm   TEXT,
    label              TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(primary_mac_norm);

-- -------------------------------------------------------
-- Assets: every discovered host, one row per IP, linked to a device
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT NOT NULL UNIQUE,
    hostname     TEXT,
    mac          TEXT,
    mac_vendor   TEXT,
    category     TEXT DEFAULT 'unk',
        -- srv | ws | net | iot | ot | voi | prn | hv | unk
    vendor       TEXT,
    model        TEXT,
    os_guess     TEXT,
    cpe          TEXT,           -- e.g. cpe:/h:siemens:s7-1200
    connected_via TEXT,         -- e.g. "Switch FDB via 192.168.86.95 port Gi1/0/3"
    open_ports   TEXT,          -- JSON array: [22, 80, 443]
    banners      TEXT,          -- JSON object: {"443": "BIG-IP ..."}
    nmap_cpes     TEXT DEFAULT '[]',
    discovery_sources TEXT DEFAULT '[]',
    top_cve      TEXT,
    top_cvss     REAL,
    first_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_scan_id INTEGER,
    notes        TEXT,
    device_id     INTEGER REFERENCES devices(id)
);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_device_id ON assets(device_id);
CREATE INDEX IF NOT EXISTS idx_assets_category ON assets(category);
CREATE INDEX IF NOT EXISTS idx_assets_top_cvss ON assets(top_cvss DESC);

-- -------------------------------------------------------
-- Findings: one row per CVE per asset
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id     INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ip           TEXT NOT NULL,
    cve_id       TEXT NOT NULL,
    cvss         REAL,
    severity     TEXT,   -- critical | high | medium | low | info
    description  TEXT,
    published    TEXT,
    confirmed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved     INTEGER DEFAULT 0,
    notes        TEXT,
    UNIQUE(asset_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

-- -------------------------------------------------------
-- Scan jobs: queued/running/done jobs dispatched by PHP / scheduler
-- (Keep in sync with migrations in api/scan_start.php, dashboard.php,
--  scanner_daemon.py, and daemon/scheduler_daemon.py.)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    status       TEXT DEFAULT 'queued',
        -- queued | running | done | aborted | failed | retrying
    target_cidr  TEXT NOT NULL,
    label        TEXT,
    exclusions   TEXT,           -- newline-separated
    phases       TEXT,           -- JSON array: ["passive","icmp",...]
    rate_pps     INTEGER DEFAULT 5,
    inter_delay  INTEGER DEFAULT 200,
    scan_mode    TEXT DEFAULT 'auto',
    profile      TEXT DEFAULT 'standard_inventory',
    priority     INTEGER DEFAULT 10,
    retry_count  INTEGER DEFAULT 0,
    max_retries  INTEGER DEFAULT 2,
    schedule_id  INTEGER DEFAULT 0,
    collector_id INTEGER DEFAULT 0,
    phase_status TEXT DEFAULT '{}',
    failure_reason TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    started_at   DATETIME,
    finished_at  DATETIME,
    hosts_found  INTEGER DEFAULT 0,
    hosts_scanned INTEGER DEFAULT 0,
    summary_json TEXT,
    error_msg    TEXT,
    created_by   TEXT DEFAULT 'web',
    -- JSON array of enrichment_sources.id; NULL = all enabled; [] = skip phase 3b
    enrichment_source_ids TEXT
);

-- -------------------------------------------------------
-- Scan log: full audit trail of every probe sent
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id   INTEGER REFERENCES scan_jobs(id),
    ts       DATETIME DEFAULT CURRENT_TIMESTAMP,
    level    TEXT DEFAULT 'INFO',  -- INFO | PROBE | WARN | ERR
    ip       TEXT,
    message  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_log_job ON scan_log(job_id);
CREATE INDEX IF NOT EXISTS idx_log_ts ON scan_log(ts DESC);

-- -------------------------------------------------------
-- Per-scan asset snapshot: preserve what each run saw
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_asset_snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
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
);
CREATE INDEX IF NOT EXISTS idx_scan_asset_snapshots_job ON scan_asset_snapshots(job_id);
CREATE INDEX IF NOT EXISTS idx_scan_asset_snapshots_asset ON scan_asset_snapshots(asset_id, job_id DESC);

-- -------------------------------------------------------
-- Per-scan finding snapshot: preserve CVE state per run
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_finding_snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cve_id      TEXT NOT NULL,
    cvss        REAL,
    severity    TEXT,
    resolved    INTEGER DEFAULT 0,
    captured_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scan_finding_snapshots_job ON scan_finding_snapshots(job_id);
CREATE INDEX IF NOT EXISTS idx_scan_finding_snapshots_asset ON scan_finding_snapshots(asset_id, job_id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_finding_snapshots_asset_cve ON scan_finding_snapshots(asset_id, cve_id, job_id DESC);

-- -------------------------------------------------------
-- Port snapshots: track port changes over time
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS port_history (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id  INTEGER REFERENCES scan_jobs(id),
    ports    TEXT NOT NULL,   -- JSON array
    seen_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- -------------------------------------------------------
-- Config: key/value settings store
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- -------------------------------------------------------
-- Local/OIDC users + roles + MFA recovery
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT NOT NULL UNIQUE,
    password_hash    TEXT,
    role             TEXT NOT NULL DEFAULT 'admin', -- viewer | scan_editor | admin
    auth_source      TEXT NOT NULL DEFAULT 'local', -- local | oidc
    oidc_issuer      TEXT,
    oidc_sub         TEXT,
    disabled         INTEGER DEFAULT 0,
    mfa_enabled      INTEGER DEFAULT 0,
    mfa_totp_secret  TEXT,
    must_change_password INTEGER DEFAULT 0,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login_at    DATETIME
);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_oidc ON users(auth_source, oidc_issuer, oidc_sub);

CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash    TEXT NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    used_at      DATETIME
);
CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_user ON user_recovery_codes(user_id, used_at);

CREATE TABLE IF NOT EXISTS auth_login_state (
    actor_key        TEXT PRIMARY KEY,
    username_norm    TEXT,
    source_ip        TEXT,
    failed_count     INTEGER DEFAULT 0,
    first_failed_at  DATETIME,
    last_failed_at   DATETIME,
    locked_until     DATETIME
);
CREATE INDEX IF NOT EXISTS idx_auth_login_state_user ON auth_login_state(username_norm);

INSERT OR IGNORE INTO config VALUES
    ('nvd_last_sync',   ''),
    ('snmp_community',  'public'),
    ('alert_webhook',   ''),
    ('alert_email',     ''),
    ('scan_schedule',   ''),
    ('auth_hash',       ''),  -- bcrypt hash of web UI password
    ('auth_mode',       'session'),  -- basic | session | oidc
    ('rbac_enabled',    '1'),
    ('oidc_enabled',    '0'),
    ('oidc_issuer_url', ''),
    ('oidc_client_id',  ''),
    ('oidc_client_secret', ''),
    ('oidc_redirect_uri', ''),
    ('oidc_role_claim', 'groups'),
    ('oidc_role_map',   ''),
    ('sso_role_source', 'surveytrace'),
    ('breakglass_enabled', '1'),
    ('breakglass_username', 'admin'),
    ('password_min_length', '12'),
    ('password_require_upper', '1'),
    ('password_require_lower', '1'),
    ('password_require_number', '1'),
    ('password_require_symbol', '1'),
    ('password_hash_algo', 'argon2id'),
    ('login_max_attempts', '5'),
    ('login_lockout_minutes', '15'),
    ('session_timeout_minutes', '480'),  -- idle timeout + session cookie max-age (5–10080)
    ('extra_safe_ports', '');  -- comma-separated additional ports for routed fast_full_tcp safe scan
