-- NetTrace database schema
-- SQLite 3.x

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- -------------------------------------------------------
-- Assets: every discovered host, one row per IP
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
    connected_via TEXT,          -- e.g. "Switch FDB via 192.168.86.95 port Gi1/0/3"
    open_ports   TEXT,           -- JSON array: [22, 80, 443]
    banners      TEXT,           -- JSON object: {"443": "BIG-IP ..."}
    top_cve      TEXT,
    top_cvss     REAL,
    first_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_scan_id INTEGER,
    notes        TEXT
);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
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
-- Scan jobs: queued/running/done jobs dispatched by PHP
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    status       TEXT DEFAULT 'queued',
        -- queued | running | done | aborted | failed
    target_cidr  TEXT NOT NULL,
    exclusions   TEXT,           -- newline-separated
    phases       TEXT,           -- JSON array: ["passive","icmp","banner","fingerprint","cve"]
    rate_pps     INTEGER DEFAULT 5,
    inter_delay  INTEGER DEFAULT 200,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    started_at   DATETIME,
    finished_at  DATETIME,
    hosts_found  INTEGER DEFAULT 0,
    hosts_scanned INTEGER DEFAULT 0,
    error_msg    TEXT,
    created_by   TEXT DEFAULT 'web'
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

INSERT OR IGNORE INTO config VALUES
    ('nvd_last_sync',   ''),
    ('snmp_community',  'public'),
    ('alert_webhook',   ''),
    ('alert_email',     ''),
    ('scan_schedule',   ''),
    ('auth_hash',       '');  -- bcrypt hash of web UI password
