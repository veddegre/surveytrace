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
        -- srv | ws | net | iot | ot | voi | prn | hv (VMware ESXi/vSphere/vCenter, Proxmox VE, Hyper-V, …) | unk
    vendor       TEXT,
    model        TEXT,
    os_guess     TEXT,
    cpe          TEXT,           -- e.g. cpe:/h:siemens:s7-1200
    connected_via TEXT,         -- e.g. "Switch FDB via 192.168.86.95 port Gi1/0/3"
    ipv6_addrs   TEXT DEFAULT '[]', -- JSON array: ["2001:db8::10", "fd00::abcd"]
    open_ports   TEXT,          -- JSON array: [22, 80, 443]
    banners      TEXT,          -- JSON object: {"443": "BIG-IP ..."}
    nmap_cpes     TEXT DEFAULT '[]',
    discovery_sources TEXT DEFAULT '[]',
    ai_last_confidence REAL,
    ai_last_rationale TEXT,
    ai_last_applied INTEGER DEFAULT 0,
    ai_last_suggested_category TEXT,
    ai_last_reason TEXT,
    ai_last_attempted INTEGER DEFAULT 0,
    ai_last_decision_ts DATETIME,
    ai_findings_guidance_cache TEXT,
    ai_host_explain_cache TEXT,
    top_cve      TEXT,
    top_cvss     REAL,
    first_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_scan_id INTEGER,
    notes        TEXT,
    device_id     INTEGER REFERENCES devices(id),
    -- Lifecycle vs expected scan coverage + operator metadata
    lifecycle_status              TEXT DEFAULT 'active',
    lifecycle_reason              TEXT,
    last_expected_scan_id         INTEGER,
    last_expected_scan_at         DATETIME,
    last_missed_scan_id           INTEGER,
    last_missed_scan_at           DATETIME,
    missed_scan_count             INTEGER DEFAULT 0,
    retired_at                    DATETIME,
    owner                         TEXT,
    business_unit                 TEXT,
    criticality                   TEXT DEFAULT 'medium',
    environment                   TEXT DEFAULT 'unknown',
    identity_confidence           REAL,
    identity_confidence_reason    TEXT,
    -- When 1, scan/enrichment must not overwrite the field (set via API PUT).
    hostname_locked               INTEGER DEFAULT 0,
    category_locked               INTEGER DEFAULT 0,
    vendor_locked                 INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_device_id ON assets(device_id);
CREATE INDEX IF NOT EXISTS idx_assets_category ON assets(category);
CREATE INDEX IF NOT EXISTS idx_assets_top_cvss ON assets(top_cvss DESC);
CREATE INDEX IF NOT EXISTS idx_assets_lifecycle_status ON assets(lifecycle_status);

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
    lifecycle_state      TEXT DEFAULT 'active',
        -- new | active | mitigated | accepted | reopened
    mitigated_at         DATETIME,
    accepted_at          DATETIME,
    accepted_by_user_id  INTEGER,
    first_seen_job_id    INTEGER,
    last_seen_job_id     INTEGER,
    -- Explainable CVE triage (scanner / collector)
    provenance_source    TEXT DEFAULT 'unknown',
        -- scanner | collector | unknown
    detection_method     TEXT,
        -- nmap_port_cpe | asset_fingerprint_cpe | collector_ingest | unknown
    confidence           TEXT DEFAULT 'low',
        -- high | medium | low
    risk_score           REAL,
        -- 0–100 weighted triage score (CVSS-derived; not a replacement for CVSS)
    evidence_json        TEXT,
        -- JSON: matched_cpe, cpe_origin, rationale, optional collector hints
    UNIQUE(asset_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_lifecycle ON findings(lifecycle_state, resolved);
CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings(risk_score DESC);

-- -------------------------------------------------------
-- CVE intelligence (CISA KEV + FIRST EPSS + OSV); sync_cve_intel.py → surveytrace.db
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_intel (
    cve_id            TEXT PRIMARY KEY,
    kev               INTEGER DEFAULT 0,
    kev_date_added    TEXT,
    kev_due_date      TEXT,
    kev_vendor        TEXT,
    kev_product       TEXT,
    kev_action        TEXT,
    epss              REAL,
    epss_percentile   REAL,
    epss_scored_at    TEXT,
    osv_ecosystems    TEXT,
    osv_updated_at    TEXT,
    updated_at        TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_cve_intel_kev ON cve_intel(kev);
CREATE INDEX IF NOT EXISTS idx_cve_intel_epss ON cve_intel(epss DESC);

-- -------------------------------------------------------
-- Scan scopes — reporting / multi-network boundaries
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_scopes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    description   TEXT,
    scope_type    TEXT DEFAULT 'network',
    cidrs         TEXT DEFAULT '[]',
    tags          TEXT DEFAULT '[]',
    owner         TEXT,
    environment   TEXT DEFAULT 'unknown',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scan_scopes_name ON scan_scopes(name);

CREATE TABLE IF NOT EXISTS scan_scope_baselines (
    scope_id         INTEGER PRIMARY KEY REFERENCES scan_scopes(id) ON DELETE CASCADE,
    baseline_job_id  INTEGER NOT NULL,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

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
    deleted_at   DATETIME,
    batch_id     INTEGER DEFAULT 0,
    batch_index  INTEGER DEFAULT 0,
    batch_total  INTEGER DEFAULT 0,
    created_by   TEXT DEFAULT 'web',
    -- JSON array of enrichment_sources.id; NULL = all enabled; [] = skip network enrichment
    enrichment_source_ids TEXT,
    -- Operator-selected baseline for reporting (at most one job should have 1)
    is_baseline INTEGER DEFAULT 0,
    -- Optional link to scan_scopes for scoped reporting
    scope_id INTEGER REFERENCES scan_scopes(id)
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_deleted_at ON scan_jobs(deleted_at, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_batch ON scan_jobs(batch_id, status, id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_scope_status_finished ON scan_jobs(scope_id, status, finished_at DESC);

-- -------------------------------------------------------
-- Scan batches: staged feeder for large target sets
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_batches (
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
);
CREATE INDEX IF NOT EXISTS idx_scan_batches_status ON scan_batches(status, id);

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
-- Scheduled report outputs (JSON payloads)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS report_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    schedule_id INTEGER,
    baseline_job_id INTEGER,
    compare_job_id INTEGER,
    kind TEXT DEFAULT 'scheduled',
    title TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_report_artifacts_created ON report_artifacts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_artifacts_schedule ON report_artifacts(schedule_id, id DESC);

-- -------------------------------------------------------
-- Integrations configuration (push + pull metadata rows)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS integrations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    type           TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    endpoint_url   TEXT NOT NULL DEFAULT '',
    host           TEXT NOT NULL DEFAULT '',
    port           INTEGER,
    auth_secret    TEXT,
    extra_json     TEXT NOT NULL DEFAULT '{}',
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_test_at   DATETIME,
    last_test_status TEXT,
    last_error     TEXT,
    token_hash         TEXT,
    token_created_at   DATETIME,
    token_last_used_at DATETIME,
    token_last_used_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations(type);
CREATE INDEX IF NOT EXISTS idx_integrations_enabled ON integrations(enabled);

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
    display_name     TEXT,
    email            TEXT,
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

CREATE TABLE IF NOT EXISTS user_audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_username   TEXT,
    target_user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_username  TEXT,
    action           TEXT NOT NULL,
    details_json     TEXT,
    source_ip        TEXT,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_user_audit_log_actor ON user_audit_log(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_audit_log_target ON user_audit_log(target_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_audit_log_created ON user_audit_log(created_at DESC);

-- -------------------------------------------------------
-- Change alerts (new assets, port deltas, CVE lifecycle)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS change_alerts (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_type            TEXT NOT NULL,
    job_id                INTEGER,
    asset_id              INTEGER,
    finding_id            INTEGER,
    detail_json           TEXT,
    dismissed_at          DATETIME,
    dismissed_by_user_id  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_change_alerts_created ON change_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_change_alerts_open ON change_alerts(dismissed_at, created_at DESC);

-- -------------------------------------------------------
-- Trusted reconciliation v1 — observations, assertions, evidence (read-model slice)
-- Milestone 1: foundational tables for multi-source beliefs + audit trail.
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS recon_sources (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_type          TEXT NOT NULL,
        -- surveytrace_scan | zabbix_inventory | surveytrace_enrichment | connector | ...
    source_instance_key  TEXT NOT NULL DEFAULT 'default',
        -- future: per-connector instance id or URL fingerprint
    display_name         TEXT NOT NULL DEFAULT '',
    trust_level          TEXT NOT NULL DEFAULT 'medium',
        -- low | medium | high | authoritative
    freshness_sec        INTEGER NOT NULL DEFAULT 86400,
        -- hint for stale-aware reconciliation (optional)
    enabled              INTEGER NOT NULL DEFAULT 1,
    meta_json            TEXT,
    UNIQUE(source_type, source_instance_key)
);
CREATE INDEX IF NOT EXISTS idx_recon_sources_type ON recon_sources(source_type, enabled);

CREATE TABLE IF NOT EXISTS asset_observations (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    asset_id             INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    observation_type     TEXT NOT NULL,
        -- os_fingerprint_scan | os_fingerprint_cpe | os_inventory_zabbix | os_hint_enrichment
        -- | hostname_observed | fqdn_observed | ipv4_observed | mac_observed | monitoring_hostid | device_link | ...
        -- | software_observed (legacy bounded credentialed package sample rows) |
        -- | software_inventory_snapshot_observed (per-target inventory diff summary; normalized tables hold detail) | ...
    raw_value            TEXT,
    normalized_value     TEXT,
    source_id            INTEGER NOT NULL REFERENCES recon_sources(id),
    source_object_ref    TEXT NOT NULL DEFAULT '',
        -- e.g. Zabbix hostid
    observed_at          DATETIME NOT NULL DEFAULT (datetime('now')),
    confidence_level     TEXT NOT NULL DEFAULT 'medium',
        -- low | medium | high | authoritative (per-observation hint)
    provenance_json      TEXT,
    UNIQUE(asset_id, observation_type, source_id, source_object_ref)
);
CREATE INDEX IF NOT EXISTS idx_asset_obs_asset ON asset_observations(asset_id, observation_type);
CREATE INDEX IF NOT EXISTS idx_asset_obs_seen ON asset_observations(observed_at DESC);

CREATE TABLE IF NOT EXISTS asset_assertions (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    asset_id             INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    assertion_type       TEXT NOT NULL,
        -- os_platform | canonical_hostname | software_inventory_summary | ...
    asserted_value       TEXT NOT NULL,
        -- normalized bucket key (machine-readable)
    confidence_level     TEXT NOT NULL DEFAULT 'medium',
        -- low | medium | high | authoritative
    status               TEXT NOT NULL DEFAULT 'active',
        -- active | superseded | conflict (reserved)
    reconciled_at        DATETIME NOT NULL DEFAULT (datetime('now')),
    explanation          TEXT,
    version              INTEGER NOT NULL DEFAULT 1,
    UNIQUE(asset_id, assertion_type)
);
CREATE INDEX IF NOT EXISTS idx_asset_assert_asset ON asset_assertions(asset_id, assertion_type);

CREATE TABLE IF NOT EXISTS assertion_sources (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    assertion_id         INTEGER NOT NULL REFERENCES asset_assertions(id) ON DELETE CASCADE,
    observation_id       INTEGER NOT NULL REFERENCES asset_observations(id) ON DELETE CASCADE,
    source_id            INTEGER NOT NULL REFERENCES recon_sources(id),
    contribution         TEXT NOT NULL DEFAULT 'corroborates',
        -- primary | corroborates | conflicting (reserved)
    weight_note          TEXT
);
CREATE INDEX IF NOT EXISTS idx_assertion_src_assert ON assertion_sources(assertion_id);
CREATE INDEX IF NOT EXISTS idx_assertion_src_obs ON assertion_sources(observation_id);

CREATE TABLE IF NOT EXISTS reconciliation_runs (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    finished_at          DATETIME NOT NULL DEFAULT (datetime('now')),
    entity_type          TEXT NOT NULL DEFAULT 'asset',
    entity_id            INTEGER NOT NULL,
    slice_key            TEXT NOT NULL,
        -- e.g. os_platform
    status               TEXT NOT NULL DEFAULT 'ok',
        -- ok | skipped | error
    result_summary_json  TEXT,
    error                TEXT
);
CREATE INDEX IF NOT EXISTS idx_recon_runs_entity ON reconciliation_runs(entity_type, entity_id, slice_key, finished_at DESC);

-- -------------------------------------------------------
-- Normalized software inventory (credentialed package inventory → durable state)
-- Join vulnerability_advisory_packages + asset_vulnerabilities for CVE-style correlation (see docs/TRUSTED_DATA_MODEL.md).
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS software_inventory (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem            TEXT NOT NULL,
        -- dpkg | rpm | generic | (future: pip, npm, …)
    canonical_name       TEXT NOT NULL,
    normalized_name      TEXT NOT NULL,
    source_package_name  TEXT,
    vendor               TEXT,
    created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at           DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_software_inventory_eco_norm ON software_inventory(ecosystem, normalized_name);
CREATE INDEX IF NOT EXISTS idx_software_inventory_eco_norm ON software_inventory(ecosystem, normalized_name);

CREATE TABLE IF NOT EXISTS software_inventory_versions (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    software_inventory_id   INTEGER NOT NULL REFERENCES software_inventory(id) ON DELETE CASCADE,
    version_raw             TEXT NOT NULL,
    version_normalized      TEXT,
    architecture            TEXT,
    distro_release            TEXT,
    package_release           TEXT,
    epoch                     TEXT,
    created_at                DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_software_inventory_versions_key
    ON software_inventory_versions(software_inventory_id, version_raw, IFNULL(architecture, ''));

CREATE TABLE IF NOT EXISTS software_inventory_asset_state (
    id                           INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id                     INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    software_inventory_version_id INTEGER NOT NULL REFERENCES software_inventory_versions(id) ON DELETE CASCADE,
    first_seen_at                DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen_at                 DATETIME NOT NULL DEFAULT (datetime('now')),
    source                       TEXT NOT NULL DEFAULT 'credentialed_check',
    credential_check_run_id      INTEGER,
    active                       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_sinv_asset_state_asset ON software_inventory_asset_state(asset_id, active, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_sinv_asset_state_version ON software_inventory_asset_state(software_inventory_version_id);
CREATE INDEX IF NOT EXISTS idx_sinv_asset_state_last_seen ON software_inventory_asset_state(last_seen_at DESC);

-- -------------------------------------------------------
-- Vulnerability advisories + inventory correlation (bounded local ingestion; no live NVD mirror here)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerability_advisories (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_key   TEXT NOT NULL,
        -- e.g. CVE-2024-1234 or distro-local key; unique canonical string
    source         TEXT NOT NULL,
        -- nvd | ubuntu | debian | redhat | alpine | internal | sample
    severity       TEXT NOT NULL DEFAULT 'unknown',
        -- critical | high | medium | low | info | unknown
    cvss_score     REAL,
    description    TEXT,
    published_at   DATETIME,
    modified_at    DATETIME,
    withdrawn      INTEGER NOT NULL DEFAULT 0,
    created_at     DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at     DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_vulnerability_advisories_key ON vulnerability_advisories(advisory_key);
CREATE INDEX IF NOT EXISTS idx_vulnerability_advisories_severity ON vulnerability_advisories(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerability_advisories_modified ON vulnerability_advisories(modified_at DESC);

CREATE TABLE IF NOT EXISTS vulnerability_advisory_packages (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id        INTEGER NOT NULL REFERENCES vulnerability_advisories(id) ON DELETE CASCADE,
    ecosystem          TEXT NOT NULL,
        -- dpkg | rpm | generic
    normalized_name    TEXT NOT NULL,
    version_operator   TEXT NOT NULL,
        -- = | < | <= | > | >= (interpreted vs installed version string for ecosystem)
    version_value      TEXT NOT NULL,
    distro_release     TEXT,
    architecture       TEXT,
    fixed_version      TEXT,
    metadata_json      TEXT,
    created_at         DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_vuln_adv_pkg_advisory ON vulnerability_advisory_packages(advisory_id);
CREATE INDEX IF NOT EXISTS idx_vuln_adv_pkg_eco_name ON vulnerability_advisory_packages(ecosystem, normalized_name);

CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
    id                              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id                        INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    software_inventory_asset_state_id INTEGER NOT NULL REFERENCES software_inventory_asset_state(id) ON DELETE CASCADE,
    advisory_id                     INTEGER NOT NULL REFERENCES vulnerability_advisories(id) ON DELETE CASCADE,
    status                          TEXT NOT NULL DEFAULT 'affected',
        -- affected | fixed | ignored
    first_seen_at                   DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen_at                    DATETIME NOT NULL DEFAULT (datetime('now')),
    detection_source                TEXT NOT NULL DEFAULT 'inventory_correlation',
    correlation_confidence          TEXT NOT NULL DEFAULT 'medium',
        -- high | medium | low
    fixed_detected_at               DATETIME,
    explain_json                    TEXT,
    created_at                      DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at                      DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(asset_id, advisory_id, software_inventory_asset_state_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_vuln_asset ON asset_vulnerabilities(asset_id, status);
CREATE INDEX IF NOT EXISTS idx_asset_vuln_advisory ON asset_vulnerabilities(advisory_id, status);
CREATE INDEX IF NOT EXISTS idx_asset_vuln_status ON asset_vulnerabilities(status, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS vulnerability_correlation_runs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at         DATETIME NOT NULL DEFAULT (datetime('now')),
    finished_at        DATETIME,
    mode               TEXT NOT NULL DEFAULT 'batch',
        -- batch | asset | jobs
    assets_processed   INTEGER NOT NULL DEFAULT 0,
    rules_evaluated    INTEGER NOT NULL DEFAULT 0,
    rows_matched       INTEGER NOT NULL DEFAULT 0,
    rows_upserted      INTEGER NOT NULL DEFAULT 0,
    rows_marked_fixed  INTEGER NOT NULL DEFAULT 0,
    duration_ms        INTEGER,
    status             TEXT NOT NULL DEFAULT 'ok',
        -- ok | partial | error
    error_safe         TEXT
);
CREATE INDEX IF NOT EXISTS idx_vuln_corr_runs_finished ON vulnerability_correlation_runs(finished_at DESC);

-- -------------------------------------------------------
-- Vulnerability triage / analyst workflow (bounded; audit trail; no hard deletes)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_vulnerability_triage (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_vulnerability_id  INTEGER NOT NULL UNIQUE REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
    triage_state            TEXT NOT NULL DEFAULT 'new',
        -- new | investigating | confirmed | mitigated | false_positive | accepted_risk
    priority                TEXT NOT NULL DEFAULT 'medium',
        -- critical | high | medium | low | info
    assigned_to             TEXT,
    due_at                  DATETIME,
    first_triaged_at        DATETIME,
    last_triaged_at         DATETIME,
    last_changed_by         TEXT,
    suppression_reason      TEXT,
    suppression_expires_at  DATETIME,
    notes_count             INTEGER NOT NULL DEFAULT 0,
    created_at              DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at              DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_av_triage_state ON asset_vulnerability_triage(triage_state);
CREATE INDEX IF NOT EXISTS idx_av_triage_priority ON asset_vulnerability_triage(priority);
CREATE INDEX IF NOT EXISTS idx_av_triage_assigned ON asset_vulnerability_triage(assigned_to);
CREATE INDEX IF NOT EXISTS idx_av_triage_due ON asset_vulnerability_triage(due_at);

CREATE TABLE IF NOT EXISTS vulnerability_notes (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_vulnerability_id  INTEGER NOT NULL REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
    author                  TEXT NOT NULL,
    note_text               TEXT NOT NULL,
    created_at              DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_vuln_notes_av ON vulnerability_notes(asset_vulnerability_id, created_at DESC);

CREATE TABLE IF NOT EXISTS vulnerability_activity_log (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_vulnerability_id  INTEGER NOT NULL REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
    action                  TEXT NOT NULL,
    actor                   TEXT NOT NULL,
    details_json            TEXT,
    created_at              DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_vuln_act_av ON vulnerability_activity_log(asset_vulnerability_id, created_at DESC);

-- -------------------------------------------------------
-- Worker execution substrate (MVP slice 1 — schema only; no runtime wiring yet)
-- See docs/WORKER_EXECUTION_SUBSTRATE.md and docs/WORKER_EXECUTION_MVP_PLAN.md
-- Logical refs: lease_node_id / node_id → worker_nodes.id (not enforced as FK)
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS worker_nodes (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    node_key             TEXT NOT NULL,
    hostname             TEXT,
    role                 TEXT,
    status               TEXT NOT NULL DEFAULT 'starting',
        -- starting | healthy | stale | degraded | error | stopped
    meta_json            TEXT,
    created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(node_key)
);
CREATE INDEX IF NOT EXISTS idx_worker_nodes_status ON worker_nodes(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_worker_nodes_role ON worker_nodes(role, status);

CREATE TABLE IF NOT EXISTS worker_jobs (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type             TEXT NOT NULL,
    entity_type          TEXT,
    entity_id            INTEGER,
    status               TEXT NOT NULL DEFAULT 'queued',
        -- queued | leased | running | retrying | completed | failed | cancelled | expired
    priority             INTEGER NOT NULL DEFAULT 0,
    lease_node_id        INTEGER,
    lease_token          TEXT,
    leased_at            DATETIME,
    lease_expires_at     DATETIME,
    attempts             INTEGER NOT NULL DEFAULT 0,
    max_attempts         INTEGER NOT NULL DEFAULT 3,
    next_attempt_at      DATETIME,
    cancel_requested_at  DATETIME,
    error_code           TEXT,
    error_message        TEXT,
    payload_json         TEXT,
    result_summary_json  TEXT,
    created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    finished_at          DATETIME
);
CREATE INDEX IF NOT EXISTS idx_worker_jobs_status_next ON worker_jobs(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_worker_jobs_type_status ON worker_jobs(job_type, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_worker_jobs_lease_exp ON worker_jobs(lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_worker_jobs_created ON worker_jobs(created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_worker_jobs_collector_mirror_entity ON worker_jobs(job_type, entity_type, entity_id)
    WHERE job_type = 'collector_ingest' AND entity_type = 'collector_submission';

CREATE TABLE IF NOT EXISTS worker_job_attempts (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id               INTEGER NOT NULL,
    attempt_no           INTEGER NOT NULL,
    node_id              INTEGER,
    status               TEXT NOT NULL,
    started_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    finished_at          DATETIME,
    error_code           TEXT,
    error_message        TEXT,
    metrics_json         TEXT,
    UNIQUE(job_id, attempt_no)
);
CREATE INDEX IF NOT EXISTS idx_worker_job_attempts_job ON worker_job_attempts(job_id, attempt_no DESC);
CREATE INDEX IF NOT EXISTS idx_worker_job_attempts_node ON worker_job_attempts(node_id, started_at DESC);

CREATE TABLE IF NOT EXISTS worker_job_events (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id               INTEGER NOT NULL,
    attempt_id           INTEGER,
    event_type           TEXT NOT NULL,
    level                TEXT NOT NULL DEFAULT 'info',
    message              TEXT,
    details_json         TEXT,
    created_at           DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_worker_job_events_job ON worker_job_events(job_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_worker_job_events_type ON worker_job_events(event_type, created_at DESC);

CREATE TABLE IF NOT EXISTS worker_heartbeats (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id              INTEGER NOT NULL,
    worker_key           TEXT,
    worker_type          TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'healthy',
    heartbeat_at         DATETIME NOT NULL DEFAULT (datetime('now')),
    details_json         TEXT
);
CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_node ON worker_heartbeats(node_id, heartbeat_at DESC);
CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_type ON worker_heartbeats(worker_type, heartbeat_at DESC);

-- -------------------------------------------------------
-- Credentialed checks engine (MVP slice 1 — schema only; no execution yet)
-- See docs/CREDENTIALED_CHECKS_ENGINE.md and docs/CREDENTIALED_CHECKS_MVP_PLAN.md
-- Migration marker: migration_credentialed_checks_v1 (api/db.php)
-- Logical refs to users.id / worker_jobs.id / assets.id — not enforced as FK
-- -------------------------------------------------------
CREATE TABLE IF NOT EXISTS credential_profiles (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT NOT NULL,
    transport            TEXT NOT NULL,
        -- ssh | winrm | snmpv3 (app-level)
    principal_json       TEXT,
    secret_ciphertext    TEXT,
    scope_json           TEXT,
    enabled              INTEGER NOT NULL DEFAULT 1,
    created_by           INTEGER,
    created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    last_test_at             DATETIME,
    last_test_status         TEXT,
        -- ok | failed (app-level)
    last_test_error_code     TEXT,
    last_test_duration_ms    INTEGER,
    deleted_at               DATETIME
        -- soft-archive; NULL = active
);
CREATE INDEX IF NOT EXISTS idx_credential_profiles_transport ON credential_profiles(transport, enabled);
CREATE INDEX IF NOT EXISTS idx_credential_profiles_created ON credential_profiles(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_credential_profiles_deleted ON credential_profiles(deleted_at);

CREATE TABLE IF NOT EXISTS credential_check_plugins (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_key           TEXT NOT NULL,
    version              TEXT NOT NULL,
    transport            TEXT NOT NULL,
    manifest_json        TEXT NOT NULL,
    state                TEXT NOT NULL DEFAULT 'stable',
        -- disabled | stable | experimental
    created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(plugin_key, version)
);
CREATE INDEX IF NOT EXISTS idx_cred_check_plugins_key ON credential_check_plugins(plugin_key);
CREATE INDEX IF NOT EXISTS idx_cred_check_plugins_transport_state ON credential_check_plugins(transport, state);

CREATE TABLE IF NOT EXISTS credential_check_jobs (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    name                       TEXT NOT NULL,
    description                TEXT,
    credential_profile_id      INTEGER NOT NULL,
    target_mode                TEXT NOT NULL,
        -- assets | scope | device
    target_json                TEXT,
    plugin_selection_json      TEXT,
    policy_json                TEXT,
    schedule_cron              TEXT,
    schedule_enabled           INTEGER NOT NULL DEFAULT 0,
    schedule_timezone          TEXT NOT NULL DEFAULT 'UTC',
    schedule_last_run_at       TEXT,
    schedule_next_run_at       TEXT,
    schedule_last_error        TEXT,
    max_concurrency            INTEGER NOT NULL DEFAULT 1,
    run_timeout_sec            INTEGER NOT NULL DEFAULT 3600,
    enabled                    INTEGER NOT NULL DEFAULT 1,
    created_by                 INTEGER,
    created_at                 DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at                 DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cred_check_jobs_profile ON credential_check_jobs(credential_profile_id, enabled);
CREATE INDEX IF NOT EXISTS idx_cred_check_jobs_enabled ON credential_check_jobs(enabled, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_cred_check_jobs_schedule_due ON credential_check_jobs(enabled, schedule_enabled, schedule_next_run_at);

CREATE TABLE IF NOT EXISTS credential_check_runs (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id               INTEGER,
    worker_job_id        INTEGER,
    started_at           DATETIME NOT NULL DEFAULT (datetime('now')),
    finished_at          DATETIME,
    status               TEXT NOT NULL DEFAULT 'queued',
        -- queued | resolving_targets | ready | running | completed | failed | cancelled
    initiated_by         TEXT,
    launch_source        TEXT NOT NULL DEFAULT 'manual',
        -- manual | scheduled
    summary_json         TEXT
);
CREATE INDEX IF NOT EXISTS idx_cred_check_runs_job ON credential_check_runs(job_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_cred_check_runs_status ON credential_check_runs(status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_cred_check_runs_worker_job ON credential_check_runs(worker_job_id);

CREATE TABLE IF NOT EXISTS credential_check_run_targets (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id               INTEGER NOT NULL,
    asset_id             INTEGER NOT NULL,
    status               TEXT NOT NULL DEFAULT 'pending',
        -- pending | skipped | completed | failed (slice 6 placeholder uses skipped + error_code)
    error_code           TEXT,
    error_message_safe   TEXT,
    started_at           DATETIME,
    finished_at          DATETIME
);
CREATE INDEX IF NOT EXISTS idx_cred_check_run_targets_run ON credential_check_run_targets(run_id, status);
CREATE INDEX IF NOT EXISTS idx_cred_check_run_targets_asset_started ON credential_check_run_targets(asset_id, started_at DESC);

CREATE TABLE IF NOT EXISTS credential_check_results (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id               INTEGER NOT NULL,
    target_id            INTEGER,
    asset_id             INTEGER NOT NULL,
    plugin_key           TEXT NOT NULL,
    plugin_version       TEXT NOT NULL,
    status               TEXT NOT NULL,
        -- success | partial | failed
    normalized_json      TEXT,
    metrics_json         TEXT,
    created_at           DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cred_check_results_run ON credential_check_results(run_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cred_check_results_target ON credential_check_results(target_id);
CREATE INDEX IF NOT EXISTS idx_cred_check_results_asset_plugin ON credential_check_results(asset_id, plugin_key, created_at DESC);

CREATE TABLE IF NOT EXISTS credential_check_artifacts (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id            INTEGER NOT NULL,
    kind                 TEXT NOT NULL,
        -- stdout | stderr | snmp_capture | file_excerpt (app-level)
    storage_path         TEXT,
    "blob"               BLOB,
    sha256               TEXT,
    size_bytes           INTEGER,
    redaction_version    INTEGER NOT NULL DEFAULT 1,
    created_at           DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cred_check_artifacts_result ON credential_check_artifacts(result_id, created_at DESC);

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
    ('scan_trash_retention_days', '30'),
    ('session_timeout_minutes', '480'),  -- idle timeout + session cookie max-age (5–10080)
    ('extra_safe_ports', '');  -- comma-separated additional ports for routed fast_full_tcp safe scan
