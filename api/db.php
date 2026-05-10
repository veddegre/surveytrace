<?php
/**
 * SurveyTrace — core database + auth helper
 * Included by every API endpoint.
 */

// Always use UTC for all date/time operations regardless of server timezone
date_default_timezone_set('UTC');

require_once __DIR__ . '/st_version.php';
define('ST_DB_PATH',  dirname(__DIR__) . '/data/surveytrace.db');
define('ST_SCHEMA',   dirname(__DIR__) . '/sql/schema.sql');
define('ST_DATA_DIR', dirname(__DIR__) . '/data');

/**
 * Runtime PRAGMAs for surveytrace.db — keep in sync with daemon/sqlite_pragmas.py.
 * WAL mode writes companion files beside the DB (surveytrace.db-wal, surveytrace.db-shm); the parent
 * directory (ST_DATA_DIR) must be writable by the PHP process, not only the main .db file.
 * Env: SURVEYTRACE_SQLITE_BUSY_TIMEOUT_MS (1000–600000, default 60000),
 *      SURVEYTRACE_SQLITE_MMAP_BYTES (set 0 to disable mmap; default 67108864).
 */
function st_sqlite_runtime_pragmas(PDO $pdo): void {
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA foreign_keys = ON');
    $busy = (int)(getenv('SURVEYTRACE_SQLITE_BUSY_TIMEOUT_MS') ?: 60000);
    if ($busy < 1000) {
        $busy = 1000;
    }
    if ($busy > 600000) {
        $busy = 600000;
    }
    $pdo->exec('PRAGMA busy_timeout = ' . $busy);
    $pdo->exec('PRAGMA synchronous = NORMAL');
    $pdo->exec('PRAGMA temp_store = MEMORY');
    $mmap = trim((string)(getenv('SURVEYTRACE_SQLITE_MMAP_BYTES') ?: '67108864'));
    if ($mmap !== '' && $mmap !== '0' && ctype_digit($mmap)) {
        $pdo->exec('PRAGMA mmap_size = ' . (int)$mmap);
    }
}

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
        @error_log('SurveyTrace DB unavailable: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string)$e->getMessage()));
        st_json(['error' => 'Database unavailable'], 503);
    }

    st_sqlite_runtime_pragmas($pdo);

    // Heavy ALTER/CREATE bootstrap runs once per PHP worker per deployed api/db.php revision (file mtime),
    // not on every new PDO. Otherwise reconnecting during long AI calls replays hundreds of exec()s and
    // locks SQLite. Mtime invalidation avoids long-lived php-fpm workers skipping new migrations after deploy
    // (symptom: 503 "Credential profiles schema not available" until manual php-fpm restart).
    static $st_db_migration_cache_mtime = null;
    $dbPhpMtime = @filemtime(__FILE__) ?: 0;
    if ($st_db_migration_cache_mtime === $dbPhpMtime) {
        $GLOBALS['st_surveytrace_pdo'] = $pdo;
        return $pdo;
    }

    // Many workers opening the DB at once (deploy, Apache restart) otherwise replay migrations in parallel
    // and hammer SQLite with overlapping writes ("database is locked"). Serialize bootstrap across processes.
    $bootstrapLockFh = @fopen($dir . '/.surveytrace_bootstrap.lock', 'c');
    if ($bootstrapLockFh !== false) {
        flock($bootstrapLockFh, LOCK_EX);
    }
    try {
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
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_operator_ollama_timeout_s', '900')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_operator_ollama_num_predict', '768')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_operator_ollama_temperature', '0.25')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_operator_prompt_banner_max_lines', '72')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_operator_prompt_banner_val_max', '96')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_operator_prompt_banner_max_chars', '8000')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_operator_ollama_num_thread', '0')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_operator_ollama_num_ctx', '0')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_openwebui_base_url', '')"
    );
    $pdo->exec(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('ai_openwebui_api_key', '')"
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
    foreach ([
        ['collector_install_token', ''],
        ['collector_token_ttl_hours', '720'],
        ['collector_lease_seconds', '600'],
        ['collector_rate_default_rps', '5'],
        ['collector_submit_max_mb', '8'],
        ['collector_artifact_store', 's3'],
        ['collector_artifact_s3_endpoint', ''],
        ['collector_artifact_s3_bucket', ''],
        ['collector_artifact_s3_region', 'us-east-1'],
        ['collector_artifact_s3_access_key', ''],
        ['collector_artifact_s3_secret_key', ''],
        ['collector_artifact_s3_prefix', 'surveytrace/collector-artifacts'],
        ['collector_artifact_s3_path_style', '1'],
        ['collector_artifact_s3_tls_verify', '1'],
    ] as $kv) {
        $pdo->prepare("INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)")->execute($kv);
    }

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
        "ALTER TABLE scan_jobs ADD COLUMN collector_id INTEGER DEFAULT 0",
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
    st_migrate_phase9_change_detection_v1($pdo);
    st_migrate_phase10_finding_triage_v1($pdo);
    st_migrate_phase11_cve_intel_v1($pdo);
    st_migrate_phase12_asset_lifecycle_v1($pdo);
    st_migrate_asset_metadata_locks_v1($pdo);
    st_migrate_phase13_reporting_v1($pdo);
    st_migrate_phase14_scan_scopes_v1($pdo);
    st_migrate_phase14_1_integrations_v1($pdo);
    st_migrate_phase14_1_integrations_per_pull_token_v1($pdo);
    st_migrate_phase16_remove_legacy_integrations_pull_token_v1($pdo);
    st_migrate_phase16_zabbix_source_v1($pdo);
    st_migrate_phase16_2_zabbix_workflow_v1($pdo);
    st_migrate_reconciliation_trusted_data_v1($pdo);
    st_migrate_reconciliation_identity_m1_slice4_v1($pdo);
    st_migrate_worker_execution_substrate_v1($pdo);
    st_migrate_worker_jobs_collector_mirror_unique_v1($pdo);
    st_migrate_credentialed_checks_v1($pdo);
    st_migrate_cred_profiles_deleted_at_v1($pdo);
    st_migrate_cred_profile_test_columns_v1($pdo);
    st_migrate_cred_check_job_schedule_v1($pdo);
    st_migrate_software_inventory_normalized_v1($pdo);
    st_migrate_vulnerability_correlation_v1($pdo);
    st_migrate_vulnerability_triage_v1($pdo);
    st_migrate_vulnerability_triage_priority_source_v1($pdo);

    require_once __DIR__ . '/lib_credentialed_checks.php';
    if (st_cred_tables_ready($pdo)) {
        st_cred_seed_builtin_plugins($pdo);
    }

    $st_db_migration_cache_mtime = $dbPhpMtime;
    } finally {
        if ($bootstrapLockFh !== false) {
            flock($bootstrapLockFh, LOCK_UN);
            fclose($bootstrapLockFh);
        }
    }

    $GLOBALS['st_surveytrace_pdo'] = $pdo;
    return $pdo;
}

/**
 * Drop the shared PDO so another connection can write during long local I/O in the same request.
 * The next st_db() opens a new PDO (PRAGMAs only — migrations skipped until api/db.php is replaced).
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

/** Deprecated profile `fast_full_tcp` is remapped to `full_tcp` everywhere (API + DB cleanup). */
function st_normalize_scan_profile(string $profile): string {
    return $profile === 'fast_full_tcp' ? 'full_tcp' : $profile;
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

/**
 * Change detection — finding lifecycle columns + change_alerts table + backfill mitigated from legacy resolved=1.
 */
function st_migrate_phase9_change_detection_v1(PDO $pdo): void {
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase9_change_detection_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    if (!is_array($tables) || !in_array('findings', $tables, true)) {
        return;
    }
    $fCols = array_column($pdo->query('PRAGMA table_info(findings)')->fetchAll(), 'name');
    foreach ([
        "ALTER TABLE findings ADD COLUMN lifecycle_state TEXT DEFAULT 'active'",
        'ALTER TABLE findings ADD COLUMN mitigated_at DATETIME',
        'ALTER TABLE findings ADD COLUMN accepted_at DATETIME',
        'ALTER TABLE findings ADD COLUMN accepted_by_user_id INTEGER',
        'ALTER TABLE findings ADD COLUMN first_seen_job_id INTEGER',
        'ALTER TABLE findings ADD COLUMN last_seen_job_id INTEGER',
    ] as $sql) {
        try {
            $pdo->exec($sql);
        } catch (Throwable $e) {
            // column may already exist
        }
    }
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_findings_lifecycle ON findings(lifecycle_state, resolved)');
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS change_alerts (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type            TEXT NOT NULL,
            job_id                INTEGER,
            asset_id              INTEGER,
            finding_id            INTEGER,
            detail_json           TEXT,
            dismissed_at          DATETIME,
            dismissed_by_user_id  INTEGER
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_change_alerts_created ON change_alerts(created_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_change_alerts_open ON change_alerts(dismissed_at, created_at DESC)');
    try {
        $pdo->exec(
            "UPDATE findings SET lifecycle_state='mitigated', mitigated_at=COALESCE(mitigated_at, datetime('now'))
             WHERE resolved=1 AND COALESCE(lifecycle_state,'active')='active'"
        );
    } catch (Throwable $e) {
        // ignore if lifecycle_state missing in very old builds (should not happen after ALTER)
    }
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase9_change_detection_v1', '1')"
    );
}

/**
 * Finding triage — per-finding provenance, detection method, confidence, risk score, evidence JSON.
 */
function st_migrate_phase10_finding_triage_v1(PDO $pdo): void {
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase10_finding_triage_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    if (!is_array($tables) || !in_array('findings', $tables, true)) {
        return;
    }
    foreach ([
        "ALTER TABLE findings ADD COLUMN provenance_source TEXT DEFAULT 'unknown'",
        'ALTER TABLE findings ADD COLUMN detection_method TEXT',
        "ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'low'",
        'ALTER TABLE findings ADD COLUMN risk_score REAL',
        'ALTER TABLE findings ADD COLUMN evidence_json TEXT',
    ] as $sql) {
        try {
            $pdo->exec($sql);
        } catch (Throwable $e) {
            // column may already exist
        }
    }
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings(risk_score DESC)');
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase10_finding_triage_v1', '1')"
    );
}

/**
 * CVE intelligence — KEV/EPSS/OSV joins (CISA KEV, FIRST EPSS, OSV ecosystems); populated by sync_cve_intel.py.
 */
function st_migrate_phase11_cve_intel_v1(PDO $pdo): void {
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase11_cve_intel_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS cve_intel (
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
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cve_intel_kev ON cve_intel(kev)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cve_intel_epss ON cve_intel(epss DESC)');
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase11_cve_intel_v1', '1')"
    );
}

/**
 * Asset lifecycle — coverage-based stale/retire + operator metadata columns.
 */
function st_migrate_phase12_asset_lifecycle_v1(PDO $pdo): void {
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase12_asset_lifecycle_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    if (!is_array($tables) || !in_array('assets', $tables, true)) {
        return;
    }
    foreach ([
        "ALTER TABLE assets ADD COLUMN lifecycle_status TEXT DEFAULT 'active'",
        'ALTER TABLE assets ADD COLUMN lifecycle_reason TEXT',
        'ALTER TABLE assets ADD COLUMN last_expected_scan_id INTEGER',
        'ALTER TABLE assets ADD COLUMN last_expected_scan_at DATETIME',
        'ALTER TABLE assets ADD COLUMN last_missed_scan_id INTEGER',
        'ALTER TABLE assets ADD COLUMN last_missed_scan_at DATETIME',
        'ALTER TABLE assets ADD COLUMN missed_scan_count INTEGER DEFAULT 0',
        'ALTER TABLE assets ADD COLUMN retired_at DATETIME',
        'ALTER TABLE assets ADD COLUMN owner TEXT',
        'ALTER TABLE assets ADD COLUMN business_unit TEXT',
        "ALTER TABLE assets ADD COLUMN criticality TEXT DEFAULT 'medium'",
        "ALTER TABLE assets ADD COLUMN environment TEXT DEFAULT 'unknown'",
        'ALTER TABLE assets ADD COLUMN identity_confidence REAL',
        'ALTER TABLE assets ADD COLUMN identity_confidence_reason TEXT',
    ] as $sql) {
        try {
            $pdo->exec($sql);
        } catch (Throwable $e) {
            // column may already exist
        }
    }
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_assets_lifecycle_status ON assets(lifecycle_status)');
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase12_asset_lifecycle_v1', '1')"
    );
}

/**
 * Asset hostname/category/vendor locks — preserve operator edits across scans.
 */
function st_migrate_asset_metadata_locks_v1(PDO $pdo): void {
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_asset_metadata_locks_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    if (!is_array($tables) || !in_array('assets', $tables, true)) {
        return;
    }
    foreach ([
        'ALTER TABLE assets ADD COLUMN hostname_locked INTEGER DEFAULT 0',
        'ALTER TABLE assets ADD COLUMN category_locked INTEGER DEFAULT 0',
        'ALTER TABLE assets ADD COLUMN vendor_locked INTEGER DEFAULT 0',
    ] as $sql) {
        try {
            $pdo->exec($sql);
        } catch (Throwable $e) {
            // column may already exist
        }
    }
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_asset_metadata_locks_v1', '1')"
    );
}

/**
 * Reporting — baselines, report artifacts, schedule_action for report-only schedules.
 */
function st_migrate_phase13_reporting_v1(PDO $pdo): void {
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase13_reporting_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    if (!is_array($tables)) {
        return;
    }
    if (in_array('scan_jobs', $tables, true)) {
        try {
            $pdo->exec('ALTER TABLE scan_jobs ADD COLUMN is_baseline INTEGER DEFAULT 0');
        } catch (Throwable $e) {
            // column may already exist
        }
    }
    if (in_array('scan_schedules', $tables, true)) {
        try {
            $pdo->exec("ALTER TABLE scan_schedules ADD COLUMN schedule_action TEXT DEFAULT 'scan'");
        } catch (Throwable $e) {
            // column may already exist
        }
    }
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS report_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            schedule_id INTEGER,
            baseline_job_id INTEGER,
            compare_job_id INTEGER,
            kind TEXT DEFAULT 'scheduled',
            title TEXT,
            payload_json TEXT NOT NULL DEFAULT '{}'
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_report_artifacts_created ON report_artifacts(created_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_report_artifacts_schedule ON report_artifacts(schedule_id, id DESC)');
    $pdo->exec("INSERT OR IGNORE INTO config (key, value) VALUES ('phase13_baseline_job_id', '')");
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase13_reporting_v1', '1')"
    );
}

/**
 * Scan scopes — multi-network reporting boundaries + scoped baselines.
 */
function st_migrate_phase14_scan_scopes_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase14_scan_scopes_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS scan_scopes (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            description   TEXT,
            scope_type    TEXT DEFAULT \'network\',
            cidrs         TEXT DEFAULT \'[]\',
            tags          TEXT DEFAULT \'[]\',
            owner         TEXT,
            environment   TEXT DEFAULT \'unknown\',
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_scan_scopes_name ON scan_scopes(name)');
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS scan_scope_baselines (
            scope_id         INTEGER PRIMARY KEY REFERENCES scan_scopes(id) ON DELETE CASCADE,
            baseline_job_id  INTEGER NOT NULL,
            updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
        )'
    );
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    if (is_array($tables) && in_array('scan_jobs', $tables, true)) {
        try {
            $pdo->exec('ALTER TABLE scan_jobs ADD COLUMN scope_id INTEGER');
        } catch (Throwable $e) {
            // column may already exist
        }
        try {
            $pdo->exec(
                'CREATE INDEX IF NOT EXISTS idx_scan_jobs_scope_status_finished ON scan_jobs(scope_id, status, finished_at DESC)'
            );
        } catch (Throwable $e) {
        }
    }
    if (is_array($tables) && in_array('scan_schedules', $tables, true)) {
        try {
            $pdo->exec('ALTER TABLE scan_schedules ADD COLUMN scope_id INTEGER');
        } catch (Throwable $e) {
        }
    }
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase14_scan_scopes_v1', '1')"
    );
}

/**
 * Integrations foundation — integration rows (initial schema; pull token storage evolved in follow-on migration).
 */
function st_migrate_phase14_1_integrations_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase14_1_integrations_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS integrations (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            name           TEXT NOT NULL,
            type           TEXT NOT NULL,
            enabled        INTEGER NOT NULL DEFAULT 1,
            endpoint_url   TEXT NOT NULL DEFAULT \'\',
            host           TEXT NOT NULL DEFAULT \'\',
            port           INTEGER,
            auth_secret    TEXT,
            extra_json     TEXT NOT NULL DEFAULT \'{}\',
            created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_test_at   DATETIME,
            last_test_status TEXT,
            last_error     TEXT
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations(type)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_integrations_enabled ON integrations(enabled)');
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase14_1_integrations_v1', '1')"
    );
}

/**
 * Idempotent: add pull-token columns on `integrations` if the table exists and any column is missing.
 * Safe to call on every bootstrap (repairs installs where the migration row was recorded before the table existed).
 */
function st_integrations_ensure_pull_token_columns(PDO $pdo): void
{
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='integrations'")->fetchAll(PDO::FETCH_COLUMN);
    if (! is_array($tables) || ! in_array('integrations', $tables, true)) {
        return;
    }
    $cols = array_column($pdo->query('PRAGMA table_info(integrations)')->fetchAll(PDO::FETCH_ASSOC), 'name');
    $addCol = static function (string $name, string $ddl) use ($pdo, &$cols): void {
        if (in_array($name, $cols, true)) {
            return;
        }
        try {
            $pdo->exec($ddl);
        } catch (Throwable $e) {
            // concurrent migration
        }
        $cols[] = $name;
    };
    $addCol('token_hash', 'ALTER TABLE integrations ADD COLUMN token_hash TEXT');
    $addCol('token_created_at', 'ALTER TABLE integrations ADD COLUMN token_created_at TEXT');
    $addCol('token_last_used_at', 'ALTER TABLE integrations ADD COLUMN token_last_used_at TEXT');
    $addCol('token_last_used_ip', 'ALTER TABLE integrations ADD COLUMN token_last_used_ip TEXT');
}

/** True when `integrations` exists and all per-pull-token columns are present. */
function st_integrations_pull_token_schema_ready(PDO $pdo): bool
{
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='integrations'")->fetchAll(PDO::FETCH_COLUMN);
    if (! is_array($tables) || ! in_array('integrations', $tables, true)) {
        return false;
    }
    $cols = array_column($pdo->query('PRAGMA table_info(integrations)')->fetchAll(PDO::FETCH_ASSOC), 'name');
    foreach (['token_hash', 'token_created_at', 'token_last_used_at', 'token_last_used_ip'] as $need) {
        if (! in_array($need, $cols, true)) {
            return false;
        }
    }

    return true;
}

/**
 * Per-integration pull token hashes (Prometheus / events / report summary consumers).
 * Idempotent column adds on `integrations`.
 */
function st_migrate_phase14_1_integrations_per_pull_token_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase14_1_integrations_per_pull_token_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        st_integrations_ensure_pull_token_columns($pdo);

        return;
    }
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='integrations'")->fetchAll(PDO::FETCH_COLUMN);
    if (! is_array($tables) || ! in_array('integrations', $tables, true)) {
        $pdo->exec(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase14_1_integrations_per_pull_token_v1', '1')"
        );

        return;
    }
    st_integrations_ensure_pull_token_columns($pdo);
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase14_1_integrations_per_pull_token_v1', '1')"
    );
}

/**
 * Remove unused legacy global pull token hash from config (pull APIs use per-integration tokens only).
 */
function st_migrate_phase16_remove_legacy_integrations_pull_token_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase16_remove_legacy_integrations_pull_token_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $pdo->exec("DELETE FROM config WHERE key = 'integrations_pull_token_bcrypt'");
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase16_remove_legacy_integrations_pull_token_v1', '1')"
    );
}

/**
 * Zabbix source connector — hosts, interfaces, tags, problems summary, asset links, scope rules.
 */
function st_migrate_phase16_zabbix_source_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase16_zabbix_source_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    require_once __DIR__ . '/lib_zabbix.php';
    st_zabbix_ensure_schema($pdo);
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase16_zabbix_source_v1', '1')"
    );
}

/**
 * Zabbix workflow — asset scope_id + denormalized Zabbix trust fields; manual link flag on zabbix_asset_links.
 */
function st_migrate_phase16_2_zabbix_workflow_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_phase16_2_zabbix_workflow_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    require_once __DIR__ . '/lib_zabbix.php';
    st_zabbix_ensure_schema($pdo);
    $cols = $pdo->query('PRAGMA table_info(assets)')->fetchAll(PDO::FETCH_ASSOC);
    $names = [];
    foreach ($cols as $c) {
        if (isset($c['name'])) {
            $names[] = (string) $c['name'];
        }
    }
    if (! in_array('scope_id', $names, true)) {
        $pdo->exec('ALTER TABLE assets ADD COLUMN scope_id INTEGER');
    }
    if (! in_array('monitored_by_zabbix', $names, true)) {
        $pdo->exec('ALTER TABLE assets ADD COLUMN monitored_by_zabbix INTEGER NOT NULL DEFAULT 0');
    }
    if (! in_array('zabbix_availability', $names, true)) {
        $pdo->exec("ALTER TABLE assets ADD COLUMN zabbix_availability TEXT NOT NULL DEFAULT ''");
    }
    if (! in_array('zabbix_problem_count', $names, true)) {
        $pdo->exec('ALTER TABLE assets ADD COLUMN zabbix_problem_count INTEGER NOT NULL DEFAULT 0');
    }
    $lcols = $pdo->query('PRAGMA table_info(zabbix_asset_links)')->fetchAll(PDO::FETCH_ASSOC);
    $lnames = [];
    foreach ($lcols as $c) {
        if (isset($c['name'])) {
            $lnames[] = (string) $c['name'];
        }
    }
    if (! in_array('is_manual', $lnames, true)) {
        $pdo->exec('ALTER TABLE zabbix_asset_links ADD COLUMN is_manual INTEGER NOT NULL DEFAULT 0');
    }
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_phase16_2_zabbix_workflow_v1', '1')"
    );
}

/**
 * Trusted data model v1 — reconciliation primitives (observations, assertions, audit runs).
 */
function st_migrate_reconciliation_trusted_data_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_reconciliation_trusted_data_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS recon_sources (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_type          TEXT NOT NULL,
            source_instance_key  TEXT NOT NULL DEFAULT 'default',
            display_name         TEXT NOT NULL DEFAULT '',
            trust_level          TEXT NOT NULL DEFAULT 'medium',
            freshness_sec        INTEGER NOT NULL DEFAULT 86400,
            enabled              INTEGER NOT NULL DEFAULT 1,
            meta_json            TEXT,
            UNIQUE(source_type, source_instance_key)
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_recon_sources_type ON recon_sources(source_type, enabled)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS asset_observations (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
            asset_id             INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            observation_type     TEXT NOT NULL,
            raw_value            TEXT,
            normalized_value     TEXT,
            source_id            INTEGER NOT NULL REFERENCES recon_sources(id),
            source_object_ref    TEXT NOT NULL DEFAULT '',
            observed_at          DATETIME NOT NULL DEFAULT (datetime('now')),
            confidence_level     TEXT NOT NULL DEFAULT 'medium',
            provenance_json      TEXT,
            UNIQUE(asset_id, observation_type, source_id, source_object_ref)
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_asset_obs_asset ON asset_observations(asset_id, observation_type)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_asset_obs_seen ON asset_observations(observed_at DESC)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS asset_assertions (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
            asset_id             INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            assertion_type       TEXT NOT NULL,
            asserted_value       TEXT NOT NULL,
            confidence_level     TEXT NOT NULL DEFAULT 'medium',
            status               TEXT NOT NULL DEFAULT 'active',
            reconciled_at        DATETIME NOT NULL DEFAULT (datetime('now')),
            explanation          TEXT,
            version              INTEGER NOT NULL DEFAULT 1,
            UNIQUE(asset_id, assertion_type)
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_asset_assert_asset ON asset_assertions(asset_id, assertion_type)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS assertion_sources (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
            assertion_id         INTEGER NOT NULL REFERENCES asset_assertions(id) ON DELETE CASCADE,
            observation_id       INTEGER NOT NULL REFERENCES asset_observations(id) ON DELETE CASCADE,
            source_id            INTEGER NOT NULL REFERENCES recon_sources(id),
            contribution         TEXT NOT NULL DEFAULT 'corroborates',
            weight_note          TEXT
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_assertion_src_assert ON assertion_sources(assertion_id)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_assertion_src_obs ON assertion_sources(observation_id)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS reconciliation_runs (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at           DATETIME NOT NULL DEFAULT (datetime('now')),
            finished_at          DATETIME NOT NULL DEFAULT (datetime('now')),
            entity_type          TEXT NOT NULL DEFAULT 'asset',
            entity_id            INTEGER NOT NULL,
            slice_key            TEXT NOT NULL,
            status               TEXT NOT NULL DEFAULT 'ok',
            result_summary_json  TEXT,
            error                TEXT
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_recon_runs_entity ON reconciliation_runs(entity_type, entity_id, slice_key, finished_at DESC)');

    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_reconciliation_trusted_data_v1', '1')"
    );
}

/**
 * Milestone 1 slice 4 — identity observations + canonical_hostname assertion (no DDL; marker only).
 */
function st_migrate_reconciliation_identity_m1_slice4_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_reconciliation_identity_m1_slice4_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_reconciliation_identity_m1_slice4_v1', '1')"
    );
}

/**
 * Worker execution substrate (MVP slice 1) — additive queue / worker telemetry tables only.
 *
 * No runtime behavior: scanner, collector ingest, scheduler, and Zabbix workers are unchanged.
 * Logical refs: lease_node_id / node_id → worker_nodes.id (not enforced as SQLite FK for flexibility).
 *
 * @see docs/WORKER_EXECUTION_SUBSTRATE.md
 * @see docs/WORKER_EXECUTION_MVP_PLAN.md
 */
function st_migrate_worker_execution_substrate_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_worker_execution_substrate_v1'")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS worker_nodes (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            node_key            TEXT NOT NULL,
            hostname             TEXT,
            role                 TEXT,
            status               TEXT NOT NULL DEFAULT 'starting',
            meta_json            TEXT,
            created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
            updated_at           DATETIME NOT NULL DEFAULT (datetime('now')),
            UNIQUE(node_key)
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_nodes_status ON worker_nodes(status, updated_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_nodes_role ON worker_nodes(role, status)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS worker_jobs (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            job_type             TEXT NOT NULL,
            entity_type          TEXT,
            entity_id            INTEGER,
            status               TEXT NOT NULL DEFAULT 'queued',
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
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_jobs_status_next ON worker_jobs(status, next_attempt_at)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_jobs_type_status ON worker_jobs(job_type, status, created_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_jobs_lease_exp ON worker_jobs(lease_expires_at)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_jobs_created ON worker_jobs(created_at DESC)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS worker_job_attempts (
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
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_job_attempts_job ON worker_job_attempts(job_id, attempt_no DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_job_attempts_node ON worker_job_attempts(node_id, started_at DESC)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS worker_job_events (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id               INTEGER NOT NULL,
            attempt_id           INTEGER,
            event_type           TEXT NOT NULL,
            level                TEXT NOT NULL DEFAULT 'info',
            message              TEXT,
            details_json         TEXT,
            created_at           DATETIME NOT NULL DEFAULT (datetime('now'))
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_job_events_job ON worker_job_events(job_id, created_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_job_events_type ON worker_job_events(event_type, created_at DESC)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS worker_heartbeats (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id              INTEGER NOT NULL,
            worker_key           TEXT,
            worker_type          TEXT NOT NULL,
            status               TEXT NOT NULL DEFAULT 'healthy',
            heartbeat_at         DATETIME NOT NULL DEFAULT (datetime('now')),
            details_json         TEXT
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_node ON worker_heartbeats(node_id, heartbeat_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_type ON worker_heartbeats(worker_type, heartbeat_at DESC)');

    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_worker_execution_substrate_v1', '1')"
    );
}

/**
 * Partial unique index so collector ingest mirror jobs are idempotent per collector_submissions row.
 */
function st_migrate_worker_jobs_collector_mirror_unique_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_worker_jobs_collector_mirror_unique_v1' LIMIT 1")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $t = $pdo->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'worker_jobs' LIMIT 1")->fetchColumn();
    if ($t === false || $t === null) {
        return;
    }
    $pdo->exec(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_worker_jobs_collector_mirror_entity
         ON worker_jobs(job_type, entity_type, entity_id)
         WHERE job_type = 'collector_ingest' AND entity_type = 'collector_submission'"
    );
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_worker_jobs_collector_mirror_unique_v1', '1')"
    );
}

/**
 * Credentialed checks engine — MVP slice 1 (schema only).
 *
 * Additive tables for profiles, plugins, jobs, runs, targets, results, artifacts.
 * No execution, no API, no secrets written. Logical refs to users / worker_jobs / assets
 * are not enforced as SQLite FKs (project style).
 *
 * @see docs/CREDENTIALED_CHECKS_ENGINE.md
 * @see docs/CREDENTIALED_CHECKS_MVP_PLAN.md
 */
function st_migrate_credentialed_checks_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_credentialed_checks_v1' LIMIT 1")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS credential_profiles (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            name                 TEXT NOT NULL,
            transport            TEXT NOT NULL,
            principal_json       TEXT,
            secret_ciphertext    TEXT,
            scope_json           TEXT,
            enabled              INTEGER NOT NULL DEFAULT 1,
            created_by           INTEGER,
            created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
            updated_at           DATETIME NOT NULL DEFAULT (datetime('now')),
            last_test_at         DATETIME,
            last_test_status     TEXT
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_credential_profiles_transport ON credential_profiles(transport, enabled)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_credential_profiles_created ON credential_profiles(created_at DESC)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS credential_check_plugins (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            plugin_key           TEXT NOT NULL,
            version              TEXT NOT NULL,
            transport            TEXT NOT NULL,
            manifest_json        TEXT NOT NULL,
            state                TEXT NOT NULL DEFAULT 'stable',
            created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
            updated_at           DATETIME NOT NULL DEFAULT (datetime('now')),
            UNIQUE(plugin_key, version)
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_plugins_key ON credential_check_plugins(plugin_key)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_plugins_transport_state ON credential_check_plugins(transport, state)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS credential_check_jobs (
            id                         INTEGER PRIMARY KEY AUTOINCREMENT,
            name                       TEXT NOT NULL,
            description                TEXT,
            credential_profile_id      INTEGER NOT NULL,
            target_mode                TEXT NOT NULL,
            target_json                TEXT,
            plugin_selection_json      TEXT,
            policy_json                TEXT,
            schedule_cron              TEXT,
            enabled                    INTEGER NOT NULL DEFAULT 1,
            created_by                 INTEGER,
            created_at                 DATETIME NOT NULL DEFAULT (datetime('now')),
            updated_at                 DATETIME NOT NULL DEFAULT (datetime('now'))
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_jobs_profile ON credential_check_jobs(credential_profile_id, enabled)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_jobs_enabled ON credential_check_jobs(enabled, updated_at DESC)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS credential_check_runs (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id               INTEGER,
            worker_job_id        INTEGER,
            started_at           DATETIME NOT NULL DEFAULT (datetime('now')),
            finished_at          DATETIME,
            status               TEXT NOT NULL DEFAULT 'queued',
            initiated_by         TEXT,
            summary_json         TEXT
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_runs_job ON credential_check_runs(job_id, started_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_runs_status ON credential_check_runs(status, started_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_runs_worker_job ON credential_check_runs(worker_job_id)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS credential_check_run_targets (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id               INTEGER NOT NULL,
            asset_id             INTEGER NOT NULL,
            status               TEXT NOT NULL DEFAULT 'pending',
            error_code           TEXT,
            error_message_safe   TEXT,
            started_at           DATETIME,
            finished_at          DATETIME
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_run_targets_run ON credential_check_run_targets(run_id, status)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_run_targets_asset_started ON credential_check_run_targets(asset_id, started_at DESC)');

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS credential_check_results (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id               INTEGER NOT NULL,
            target_id            INTEGER,
            asset_id             INTEGER NOT NULL,
            plugin_key           TEXT NOT NULL,
            plugin_version       TEXT NOT NULL,
            status               TEXT NOT NULL,
            normalized_json      TEXT,
            metrics_json         TEXT,
            created_at           DATETIME NOT NULL DEFAULT (datetime('now'))
        )"
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_results_run ON credential_check_results(run_id, created_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_results_target ON credential_check_results(target_id)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_results_asset_plugin ON credential_check_results(asset_id, plugin_key, created_at DESC)');

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS credential_check_artifacts (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            result_id            INTEGER NOT NULL,
            kind                 TEXT NOT NULL,
            storage_path         TEXT,
            "blob"               BLOB,
            sha256               TEXT,
            size_bytes           INTEGER,
            redaction_version    INTEGER NOT NULL DEFAULT 1,
            created_at           DATETIME NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_artifacts_result ON credential_check_artifacts(result_id, created_at DESC)');

    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_credentialed_checks_v1', '1')"
    );
}

/**
 * Add credential_profiles.deleted_at for soft-archive when profiles are still referenced by jobs.
 */
function st_migrate_cred_profiles_deleted_at_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_cred_profiles_deleted_at_v1' LIMIT 1")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $t = $pdo->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credential_profiles' LIMIT 1")->fetchColumn();
    if ($t === false || $t === null) {
        return;
    }
    $cols = array_column($pdo->query('PRAGMA table_info(credential_profiles)')->fetchAll(PDO::FETCH_ASSOC), 'name');
    if (! in_array('deleted_at', $cols, true)) {
        $pdo->exec('ALTER TABLE credential_profiles ADD COLUMN deleted_at DATETIME');
    }
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_credential_profiles_deleted ON credential_profiles(deleted_at)');
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_cred_profiles_deleted_at_v1', '1')"
    );
}

/**
 * Credential profile transport test result columns (slice 5 handshake).
 */
function st_migrate_cred_profile_test_columns_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_cred_profile_test_columns_v1' LIMIT 1")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $t = $pdo->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credential_profiles' LIMIT 1")->fetchColumn();
    if ($t === false || $t === null) {
        return;
    }
    $cols = array_column($pdo->query('PRAGMA table_info(credential_profiles)')->fetchAll(PDO::FETCH_ASSOC), 'name');
    if (! in_array('last_test_error_code', $cols, true)) {
        $pdo->exec('ALTER TABLE credential_profiles ADD COLUMN last_test_error_code TEXT');
    }
    if (! in_array('last_test_duration_ms', $cols, true)) {
        $pdo->exec('ALTER TABLE credential_profiles ADD COLUMN last_test_duration_ms INTEGER');
    }
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_cred_profile_test_columns_v1', '1')"
    );
}

/**
 * Credential check job recurring schedule (Phase 1) + run launch_source.
 */
function st_migrate_cred_check_job_schedule_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_cred_check_job_schedule_v1' LIMIT 1")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $t = $pdo->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credential_check_jobs' LIMIT 1")->fetchColumn();
    if ($t === false || $t === null) {
        return;
    }
    $jobCol = static function (PDO $pdo): array {
        return array_column($pdo->query('PRAGMA table_info(credential_check_jobs)')->fetchAll(PDO::FETCH_ASSOC), 'name');
    };
    $jcols = $jobCol($pdo);
    if (! in_array('schedule_enabled', $jcols, true)) {
        $pdo->exec('ALTER TABLE credential_check_jobs ADD COLUMN schedule_enabled INTEGER NOT NULL DEFAULT 0');
    }
    $jcols = $jobCol($pdo);
    if (! in_array('schedule_timezone', $jcols, true)) {
        $pdo->exec("ALTER TABLE credential_check_jobs ADD COLUMN schedule_timezone TEXT NOT NULL DEFAULT 'UTC'");
    }
    $jcols = $jobCol($pdo);
    if (! in_array('schedule_last_run_at', $jcols, true)) {
        $pdo->exec('ALTER TABLE credential_check_jobs ADD COLUMN schedule_last_run_at TEXT');
    }
    $jcols = $jobCol($pdo);
    if (! in_array('schedule_next_run_at', $jcols, true)) {
        $pdo->exec('ALTER TABLE credential_check_jobs ADD COLUMN schedule_next_run_at TEXT');
    }
    $jcols = $jobCol($pdo);
    if (! in_array('schedule_last_error', $jcols, true)) {
        $pdo->exec('ALTER TABLE credential_check_jobs ADD COLUMN schedule_last_error TEXT');
    }
    $jcols = $jobCol($pdo);
    if (! in_array('max_concurrency', $jcols, true)) {
        $pdo->exec('ALTER TABLE credential_check_jobs ADD COLUMN max_concurrency INTEGER NOT NULL DEFAULT 1');
    }
    $jcols = $jobCol($pdo);
    if (! in_array('run_timeout_sec', $jcols, true)) {
        $pdo->exec('ALTER TABLE credential_check_jobs ADD COLUMN run_timeout_sec INTEGER NOT NULL DEFAULT 3600');
    }
    $rcols = array_column($pdo->query('PRAGMA table_info(credential_check_runs)')->fetchAll(PDO::FETCH_ASSOC), 'name');
    if (! in_array('launch_source', $rcols, true)) {
        $pdo->exec("ALTER TABLE credential_check_runs ADD COLUMN launch_source TEXT NOT NULL DEFAULT 'manual'");
    }
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_cred_check_jobs_schedule_due ON credential_check_jobs(enabled, schedule_enabled, schedule_next_run_at)');
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_cred_check_job_schedule_v1', '1')"
    );
}

/**
 * Normalized software inventory tables (credentialed SSH package inventory persistence).
 */
function st_migrate_software_inventory_normalized_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_software_inventory_normalized_v1' LIMIT 1")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $t = $pdo->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'assets' LIMIT 1")->fetchColumn();
    if ($t === false || $t === null) {
        return;
    }
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS software_inventory (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem            TEXT NOT NULL,
            canonical_name       TEXT NOT NULL,
            normalized_name      TEXT NOT NULL,
            source_package_name  TEXT,
            vendor               TEXT,
            created_at           DATETIME NOT NULL DEFAULT (datetime(\'now\')),
            updated_at           DATETIME NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );
    $pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS uq_software_inventory_eco_norm ON software_inventory(ecosystem, normalized_name)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_software_inventory_eco_norm ON software_inventory(ecosystem, normalized_name)');
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS software_inventory_versions (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            software_inventory_id   INTEGER NOT NULL REFERENCES software_inventory(id) ON DELETE CASCADE,
            version_raw             TEXT NOT NULL,
            version_normalized      TEXT,
            architecture            TEXT,
            distro_release            TEXT,
            package_release           TEXT,
            epoch                     TEXT,
            created_at                DATETIME NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );
    $pdo->exec(
        'CREATE UNIQUE INDEX IF NOT EXISTS uq_software_inventory_versions_key
            ON software_inventory_versions(software_inventory_id, version_raw, IFNULL(architecture, \'\'))'
    );
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS software_inventory_asset_state (
            id                           INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id                     INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            software_inventory_version_id INTEGER NOT NULL REFERENCES software_inventory_versions(id) ON DELETE CASCADE,
            first_seen_at                DATETIME NOT NULL DEFAULT (datetime(\'now\')),
            last_seen_at                 DATETIME NOT NULL DEFAULT (datetime(\'now\')),
            source                       TEXT NOT NULL DEFAULT \'credentialed_check\',
            credential_check_run_id      INTEGER,
            active                       INTEGER NOT NULL DEFAULT 1
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_sinv_asset_state_asset ON software_inventory_asset_state(asset_id, active, last_seen_at DESC)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_sinv_asset_state_version ON software_inventory_asset_state(software_inventory_version_id)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_sinv_asset_state_last_seen ON software_inventory_asset_state(last_seen_at DESC)');
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_software_inventory_normalized_v1', '1')"
    );
}

/**
 * Advisory records + package rules + correlated asset_vulnerabilities (inventory-driven; local ingestion).
 */
function st_migrate_vulnerability_correlation_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_vulnerability_correlation_v1' LIMIT 1")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $t = $pdo->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'assets' LIMIT 1")->fetchColumn();
    if ($t === false || $t === null) {
        return;
    }
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS vulnerability_advisories (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_key   TEXT NOT NULL,
            source         TEXT NOT NULL,
            severity       TEXT NOT NULL DEFAULT \'unknown\',
            cvss_score     REAL,
            description    TEXT,
            published_at   DATETIME,
            modified_at    DATETIME,
            withdrawn      INTEGER NOT NULL DEFAULT 0,
            created_at     DATETIME NOT NULL DEFAULT (datetime(\'now\')),
            updated_at     DATETIME NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );
    $pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS uq_vulnerability_advisories_key ON vulnerability_advisories(advisory_key)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_vulnerability_advisories_severity ON vulnerability_advisories(severity)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_vulnerability_advisories_modified ON vulnerability_advisories(modified_at DESC)');
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS vulnerability_advisory_packages (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id        INTEGER NOT NULL REFERENCES vulnerability_advisories(id) ON DELETE CASCADE,
            ecosystem          TEXT NOT NULL,
            normalized_name    TEXT NOT NULL,
            version_operator   TEXT NOT NULL,
            version_value      TEXT NOT NULL,
            distro_release     TEXT,
            architecture       TEXT,
            fixed_version      TEXT,
            metadata_json      TEXT,
            created_at         DATETIME NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_vuln_adv_pkg_advisory ON vulnerability_advisory_packages(advisory_id)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_vuln_adv_pkg_eco_name ON vulnerability_advisory_packages(ecosystem, normalized_name)');
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
            id                              INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id                        INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            software_inventory_asset_state_id INTEGER NOT NULL REFERENCES software_inventory_asset_state(id) ON DELETE CASCADE,
            advisory_id                     INTEGER NOT NULL REFERENCES vulnerability_advisories(id) ON DELETE CASCADE,
            status                          TEXT NOT NULL DEFAULT \'affected\',
            first_seen_at                   DATETIME NOT NULL DEFAULT (datetime(\'now\')),
            last_seen_at                    DATETIME NOT NULL DEFAULT (datetime(\'now\')),
            detection_source                TEXT NOT NULL DEFAULT \'inventory_correlation\',
            correlation_confidence          TEXT NOT NULL DEFAULT \'medium\',
            fixed_detected_at               DATETIME,
            explain_json                    TEXT,
            created_at                      DATETIME NOT NULL DEFAULT (datetime(\'now\')),
            updated_at                      DATETIME NOT NULL DEFAULT (datetime(\'now\')),
            UNIQUE(asset_id, advisory_id, software_inventory_asset_state_id)
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_asset_vuln_asset ON asset_vulnerabilities(asset_id, status)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_asset_vuln_advisory ON asset_vulnerabilities(advisory_id, status)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_asset_vuln_status ON asset_vulnerabilities(status, last_seen_at DESC)');
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS vulnerability_correlation_runs (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at         DATETIME NOT NULL DEFAULT (datetime(\'now\')),
            finished_at        DATETIME,
            mode               TEXT NOT NULL DEFAULT \'batch\',
            assets_processed   INTEGER NOT NULL DEFAULT 0,
            rules_evaluated    INTEGER NOT NULL DEFAULT 0,
            rows_matched       INTEGER NOT NULL DEFAULT 0,
            rows_upserted      INTEGER NOT NULL DEFAULT 0,
            rows_marked_fixed  INTEGER NOT NULL DEFAULT 0,
            duration_ms        INTEGER,
            status             TEXT NOT NULL DEFAULT \'ok\',
            error_safe         TEXT
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_vuln_corr_runs_finished ON vulnerability_correlation_runs(finished_at DESC)');
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_vulnerability_correlation_v1', '1')"
    );
}

/**
 * Analyst triage, notes, and immutable activity log (operational workflow).
 */
function st_migrate_vulnerability_triage_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_vulnerability_triage_v1' LIMIT 1")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $t = $pdo->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'asset_vulnerabilities' LIMIT 1")->fetchColumn();
    if ($t === false || $t === null) {
        return;
    }
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS asset_vulnerability_triage (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_vulnerability_id  INTEGER NOT NULL UNIQUE REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
            triage_state            TEXT NOT NULL DEFAULT \'new\',
            priority                TEXT NOT NULL DEFAULT \'medium\',
            priority_source         TEXT NOT NULL DEFAULT \'model\',
            assigned_to             TEXT,
            due_at                  DATETIME,
            first_triaged_at        DATETIME,
            last_triaged_at         DATETIME,
            last_changed_by         TEXT,
            suppression_reason      TEXT,
            suppression_expires_at  DATETIME,
            notes_count             INTEGER NOT NULL DEFAULT 0,
            created_at              DATETIME NOT NULL DEFAULT (datetime(\'now\')),
            updated_at              DATETIME NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_av_triage_state ON asset_vulnerability_triage(triage_state)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_av_triage_priority ON asset_vulnerability_triage(priority)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_av_triage_assigned ON asset_vulnerability_triage(assigned_to)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_av_triage_due ON asset_vulnerability_triage(due_at)');
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS vulnerability_notes (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_vulnerability_id  INTEGER NOT NULL REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
            author                  TEXT NOT NULL,
            note_text               TEXT NOT NULL,
            created_at              DATETIME NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_vuln_notes_av ON vulnerability_notes(asset_vulnerability_id, created_at DESC)');
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS vulnerability_activity_log (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_vulnerability_id  INTEGER NOT NULL REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
            action                  TEXT NOT NULL,
            actor                   TEXT NOT NULL,
            details_json            TEXT,
            created_at              DATETIME NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_vuln_act_av ON vulnerability_activity_log(asset_vulnerability_id, created_at DESC)');
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_vulnerability_triage_v1', '1')"
    );
}

/**
 * Triage row: priority_source (model vs analyst_override) for API/UI clarity.
 */
function st_migrate_vulnerability_triage_priority_source_v1(PDO $pdo): void
{
    $v = $pdo->query("SELECT value FROM config WHERE key = 'migration_vulnerability_triage_priority_source_v1' LIMIT 1")->fetchColumn();
    if ($v === '1' || $v === 1) {
        return;
    }
    $t = $pdo->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'asset_vulnerability_triage' LIMIT 1")->fetchColumn();
    if ($t === false || $t === null) {
        return;
    }
    $has = false;
    try {
        foreach ($pdo->query('PRAGMA table_info(asset_vulnerability_triage)') ?: [] as $col) {
            if (is_array($col) && (($col['name'] ?? '') === 'priority_source')) {
                $has = true;
                break;
            }
        }
    } catch (Throwable $e) {
        $has = false;
    }
    if (! $has) {
        try {
            $pdo->exec(
                "ALTER TABLE asset_vulnerability_triage ADD COLUMN priority_source TEXT NOT NULL DEFAULT 'model'"
            );
        } catch (Throwable $e) {
            @error_log('SurveyTrace st_migrate_vulnerability_triage_priority_source_v1: ' . $e->getMessage());

            return;
        }
    }
    try {
        $pdo->exec("UPDATE asset_vulnerability_triage SET priority_source = 'model' WHERE priority_source IS NULL OR trim(priority_source) = ''");
    } catch (Throwable $e) {
        // ignore
    }
    $pdo->exec(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_vulnerability_triage_priority_source_v1', '1')"
    );
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------
function st_config(string $key, string $default = ''): string {
    if (!isset($GLOBALS['st_config_cache']) || !is_array($GLOBALS['st_config_cache'])) {
        $GLOBALS['st_config_cache'] = [];
    }
    $cache = &$GLOBALS['st_config_cache'];
    if (isset($cache[$key])) {
        return $cache[$key];
    }
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
    if (isset($GLOBALS['st_config_cache']) && is_array($GLOBALS['st_config_cache'])) {
        unset($GLOBALS['st_config_cache'][$key]);
    }
}

/**
 * Wall-clock seconds to wait for Ollama /api/generate on operator HTTP flows (host panel summary,
 * scan AI refresh, CVE triage API). Config key ai_operator_ollama_timeout_s; clamped 120–3600.
 */
function st_ai_operator_ollama_timeout_cap(): int {
    $v = (int)st_config('ai_operator_ollama_timeout_s', '900');
    return max(120, min(3600, $v));
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
        header('X-Frame-Options: SAMEORIGIN');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        $xf = strtolower(trim((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
        if ($https || $xf === 'https') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
        // Deliberately no broad Content-Security-Policy here: the SPA uses inline handlers/styles.
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

/**
 * JSON 429 with Retry-After (rate limiting). Same baseline headers as st_json().
 */
function st_json_rate_limited(string $message = 'Too many requests', int $retryAfterSeconds = 60): never {
    if (!headers_sent()) {
        http_response_code(429);
        $ra = max(1, min(86400, $retryAfterSeconds));
        header('Retry-After: ' . $ra);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        $xf = strtolower(trim((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
        if ($https || $xf === 'https') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
        header('Cache-Control: no-store');
    }
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
        | JSON_INVALID_UTF8_SUBSTITUTE;
    $out = json_encode(['ok' => false, 'error' => $message], $flags);
    if ($out === false) {
        $out = '{"ok":false,"error":"Too many requests"}';
    }
    echo $out;
    exit;
}

/**
 * Emit JSON body only (no SurveyTrace envelope). Used for Grafana Infinity ?view= slices on pull APIs.
 */
function st_json_raw(mixed $data, int $status = 200): never
{
    if (! headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        $xf = strtolower(trim((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
        if ($https || $xf === 'https') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
        header('Cache-Control: no-store');
    }
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;
    $out = json_encode($data, $flags);
    if ($out === false) {
        $out = '{"error":"json_encode_failed"}';
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
    if (session_status() === PHP_SESSION_ACTIVE) {
        @session_regenerate_id(true);
        $_SESSION['st_csrf'] = bin2hex(random_bytes(32));
    }
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
        $clean = static function (?string $s): ?string {
            if ($s === null) return null;
            $v = preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string)$s);
            return trim((string)$v);
        };
        st_ensure_user_audit_schema();
        $actor = st_current_user();
        $actorId = $actorUserId ?? (($actor['id'] ?? 0) > 0 ? (int)$actor['id'] : null);
        $actorName = $clean($actorUsername ?? (($actor['username'] ?? '') !== '' ? (string)$actor['username'] : null));
        $targetUsername = $clean($targetUsername);
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
        $msg = preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string)$e->getMessage());
        @error_log('SurveyTrace audit log write failed: ' . trim((string)$msg));
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
        $n = strtoupper(bin2hex(random_bytes(8))); // 64-bit entropy per code
        $out[] = substr($n, 0, 4) . '-' . substr($n, 4, 4) . '-' . substr($n, 8, 4) . '-' . substr($n, 12, 4);
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

/** Default bcrypt cost for new hashes (must match st_password_needs_rehash options). */
function st_password_bcrypt_options(): array {
    return ['cost' => 12];
}

function st_password_hash(string $password): string {
    $algo = st_password_hash_algo();
    if ($algo === 'argon2id' && defined('PASSWORD_ARGON2ID')) {
        return password_hash($password, PASSWORD_ARGON2ID);
    }
    return password_hash($password, PASSWORD_BCRYPT, st_password_bcrypt_options());
}

function st_password_needs_rehash(string $hash): bool {
    $algo = st_password_hash_algo();
    if ($algo === 'argon2id' && defined('PASSWORD_ARGON2ID')) {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID);
    }
    return password_needs_rehash($hash, PASSWORD_BCRYPT, st_password_bcrypt_options());
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
    $stmt = st_db()->prepare(
        "SELECT failed_count, locked_until,
                CASE WHEN locked_until IS NOT NULL AND locked_until <> ''
                     AND locked_until > datetime('now') THEN 1 ELSE 0 END AS locked_now
         FROM auth_login_state WHERE actor_key=? LIMIT 1"
    );
    $stmt->execute([$actorKey]);
    $row = $stmt->fetch() ?: ['failed_count' => 0, 'locked_until' => null, 'locked_now' => 0];
    $locked = ((int)($row['locked_now'] ?? 0)) === 1;
    $retryAfter = 0;
    if ($locked) {
        $stmt2 = st_db()->prepare(
            "SELECT CAST((strftime('%s', locked_until) - strftime('%s','now')) AS INTEGER) AS d
             FROM auth_login_state WHERE actor_key=? LIMIT 1"
        );
        $stmt2->execute([$actorKey]);
        $retryAfter = max(0, (int)$stmt2->fetchColumn());
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
    if ($origin === '' && $referer === '') {
        st_json(['error' => 'Cross-origin request rejected (missing Origin/Referer)'], 403);
    }
}
