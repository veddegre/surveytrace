<?php
/**
 * End-to-end operational lifecycle regression selftest (sqlite :memory:).
 *
 *   php scripts/st_operational_integrity_selftest.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_version_compare.php';
require_once dirname(__DIR__) . '/api/lib_vulnerability_correlation.php';
require_once dirname(__DIR__) . '/api/lib_vulnerability_triage.php';

function st_oi_fail(string $msg): void
{
    fwrite(STDERR, 'FAIL: ' . $msg . "\n");
    exit(1);
}

// ---------------------------------------------------------------------------
// Schema (same DDL as st_vulnerability_dashboard_selftest.php)
// ---------------------------------------------------------------------------

$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('PRAGMA foreign_keys=ON');

$pdo->exec('CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)');
$pdo->exec("INSERT INTO config VALUES ('migration_worker_execution_substrate_v1','1')");

$pdo->exec(
    'CREATE TABLE worker_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_type TEXT NOT NULL,
        entity_type TEXT,
        entity_id INTEGER,
        status TEXT NOT NULL DEFAULT \'queued\',
        priority INTEGER NOT NULL DEFAULT 0,
        lease_node_id INTEGER,
        lease_token TEXT,
        leased_at DATETIME,
        lease_expires_at DATETIME,
        attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 3,
        next_attempt_at DATETIME,
        cancel_requested_at DATETIME,
        error_code TEXT,
        error_message TEXT,
        payload_json TEXT,
        result_summary_json TEXT,
        created_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        updated_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        finished_at DATETIME
    )'
);

$pdo->exec('CREATE TABLE assets (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, hostname TEXT)');

$pdo->exec(
    'CREATE TABLE software_inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ecosystem TEXT NOT NULL,
        canonical_name TEXT NOT NULL,
        normalized_name TEXT NOT NULL,
        source_package_name TEXT,
        vendor TEXT,
        created_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        updated_at DATETIME NOT NULL DEFAULT (datetime(\'now\'))
    )'
);
$pdo->exec(
    'CREATE TABLE software_inventory_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        software_inventory_id INTEGER NOT NULL REFERENCES software_inventory(id) ON DELETE CASCADE,
        version_raw TEXT NOT NULL,
        version_normalized TEXT,
        architecture TEXT,
        distro_release TEXT,
        package_release TEXT,
        epoch TEXT,
        created_at DATETIME NOT NULL DEFAULT (datetime(\'now\'))
    )'
);
$pdo->exec(
    'CREATE TABLE software_inventory_asset_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        software_inventory_version_id INTEGER NOT NULL REFERENCES software_inventory_versions(id) ON DELETE CASCADE,
        first_seen_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        last_seen_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        source TEXT NOT NULL DEFAULT \'credentialed_check\',
        credential_check_run_id INTEGER,
        active INTEGER NOT NULL DEFAULT 1
    )'
);

$pdo->exec(
    'CREATE TABLE vulnerability_advisories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        advisory_key TEXT NOT NULL,
        source TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT \'unknown\',
        cvss_score REAL,
        description TEXT,
        references_json TEXT,
        package_authority TEXT NOT NULL DEFAULT \'internal\',
        published_at DATETIME,
        modified_at DATETIME,
        withdrawn INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        updated_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        UNIQUE(advisory_key)
    )'
);
$pdo->exec(
    'CREATE TABLE vulnerability_advisory_packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        advisory_id INTEGER NOT NULL REFERENCES vulnerability_advisories(id) ON DELETE CASCADE,
        ecosystem TEXT NOT NULL,
        normalized_name TEXT NOT NULL,
        version_operator TEXT NOT NULL,
        version_value TEXT NOT NULL,
        distro_release TEXT,
        architecture TEXT,
        fixed_version TEXT,
        metadata_json TEXT,
        created_at DATETIME NOT NULL DEFAULT (datetime(\'now\'))
    )'
);
$pdo->exec(
    'CREATE TABLE asset_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        software_inventory_asset_state_id INTEGER NOT NULL REFERENCES software_inventory_asset_state(id) ON DELETE CASCADE,
        advisory_id INTEGER NOT NULL REFERENCES vulnerability_advisories(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT \'affected\',
        first_seen_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        last_seen_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        detection_source TEXT NOT NULL DEFAULT \'inventory_correlation\',
        correlation_confidence TEXT NOT NULL DEFAULT \'medium\',
        fixed_detected_at DATETIME,
        explain_json TEXT,
        created_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        updated_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        UNIQUE(asset_id, advisory_id, software_inventory_asset_state_id)
    )'
);
$pdo->exec(
    'CREATE TABLE vulnerability_correlation_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        finished_at DATETIME,
        mode TEXT NOT NULL DEFAULT \'batch\',
        assets_processed INTEGER NOT NULL DEFAULT 0,
        rules_evaluated INTEGER NOT NULL DEFAULT 0,
        rows_matched INTEGER NOT NULL DEFAULT 0,
        rows_upserted INTEGER NOT NULL DEFAULT 0,
        rows_marked_fixed INTEGER NOT NULL DEFAULT 0,
        duration_ms INTEGER,
        status TEXT NOT NULL DEFAULT \'ok\',
        error_safe TEXT
    )'
);
$pdo->exec(
    'CREATE TABLE asset_vulnerability_triage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_vulnerability_id INTEGER NOT NULL UNIQUE REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
        triage_state TEXT NOT NULL DEFAULT \'new\',
        priority TEXT NOT NULL DEFAULT \'medium\',
        priority_source TEXT NOT NULL DEFAULT \'model\',
        assigned_to TEXT,
        due_at DATETIME,
        first_triaged_at DATETIME,
        last_triaged_at DATETIME,
        last_changed_by TEXT,
        suppression_reason TEXT,
        suppression_expires_at DATETIME,
        notes_count INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT (datetime(\'now\')),
        updated_at DATETIME NOT NULL DEFAULT (datetime(\'now\'))
    )'
);
$pdo->exec(
    'CREATE TABLE vulnerability_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_vulnerability_id INTEGER NOT NULL REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
        author TEXT NOT NULL,
        note_text TEXT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT (datetime(\'now\'))
    )'
);
$pdo->exec(
    'CREATE TABLE vulnerability_activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_vulnerability_id INTEGER NOT NULL REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
        action TEXT NOT NULL,
        actor TEXT NOT NULL,
        details_json TEXT,
        created_at DATETIME NOT NULL DEFAULT (datetime(\'now\'))
    )'
);

// ---------------------------------------------------------------------------
// Step 1: Seed 2 assets with software inventory
// ---------------------------------------------------------------------------

$pdo->exec("INSERT INTO assets (id, ip, hostname) VALUES (1, '10.0.0.1', 'host-a')");
$pdo->exec("INSERT INTO assets (id, ip, hostname) VALUES (2, '10.0.0.2', 'host-b')");

$pdo->exec("INSERT INTO software_inventory (id, ecosystem, canonical_name, normalized_name) VALUES (1, 'dpkg', 'openssl', 'openssl')");
$pdo->exec("INSERT INTO software_inventory_versions (id, software_inventory_id, version_raw, version_normalized) VALUES (1, 1, '3.0.10-1', '3.0.10-1')");
$pdo->exec("INSERT INTO software_inventory_asset_state (id, asset_id, software_inventory_version_id, active) VALUES (1, 1, 1, 1)");
$pdo->exec("INSERT INTO software_inventory_asset_state (id, asset_id, software_inventory_version_id, active) VALUES (2, 2, 1, 1)");

// ---------------------------------------------------------------------------
// Step 2: Import advisory (internal, package_authority='internal')
// ---------------------------------------------------------------------------

$pdo->exec(
    "INSERT INTO vulnerability_advisories (id, advisory_key, source, severity, cvss_score, package_authority, references_json)
     VALUES (1, 'CVE-2025-9999', 'internal', 'critical', 9.8, 'internal', '[\"https://example.com/advisory\"]')"
);
$pdo->exec(
    "INSERT INTO vulnerability_advisory_packages (advisory_id, ecosystem, normalized_name, version_operator, version_value)
     VALUES (1, 'dpkg', 'openssl', '<', '99.0.0-1')"
);

// ---------------------------------------------------------------------------
// Step 3: Correlate both assets — assert affected rows created
// ---------------------------------------------------------------------------

$c1 = st_vuln_correlation_run_for_asset($pdo, 1, null);
if (! $c1['ok']) {
    st_oi_fail('correlation asset 1: ok=false');
}
if ($c1['matched'] < 1) {
    st_oi_fail('correlation asset 1: matched=' . $c1['matched'] . ', expected >= 1');
}

$c2 = st_vuln_correlation_run_for_asset($pdo, 2, null);
if (! $c2['ok']) {
    st_oi_fail('correlation asset 2: ok=false');
}
if ($c2['matched'] < 1) {
    st_oi_fail('correlation asset 2: matched=' . $c2['matched'] . ', expected >= 1');
}

$avCount = (int) $pdo->query("SELECT COUNT(*) FROM asset_vulnerabilities WHERE status='affected'")->fetchColumn();
if ($avCount !== 2) {
    st_oi_fail('affected rows after correlation: expected 2, got ' . $avCount);
}

// ---------------------------------------------------------------------------
// Step 4: Verify triage rows created with priority_source='model'
// ---------------------------------------------------------------------------

$triageCount = (int) $pdo->query('SELECT COUNT(*) FROM asset_vulnerability_triage')->fetchColumn();
if ($triageCount !== 2) {
    st_oi_fail('triage rows after correlation: expected 2, got ' . $triageCount);
}

$modelSourceCount = (int) $pdo->query("SELECT COUNT(*) FROM asset_vulnerability_triage WHERE priority_source='model'")->fetchColumn();
if ($modelSourceCount !== 2) {
    st_oi_fail('triage priority_source=model count: expected 2, got ' . $modelSourceCount);
}

// ---------------------------------------------------------------------------
// Step 5: Suppression — verify rollup counts suppressed=1
// ---------------------------------------------------------------------------

$avId1 = (int) $pdo->query('SELECT id FROM asset_vulnerabilities WHERE asset_id=1 LIMIT 1')->fetchColumn();
if ($avId1 < 1) {
    st_oi_fail('cannot find asset_vulnerability for asset 1');
}

$pdo->exec("UPDATE asset_vulnerability_triage SET suppression_reason='accepted risk' WHERE asset_vulnerability_id={$avId1}");
$r5 = st_vuln_asset_risk_rollup($pdo, 1);
if ($r5['suppressed'] !== 1) {
    st_oi_fail('suppression rollup: expected suppressed=1, got ' . $r5['suppressed']);
}

$pdo->exec("UPDATE asset_vulnerability_triage SET suppression_reason=NULL WHERE asset_vulnerability_id={$avId1}");

// ---------------------------------------------------------------------------
// Step 6: Reset-to-model — analyst_override then reset
// ---------------------------------------------------------------------------

if (! st_vt_update_state($pdo, $avId1, 'investigating', 'high', 'analyst.test')) {
    st_oi_fail('update_state for analyst override');
}
$overrideSrc = (string) $pdo->query(
    "SELECT priority_source FROM asset_vulnerability_triage WHERE asset_vulnerability_id={$avId1}"
)->fetchColumn();
if ($overrideSrc !== 'analyst_override') {
    st_oi_fail('after explicit priority: expected analyst_override, got ' . $overrideSrc);
}

$rollupOv = st_vuln_asset_risk_rollup($pdo, 1);
if ($rollupOv['overrides'] !== 1) {
    st_oi_fail('override rollup: expected 1, got ' . $rollupOv['overrides']);
}

if (! st_vt_reset_priority_to_model($pdo, $avId1, 'admin.test')) {
    st_oi_fail('reset_priority_to_model');
}
$resetSrc = (string) $pdo->query(
    "SELECT priority_source FROM asset_vulnerability_triage WHERE asset_vulnerability_id={$avId1}"
)->fetchColumn();
if ($resetSrc !== 'model') {
    st_oi_fail('after reset: expected model, got ' . $resetSrc);
}

$rollupRst = st_vuln_asset_risk_rollup($pdo, 1);
if ($rollupRst['overrides'] !== 0) {
    st_oi_fail('override rollup after reset: expected 0, got ' . $rollupRst['overrides']);
}

// ---------------------------------------------------------------------------
// Step 7: Dashboard rollup — total_open matches, no negative counters
// ---------------------------------------------------------------------------

$sum = st_vuln_dashboard_summary($pdo);
if ($sum['total_open'] !== $avCount) {
    st_oi_fail('dashboard total_open: expected ' . $avCount . ', got ' . $sum['total_open']);
}

$nonNegKeys = [
    'total_open', 'critical_count', 'high_count', 'medium_count', 'low_count',
    'info_count', 'suppressed', 'overrides', 'distinct_affected_assets', 'stale_findings_over_30d',
];
foreach ($nonNegKeys as $k) {
    if (array_key_exists($k, $sum) && (int) $sum[$k] < 0) {
        st_oi_fail('dashboard negative counter: ' . $k . '=' . $sum[$k]);
    }
}

// ---------------------------------------------------------------------------
// Step 11 (run before cleanup): Bounded outputs — top_assets limit=1
// ---------------------------------------------------------------------------

$top = st_vuln_dashboard_top_assets($pdo, 1);
if (count($top) > 1) {
    st_oi_fail('top_assets limit=1: got ' . count($top) . ' rows, expected <= 1');
}
if (count($top) < 1) {
    st_oi_fail('top_assets limit=1: expected at least 1 row');
}

// ---------------------------------------------------------------------------
// Step 8: Cleanup/removal — delete advisory, assert cascade removes dependents
// ---------------------------------------------------------------------------

$pdo->exec('DELETE FROM vulnerability_advisories WHERE id=1');

$orphanTriage = (int) $pdo->query(
    'SELECT COUNT(*) FROM asset_vulnerability_triage t
     LEFT JOIN asset_vulnerabilities av ON av.id = t.asset_vulnerability_id
     WHERE av.id IS NULL'
)->fetchColumn();
if ($orphanTriage > 0) {
    st_oi_fail('orphan triage rows after advisory delete: ' . $orphanTriage);
}

$orphanActivity = (int) $pdo->query(
    'SELECT COUNT(*) FROM vulnerability_activity_log l
     LEFT JOIN asset_vulnerabilities av ON av.id = l.asset_vulnerability_id
     WHERE av.id IS NULL'
)->fetchColumn();
if ($orphanActivity > 0) {
    st_oi_fail('orphan activity rows after advisory delete: ' . $orphanActivity);
}

// ---------------------------------------------------------------------------
// Step 9: Scheduler state — completed job + correlation run
// ---------------------------------------------------------------------------

$pdo->exec(
    "INSERT INTO worker_jobs (job_type, entity_type, entity_id, status, finished_at)
     VALUES ('vulnerability_correlation', 'asset', 1, 'completed', datetime('now'))"
);
$pdo->exec(
    "INSERT INTO vulnerability_correlation_runs (started_at, finished_at, mode, assets_processed, status, duration_ms)
     VALUES (datetime('now', '-1 minute'), datetime('now'), 'batch', 2, 'ok', 500)"
);

// ---------------------------------------------------------------------------
// Step 10: Health snapshot — assert shape and no crash
// ---------------------------------------------------------------------------

$health = st_vuln_dashboard_health_snapshot($pdo);
$requiredHealthKeys = [
    'total_open_findings', 'critical_open_findings', 'stale_findings_over_30d',
    'suppressed_active', 'override_active', 'top_risk_asset_id', 'warnings',
];
foreach ($requiredHealthKeys as $k) {
    if (! array_key_exists($k, $health)) {
        st_oi_fail('health snapshot missing key: ' . $k);
    }
}
if (! is_array($health['warnings'])) {
    st_oi_fail('health warnings must be array');
}

$hasMissingCorrWarning = false;
foreach ($health['warnings'] as $w) {
    if (str_contains((string) $w, 'No correlation runs recorded')) {
        $hasMissingCorrWarning = true;
    }
}
if ($hasMissingCorrWarning) {
    st_oi_fail('health snapshot should not warn about missing correlation runs when run exists');
}

// ---------------------------------------------------------------------------
// Step 12: Consistent counts — all vuln-related tables empty after cleanup
// ---------------------------------------------------------------------------

$remainAv = (int) $pdo->query('SELECT COUNT(*) FROM asset_vulnerabilities')->fetchColumn();
if ($remainAv !== 0) {
    st_oi_fail('post-cleanup asset_vulnerabilities: expected 0, got ' . $remainAv);
}

$remainTriage = (int) $pdo->query('SELECT COUNT(*) FROM asset_vulnerability_triage')->fetchColumn();
if ($remainTriage !== 0) {
    st_oi_fail('post-cleanup triage: expected 0, got ' . $remainTriage);
}

$remainNotes = (int) $pdo->query('SELECT COUNT(*) FROM vulnerability_notes')->fetchColumn();
if ($remainNotes !== 0) {
    st_oi_fail('post-cleanup notes: expected 0, got ' . $remainNotes);
}

$remainLog = (int) $pdo->query('SELECT COUNT(*) FROM vulnerability_activity_log')->fetchColumn();
if ($remainLog !== 0) {
    st_oi_fail('post-cleanup activity_log: expected 0, got ' . $remainLog);
}

// ---------------------------------------------------------------------------
// Step 13: No orphan rows — triage referencing missing asset_vulnerabilities
// ---------------------------------------------------------------------------

$orphanFinal = (int) $pdo->query(
    'SELECT COUNT(*) FROM asset_vulnerability_triage t
     LEFT JOIN asset_vulnerabilities av ON av.id = t.asset_vulnerability_id
     WHERE av.id IS NULL'
)->fetchColumn();
if ($orphanFinal > 0) {
    st_oi_fail('final orphan triage check: expected 0, got ' . $orphanFinal);
}

echo "OK st_operational_integrity_selftest\n";
exit(0);
