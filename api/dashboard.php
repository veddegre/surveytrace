<?php
/**
 * SurveyTrace — GET /api/dashboard.php
 *
 * Returns all data needed to render the dashboard in a single request:
 *   - Asset counts by category
 *   - Finding counts by severity
 *   - Last scan summary
 *   - Recent activity (last 20 log events across all jobs)
 *   - Top 5 most-vulnerable assets
 *   - Change detection: new/changed/gone since the previous scan
 */

require_once __DIR__ . '/db.php';
st_auth();
st_method('GET');

$db = st_db();

// Ensure newer scan_jobs columns exist for legacy databases
$scanJobCols = array_column($db->query("PRAGMA table_info(scan_jobs)")->fetchAll(), 'name');
$scanJobMigrations = [
    'scan_mode'              => "TEXT DEFAULT 'auto'",
    'profile'                => "TEXT DEFAULT 'standard_inventory'",
    'priority'               => "INTEGER DEFAULT 10",
    'retry_count'            => "INTEGER DEFAULT 0",
    'max_retries'            => "INTEGER DEFAULT 2",
    'label'                  => "TEXT",
    'summary_json'           => "TEXT",
    'schedule_id'            => "INTEGER DEFAULT 0",
    'collector_id'           => "INTEGER DEFAULT 0",
    'phase_status'           => "TEXT DEFAULT '{}'",
    'failure_reason'         => "TEXT",
    'enrichment_source_ids'  => "TEXT",
];
foreach ($scanJobMigrations as $col => $defn) {
    if (!in_array($col, $scanJobCols, true)) {
        $db->exec("ALTER TABLE scan_jobs ADD COLUMN $col $defn");
    }
}

// ---------------------------------------------------------------------------
// Asset summary
// ---------------------------------------------------------------------------
$total_assets = (int)$db->query("SELECT COUNT(*) FROM assets")->fetchColumn();
$unclassified = (int)$db->query("SELECT COUNT(*) FROM assets WHERE category='unk'")->fetchColumn();

$cat_raw = $db->query("SELECT category, COUNT(*) AS cnt FROM assets GROUP BY category ORDER BY cnt DESC")->fetchAll();
$by_category = [];
foreach ($cat_raw as $r) $by_category[$r['category']] = (int)$r['cnt'];

// Assets seen in last 24h vs previous scan window
$new_assets = (int)$db->query(
    "SELECT COUNT(*) FROM assets WHERE first_seen >= datetime('now','-24 hours')"
)->fetchColumn();

// ---------------------------------------------------------------------------
// Findings summary
// ---------------------------------------------------------------------------
$open_findings = (int)$db->query("SELECT COUNT(*) FROM findings WHERE resolved=0")->fetchColumn();

$sev_raw = $db->query("
    SELECT severity, COUNT(*) AS cnt
    FROM findings
    WHERE resolved = 0
    GROUP BY severity
")->fetchAll();
$by_severity = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
foreach ($sev_raw as $r) {
    $key = strtolower($r['severity'] ?? '');
    if (isset($by_severity[$key])) $by_severity[$key] = (int)$r['cnt'];
}

// ---------------------------------------------------------------------------
// Last scan metadata
// ---------------------------------------------------------------------------
$last_scan = $db->query("
    SELECT
        id, status, target_cidr, label,
        hosts_found, hosts_scanned,
        created_at, started_at, finished_at,
        CAST((julianday(COALESCE(finished_at,'now')) - julianday(COALESCE(started_at, created_at))) * 86400 AS INTEGER) AS duration_secs,
        CAST((julianday('now') - julianday(COALESCE(finished_at, created_at))) * 86400 AS INTEGER) AS age_secs
    FROM scan_jobs
    ORDER BY id DESC LIMIT 1
")->fetch();

if ($last_scan) {
    $last_scan['phases'] = json_decode(
        $db->prepare("SELECT phases FROM scan_jobs WHERE id=?")->execute([$last_scan['id']])
            ? ($db->prepare("SELECT phases FROM scan_jobs WHERE id=?")->execute([$last_scan['id']]) && false ?: '')
            : '',
        true
    ) ?: [];
    // Re-query cleanly
    $pstmt = $db->prepare("SELECT phases FROM scan_jobs WHERE id=?");
    $pstmt->execute([$last_scan['id']]);
    $last_scan['phases'] = json_decode($pstmt->fetchColumn() ?: '[]', true) ?: [];
}

// ---------------------------------------------------------------------------
// Scan history (last 10, for sparkline / history table)
// ---------------------------------------------------------------------------
$scan_history = $db->query("
    SELECT id, status, target_cidr, label, hosts_found,
           created_at, finished_at,
           CAST((julianday(COALESCE(finished_at,'now')) - julianday(created_at)) * 86400 AS INTEGER) AS duration_secs
    FROM scan_jobs
    WHERE status IN ('done','failed','aborted')
    ORDER BY id DESC LIMIT 10
")->fetchAll();

// ---------------------------------------------------------------------------
// Top 5 most vulnerable assets
// ---------------------------------------------------------------------------
$top_vulnerable = $db->query("
    SELECT a.id, a.ip, a.device_id, a.hostname, a.category, a.vendor, a.top_cve, a.top_cvss,
           COUNT(f.id) AS finding_count
    FROM assets a
    JOIN findings f ON f.asset_id = a.id AND f.resolved = 0
    WHERE a.top_cvss IS NOT NULL
    GROUP BY a.id
    ORDER BY a.top_cvss DESC, finding_count DESC
    LIMIT 5
")->fetchAll();

foreach ($top_vulnerable as &$tv) {
    $tv['severity']      = st_severity((float)($tv['top_cvss'] ?? 0));
    $tv['top_cvss']      = (float)($tv['top_cvss'] ?? 0);
    $tv['finding_count'] = (int)$tv['finding_count'];
    if (isset($tv['device_id']) && $tv['device_id'] !== null && $tv['device_id'] !== '') {
        $tv['device_id'] = (int)$tv['device_id'];
    }
}
unset($tv);

// ---------------------------------------------------------------------------
// Recent activity feed (last 25 log lines across all jobs, skipping bulk PROBE lines)
// ---------------------------------------------------------------------------
$activity = $db->query("
    SELECT l.id, l.ts, l.level, l.ip, l.message, l.job_id,
           j.target_cidr
    FROM scan_log l
    LEFT JOIN scan_jobs j ON j.id = l.job_id
    WHERE l.level IN ('INFO','WARN','ERR')
    ORDER BY l.id DESC
    LIMIT 25
")->fetchAll();
$activity = array_reverse($activity);

// ---------------------------------------------------------------------------
// Change detection: new hosts, port changes, gone hosts vs previous scan
// ---------------------------------------------------------------------------
$prev_scan = $db->query("
    SELECT id FROM scan_jobs WHERE status='done' ORDER BY id DESC LIMIT 1 OFFSET 1
")->fetchColumn();

$changes = ['new_hosts' => [], 'changed_ports' => [], 'gone_hosts' => []];

if ($prev_scan) {
    // New hosts: first_seen after the previous scan started
    $prev_started = $db->prepare("SELECT started_at FROM scan_jobs WHERE id=?");
    $prev_started->execute([$prev_scan]);
    $prev_ts = $prev_started->fetchColumn();

    if ($prev_ts) {
        $new_hosts_raw = $db->prepare("
            SELECT ip, hostname, category, vendor, first_seen
            FROM assets WHERE first_seen > ?
            ORDER BY first_seen DESC LIMIT 20
        ");
        $new_hosts_raw->execute([$prev_ts]);
        $changes['new_hosts'] = $new_hosts_raw->fetchAll();

        // Port changes: assets whose port_history has > 1 record since prev scan
        $changed_ports_raw = $db->query("
            SELECT DISTINCT a.ip, a.hostname, a.category,
                   ph.ports AS current_ports, ph.seen_at
            FROM port_history ph
            JOIN assets a ON a.id = ph.asset_id
            WHERE ph.seen_at > '$prev_ts'
              AND ph.asset_id IN (
                  SELECT asset_id FROM port_history WHERE seen_at <= '$prev_ts' LIMIT 500
              )
            ORDER BY ph.seen_at DESC LIMIT 20
        ")->fetchAll();
        foreach ($changed_ports_raw as &$cp) {
            $cp['current_ports'] = json_decode($cp['current_ports'] ?? '[]', true) ?: [];
        }
        unset($cp);
        $changes['changed_ports'] = $changed_ports_raw;
    }
}

// NVD sync status
$nvd_sync = st_config('nvd_last_sync', 'never');
$oui_sync = st_config('oui_last_sync', 'never');
$webfp_sync = st_config('webfp_last_sync', 'never');
$oui_count = (int)st_config('oui_prefix_count', '0');
$webfp_count = (int)st_config('webfp_rule_count', '0');

st_json([
    'assets' => [
        'total'        => $total_assets,
        'unclassified' => $unclassified,
        'new_24h'      => $new_assets,
        'by_category'  => $by_category,
    ],
    'findings' => [
        'open'        => $open_findings,
        'by_severity' => $by_severity,
    ],
    'last_scan'      => $last_scan,
    'scan_history'   => $scan_history,
    'top_vulnerable' => $top_vulnerable,
    'activity'       => $activity,
    'changes'        => $changes,
    'nvd_last_sync'  => $nvd_sync,
    'oui_last_sync'  => $oui_sync,
    'webfp_last_sync'=> $webfp_sync,
    'oui_prefix_count' => $oui_count,
    'webfp_rule_count' => $webfp_count,
    'server_time'    => date('c'),
]);
