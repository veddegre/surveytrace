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
st_require_role(['viewer', 'scan_editor', 'admin']);
st_method('GET');

$db = st_db();
$trend_days = isset($_GET['trend_days']) ? (int)$_GET['trend_days'] : 14;
if (!in_array($trend_days, [7, 14, 30], true)) $trend_days = 14;
$trend_start_offset = '-' . max(0, $trend_days - 1) . ' days';
$prev_window_start_offset = '-' . max(0, ($trend_days * 2) - 1) . ' days';
$prev_window_end_offset = '-' . $trend_days . ' days';

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
// Executive metrics/trends (last 14 days)
// ---------------------------------------------------------------------------
$assets_new_7d = (int)$db->query(
    "SELECT COUNT(*) FROM assets WHERE first_seen >= datetime('now','-7 days')"
)->fetchColumn();
$findings_new_7d = (int)$db->query(
    "SELECT COUNT(*) FROM findings WHERE confirmed_at IS NOT NULL AND confirmed_at >= datetime('now','-7 days')"
)->fetchColumn();
$scans_7d = (int)$db->query(
    "SELECT COUNT(*) FROM scan_jobs WHERE created_at >= datetime('now','-7 days')"
)->fetchColumn();
$scan_fail_7d = (int)$db->query(
    "SELECT COUNT(*) FROM scan_jobs WHERE created_at >= datetime('now','-7 days') AND status IN ('failed','aborted')"
)->fetchColumn();
$scan_done_7d = (int)$db->query(
    "SELECT COUNT(*) FROM scan_jobs WHERE created_at >= datetime('now','-7 days') AND status = 'done'"
)->fetchColumn();
$avg_scan_duration_7d = (int)$db->query("
    SELECT COALESCE(AVG(
        CAST((julianday(COALESCE(finished_at,'now')) - julianday(COALESCE(started_at, created_at))) * 86400 AS INTEGER)
    ), 0)
    FROM scan_jobs
    WHERE status = 'done' AND created_at >= datetime('now','-7 days')
")->fetchColumn();
$scan_sla_7d = (int)$db->query("
    SELECT COUNT(*)
    FROM scan_jobs
    WHERE status = 'done'
      AND created_at >= datetime('now','-7 days')
      AND CAST((julianday(COALESCE(finished_at,'now')) - julianday(COALESCE(started_at, created_at))) * 86400 AS INTEGER) <= 3600
")->fetchColumn();
$completion_rate_14d = (int)$db->query("
    SELECT CASE WHEN COUNT(*) = 0 THEN 0
           ELSE ROUND(100.0 * SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) / COUNT(*))
           END
    FROM scan_jobs
    WHERE created_at >= datetime('now','-14 days')
")->fetchColumn();

$trend_rows = $db->query("
    WITH RECURSIVE days(d) AS (
      SELECT date('now', '$trend_start_offset')
      UNION ALL
      SELECT date(d, '+1 day') FROM days WHERE d < date('now')
    )
    SELECT
      d AS day,
      (SELECT COUNT(*) FROM assets a WHERE date(a.first_seen) = d) AS assets_new,
      (SELECT COUNT(*) FROM findings f WHERE f.confirmed_at IS NOT NULL AND date(f.confirmed_at) = d) AS findings_new,
      (SELECT COUNT(*) FROM findings f WHERE f.confirmed_at IS NOT NULL AND date(f.confirmed_at) = d AND lower(f.severity) = 'critical') AS findings_critical_new,
      (SELECT COUNT(*) FROM findings f WHERE f.confirmed_at IS NOT NULL AND date(f.confirmed_at) = d AND lower(f.severity) = 'high') AS findings_high_new,
      (SELECT COUNT(*) FROM scan_jobs s WHERE date(s.created_at) = d) AS scans_total,
      (SELECT COUNT(*) FROM scan_jobs s WHERE date(s.created_at) = d AND s.status = 'done') AS scans_done,
      (SELECT COUNT(*) FROM scan_jobs s WHERE date(s.created_at) = d AND s.status IN ('failed','aborted')) AS scans_failed
    FROM days
    ORDER BY d ASC
")->fetchAll();

// Executive period-over-period comparison (current window vs previous same-sized window)
$curr_assets_new = (int)$db->query("
    SELECT COUNT(*) FROM assets
    WHERE first_seen >= date('now', '$trend_start_offset')
      AND first_seen < date('now', '+1 day')
")->fetchColumn();
$prev_assets_new = (int)$db->query("
    SELECT COUNT(*) FROM assets
    WHERE first_seen >= date('now', '$prev_window_start_offset')
      AND first_seen < date('now', '$prev_window_end_offset')
")->fetchColumn();

$curr_findings_new = (int)$db->query("
    SELECT COUNT(*) FROM findings
    WHERE confirmed_at IS NOT NULL
      AND confirmed_at >= date('now', '$trend_start_offset')
      AND confirmed_at < date('now', '+1 day')
")->fetchColumn();
$prev_findings_new = (int)$db->query("
    SELECT COUNT(*) FROM findings
    WHERE confirmed_at IS NOT NULL
      AND confirmed_at >= date('now', '$prev_window_start_offset')
      AND confirmed_at < date('now', '$prev_window_end_offset')
")->fetchColumn();

$curr_scans_total = (int)$db->query("
    SELECT COUNT(*) FROM scan_jobs
    WHERE created_at >= date('now', '$trend_start_offset')
      AND created_at < date('now', '+1 day')
")->fetchColumn();
$curr_scans_done = (int)$db->query("
    SELECT COUNT(*) FROM scan_jobs
    WHERE status='done'
      AND created_at >= date('now', '$trend_start_offset')
      AND created_at < date('now', '+1 day')
")->fetchColumn();
$prev_scans_total = (int)$db->query("
    SELECT COUNT(*) FROM scan_jobs
    WHERE created_at >= date('now', '$prev_window_start_offset')
      AND created_at < date('now', '$prev_window_end_offset')
")->fetchColumn();
$prev_scans_done = (int)$db->query("
    SELECT COUNT(*) FROM scan_jobs
    WHERE status='done'
      AND created_at >= date('now', '$prev_window_start_offset')
      AND created_at < date('now', '$prev_window_end_offset')
")->fetchColumn();

$curr_critical_new = (int)$db->query("
    SELECT COUNT(*) FROM findings
    WHERE confirmed_at IS NOT NULL
      AND lower(severity)='critical'
      AND confirmed_at >= date('now', '$trend_start_offset')
      AND confirmed_at < date('now', '+1 day')
")->fetchColumn();
$curr_high_new = (int)$db->query("
    SELECT COUNT(*) FROM findings
    WHERE confirmed_at IS NOT NULL
      AND lower(severity)='high'
      AND confirmed_at >= date('now', '$trend_start_offset')
      AND confirmed_at < date('now', '+1 day')
")->fetchColumn();
$prev_critical_new = (int)$db->query("
    SELECT COUNT(*) FROM findings
    WHERE confirmed_at IS NOT NULL
      AND lower(severity)='critical'
      AND confirmed_at >= date('now', '$prev_window_start_offset')
      AND confirmed_at < date('now', '$prev_window_end_offset')
")->fetchColumn();
$prev_high_new = (int)$db->query("
    SELECT COUNT(*) FROM findings
    WHERE confirmed_at IS NOT NULL
      AND lower(severity)='high'
      AND confirmed_at >= date('now', '$prev_window_start_offset')
      AND confirmed_at < date('now', '$prev_window_end_offset')
")->fetchColumn();

$curr_risk_pressure = ($curr_critical_new * 5) + ($curr_high_new * 3);
$prev_risk_pressure = ($prev_critical_new * 5) + ($prev_high_new * 3);
$curr_completion_rate = $curr_scans_total > 0 ? (int)round(($curr_scans_done * 100.0) / $curr_scans_total) : 0;
$prev_completion_rate = $prev_scans_total > 0 ? (int)round(($prev_scans_done * 100.0) / $prev_scans_total) : 0;

$delta = function(int $curr, int $prev): array {
    if ($prev === 0) {
        return ['abs' => $curr - $prev, 'pct' => null];
    }
    return ['abs' => $curr - $prev, 'pct' => round((($curr - $prev) * 100.0) / $prev, 1)];
};

$summary_bullets = [];
$summary_bullets[] = "Overall risk trend is " . ($curr_risk_pressure > $prev_risk_pressure ? "rising" : ($curr_risk_pressure < $prev_risk_pressure ? "improving" : "stable")) .
    " (" . $curr_risk_pressure . " vs " . $prev_risk_pressure . " in the prior " . $trend_days . "-day period).";
$summary_bullets[] = "Scan success rate is " . $curr_completion_rate . "% (" . $curr_scans_done . " of " . $curr_scans_total . " scans completed).";
$summary_bullets[] = "New issues identified this period: " . $curr_findings_new . " total (" . $curr_critical_new . " critical, " . $curr_high_new . " high).";

// Optional AI summary from the latest completed run summary_json
$exec_ai_summary = null;
$exec_ai_scan_meta = null;
try {
    $row = $db->query("
        SELECT id, label, summary_json
        FROM scan_jobs
        WHERE status = 'done'
          AND summary_json IS NOT NULL
          AND summary_json != ''
        ORDER BY id DESC
        LIMIT 1
    ")->fetch(PDO::FETCH_ASSOC);
    if (is_array($row) && is_string($row['summary_json'] ?? null) && trim((string)$row['summary_json']) !== '') {
        $rawSj = (string)$row['summary_json'];
        $sj = json_decode($rawSj, true);
        if (!is_array($sj)) {
            $sj = json_decode($rawSj, true, 512, JSON_INVALID_UTF8_SUBSTITUTE);
        }
        if (is_array($sj)) {
            $exec_ai_scan_meta = [
                'job_id' => (int)($row['id'] ?? 0),
                'label' => (string)($row['label'] ?? ''),
                'ai_enrichment_attempts' => (int)($sj['ai_enrichment_attempts'] ?? 0),
                'ai_enrichment_applied' => (int)($sj['ai_enrichment_applied'] ?? 0),
                'ai_reason_counts' => is_array($sj['ai_reason_counts'] ?? null) ? $sj['ai_reason_counts'] : [],
                'ai_scan_summary_status' => (string)($sj['ai_scan_summary_status'] ?? ''),
                'ai_scan_summary_detail' => (string)($sj['ai_scan_summary_detail'] ?? ''),
            ];
            if (isset($sj['ai_summary']) && is_array($sj['ai_summary'])) {
                $ov = trim((string)($sj['ai_summary']['overview'] ?? ''));
                $cc = array_values(array_filter(array_map('strval', (array)($sj['ai_summary']['concerns'] ?? []))));
                $ns = array_values(array_filter(array_map('strval', (array)($sj['ai_summary']['next_steps'] ?? []))));
                $exec_ai_summary = [
                    'overview' => $ov,
                    'concerns' => array_slice($cc, 0, 5),
                    'next_steps' => array_slice($ns, 0, 5),
                ];
            }
        }
    }
} catch (Throwable $e) {
    $exec_ai_summary = null;
    $exec_ai_scan_meta = null;
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
    'executive'      => [
        'kpis' => [
            'assets_total' => $total_assets,
            'assets_new_7d' => $assets_new_7d,
            'open_findings' => $open_findings,
            'critical_open' => (int)($by_severity['critical'] ?? 0),
            'high_open' => (int)($by_severity['high'] ?? 0),
            'findings_new_7d' => $findings_new_7d,
            'scans_7d' => $scans_7d,
            'scan_fail_7d' => $scan_fail_7d,
            'scan_done_7d' => $scan_done_7d,
            'completion_rate_14d' => $completion_rate_14d,
            'avg_scan_duration_7d_sec' => $avg_scan_duration_7d,
            'scan_sla_7d' => $scan_sla_7d,
        ],
        'severity_open' => $by_severity,
        'trend_14d' => array_map(function($r) {
            $critical = (int)$r['findings_critical_new'];
            $high = (int)$r['findings_high_new'];
            $risk_pressure = ($critical * 5) + ($high * 3);
            return [
                'day' => $r['day'],
                'assets_new' => (int)$r['assets_new'],
                'findings_new' => (int)$r['findings_new'],
                'findings_critical_new' => $critical,
                'findings_high_new' => $high,
                'scans_total' => (int)$r['scans_total'],
                'scans_done' => (int)$r['scans_done'],
                'scans_failed' => (int)$r['scans_failed'],
                'risk_pressure' => $risk_pressure,
            ];
        }, $trend_rows),
        'trend_days' => $trend_days,
        'top_risky' => $top_vulnerable,
        'comparison' => [
            'window_days' => $trend_days,
            'assets_new' => ['current' => $curr_assets_new, 'previous' => $prev_assets_new, 'delta' => $delta($curr_assets_new, $prev_assets_new)],
            'findings_new' => ['current' => $curr_findings_new, 'previous' => $prev_findings_new, 'delta' => $delta($curr_findings_new, $prev_findings_new)],
            'risk_pressure' => ['current' => $curr_risk_pressure, 'previous' => $prev_risk_pressure, 'delta' => $delta($curr_risk_pressure, $prev_risk_pressure)],
            'completion_rate' => ['current' => $curr_completion_rate, 'previous' => $prev_completion_rate, 'delta' => $delta($curr_completion_rate, $prev_completion_rate)],
        ],
        'brief' => $summary_bullets,
        'ai_scan_summary' => $exec_ai_summary,
        'ai_scan_meta' => $exec_ai_scan_meta,
    ],
]);
