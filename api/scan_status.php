<?php
/**
 * SurveyTrace — GET /api/scan_status.php
 *
 * Returns the current state of a scan job plus a paginated tail of the
 * audit log. Designed to be polled every 2–3 seconds from the UI.
 *
 * Query params:
 *   job_id       — specific job ID; omit for the most recent job
 *   since_log_id — return only log rows with id > this value (cursor pagination)
 *   log_limit    — max log rows to return per poll (default 80, max 200)
 *
 * Response:
 * {
 *   "job": {
 *     "id", "status", "target_cidr", "label",
 *     "phases",            // decoded JSON array
 *     "rate_pps", "inter_delay",
 *     "created_at", "started_at", "finished_at",
 *     "hosts_found", "hosts_scanned",
 *     "progress_pct",      // computed 0–100
 *     "elapsed_secs",      // seconds since started_at
 *     "error_msg"
 *   },
 *   "log": [
 *     {"id", "ts", "level", "ip", "message"}
 *   ],
 *   "last_log_id": N       // use as since_log_id on next poll
 * }
 */

require_once __DIR__ . '/db.php';
st_auth();
st_method('GET');

$db        = st_db();
$job_id    = st_int('job_id');
$since     = st_int('since_log_id');
$log_limit = st_int('log_limit', 80, 1, 200);

// Ensure newer scan_jobs columns exist for legacy DBs
$scanJobCols = array_column($db->query("PRAGMA table_info(scan_jobs)")->fetchAll(), 'name');
$scanJobMigrations = [
    'scan_mode'  => "TEXT DEFAULT 'auto'",
    'profile'    => "TEXT DEFAULT 'standard_inventory'",
    'priority'   => "INTEGER DEFAULT 10",
    'retry_count'=> "INTEGER DEFAULT 0",
    'summary_json'=> "TEXT",
];
foreach ($scanJobMigrations as $col => $defn) {
    if (!in_array($col, $scanJobCols, true)) {
        $db->exec("ALTER TABLE scan_jobs ADD COLUMN $col $defn");
    }
}

// ---------------------------------------------------------------------------
// Fetch job row
// ---------------------------------------------------------------------------
if ($job_id > 0) {
    $jstmt = $db->prepare("SELECT * FROM scan_jobs WHERE id = ?");
    $jstmt->execute([$job_id]);
    $job = $jstmt->fetch();
    if (!$job) {
        st_json(['error' => "Job #$job_id not found"], 404);
    }
} else {
    // Most recent job of any status
    $job = $db->query("SELECT * FROM scan_jobs ORDER BY id DESC LIMIT 1")->fetch();
}

if (!$job) {
    st_json(['job' => null, 'log' => [], 'last_log_id' => 0]);
}

// ---------------------------------------------------------------------------
// Enrich job row
// ---------------------------------------------------------------------------
$job['phases'] = json_decode($job['phases'] ?? '[]', true) ?: [];

// Progress percentage
$found   = max(1, (int)$job['hosts_found']);
$scanned = (int)$job['hosts_scanned'];

// Progress: phases contribute different weights
// passive(5) + icmp(10) + banner(60) + cve(25) = 100
// During banner phase hosts_scanned reflects batch progress
$phase_progress = 0;
if ($job['status'] === 'running') {
    $phases = $job['phases'];
    if ($found > 0 && $scanned > 0) {
        // We have scanned hosts — use ratio
        $phase_progress = (int)min(99, ($scanned / $found) * 100);
    } elseif ($found > 0) {
        // Found hosts but scanned=0 means we're in passive/icmp/banner phases
        // Show at least 10% so the bar moves
        $phase_progress = 10;
    } else {
        // Still discovering
        $phase_progress = 5;
    }
}

$job['progress_pct'] = match($job['status']) {
    'done'    => 100,
    'aborted',
    'failed'  => $found > 0 ? (int)min(100, ($scanned / $found) * 100) : 0,
    'running' => $phase_progress,
    default   => 0,  // queued
};

// Elapsed time
if ($job['started_at']) {
    $job['elapsed_secs'] = (int)(time() - strtotime($job['started_at']));
} else {
    $job['elapsed_secs'] = 0;
}

// Open CVE count for this job's assets (quick summary)
$job['open_findings'] = (int)$db->query("
    SELECT COUNT(*) FROM findings f
    JOIN assets a ON a.id = f.asset_id
    WHERE f.resolved = 0 AND a.last_scan_id = {$job['id']}
")->fetchColumn();

// Phase display label for UI progress message
$phase_labels = [
    'passive'     => 'Phase 1: passive ARP/mDNS discovery…',
    'icmp'        => 'Phase 2: ICMP/ARP sweep…',
    'banner'      => 'Phase 3: port & banner grab…',
    'fingerprint' => 'Phase 3: service fingerprinting…',
    'snmp'        => 'Phase 3: SNMP enumeration…',
    'ot'          => 'Phase 3: OT protocol probes…',
    'cve'         => 'Phase 4: CVE correlation…',
];
$job['phase_labels'] = $phase_labels;

// ---------------------------------------------------------------------------
// Audit log tail (cursor-based so the UI only receives new lines)
// ---------------------------------------------------------------------------
$lstmt = $db->prepare("
    SELECT id, ts, level, ip, message
    FROM scan_log
    WHERE job_id = :jid
      AND id > :since
    ORDER BY id ASC
    LIMIT :lim
");
$lstmt->bindValue(':jid',   $job['id'],  PDO::PARAM_INT);
$lstmt->bindValue(':since', $since,      PDO::PARAM_INT);
$lstmt->bindValue(':lim',   $log_limit,  PDO::PARAM_INT);
$lstmt->execute();
$log_rows = $lstmt->fetchAll();

$last_log_id = $since;
if (!empty($log_rows)) {
    $last_log_id = (int)end($log_rows)['id'];
}

// Total log line count for this job
$job['total_log_lines'] = (int)$db->prepare(
    "SELECT COUNT(*) FROM scan_log WHERE job_id = ?"
)->execute([$job['id']]) ? $db->prepare(
    "SELECT COUNT(*) FROM scan_log WHERE job_id = ?"
)->execute([$job['id']]) && false : 0;

// Re-query cleanly for the count
$cstmt = $db->prepare("SELECT COUNT(*) FROM scan_log WHERE job_id = ?");
$cstmt->execute([$job['id']]);
$job['total_log_lines'] = (int)$cstmt->fetchColumn();

// ---------------------------------------------------------------------------
// Job history — all jobs for the UI (queue panel + history panel)
// ---------------------------------------------------------------------------
$history = $db->query("
    SELECT id, status, target_cidr, label, hosts_found, hosts_scanned,
           created_at, started_at, finished_at, error_msg, summary_json,
           COALESCE(profile, 'standard_inventory') AS profile,
           COALESCE(scan_mode, 'auto') AS scan_mode,
           COALESCE(priority, 10) AS priority,
           CAST((julianday(COALESCE(finished_at,'now')) - julianday(COALESCE(started_at, created_at))) * 86400 AS INTEGER) AS duration_secs
    FROM scan_jobs
    ORDER BY id DESC
    LIMIT 30
")->fetchAll();

st_json([
    'job'         => $job,
    'log'         => $log_rows,
    'last_log_id' => $last_log_id,
    'history'     => array_map(function($h) {
        $found   = max(1, (int)($h['hosts_found'] ?? 0));
        $scanned = (int)($h['hosts_scanned'] ?? 0);
        $status  = $h['status'] ?? '';
        $h['progress_pct'] = match($status) {
            'done'    => 100,
            'running' => $found > 0 && $scanned > 0
                ? (int)min(99, ($scanned / $found) * 100)
                : ($found > 0 ? 10 : 5),
            'failed','aborted' => $found > 0
                ? (int)min(100, ($scanned / $found) * 100) : 0,
            default => 0,
        };
        $h['retry_count'] = (int)($h['retry_count'] ?? 0);
        $h['priority']    = (int)($h['priority']    ?? 10);
        $h['profile']     = $h['profile'] ?? 'standard_inventory';
        $h['summary']     = json_decode((string)($h['summary_json'] ?? ''), true) ?: null;
        unset($h['summary_json']);
        return $h;
    }, $history),
]);
