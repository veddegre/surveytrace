<?php
/**
 * SurveyTrace — GET /api/scan_history.php
 *
 * Query params:
 *   - id: optional scan job id for full detail
 *   - limit: list size when id is omitted (default 50, max 200)
 */

require_once __DIR__ . '/db.php';
st_auth();
st_method('GET');

$db = st_db();
$id = st_int('id', 0, 0);
$limit = st_int('limit', 50, 1, 200);

// Ensure history columns exist for older DBs
$scanJobCols = array_column($db->query("PRAGMA table_info(scan_jobs)")->fetchAll(), 'name');
$scanJobMigrations = [
    'scan_mode'   => "TEXT DEFAULT 'auto'",
    'profile'     => "TEXT DEFAULT 'standard_inventory'",
    'priority'    => "INTEGER DEFAULT 10",
    'retry_count' => "INTEGER DEFAULT 0",
    'summary_json'=> "TEXT",
];
foreach ($scanJobMigrations as $col => $defn) {
    if (!in_array($col, $scanJobCols, true)) {
        $db->exec("ALTER TABLE scan_jobs ADD COLUMN $col $defn");
    }
}

if ($id > 0) {
    $stmt = $db->prepare("
        SELECT id, status, target_cidr, label, exclusions, phases, rate_pps, inter_delay,
               created_at, started_at, finished_at, hosts_found, hosts_scanned,
               error_msg, COALESCE(profile, 'standard_inventory') AS profile,
               COALESCE(scan_mode, 'auto') AS scan_mode,
               COALESCE(priority, 10) AS priority,
               COALESCE(retry_count, 0) AS retry_count,
               summary_json,
               CAST((julianday(COALESCE(finished_at,'now')) - julianday(COALESCE(started_at, created_at))) * 86400 AS INTEGER) AS duration_secs
        FROM scan_jobs
        WHERE id = ?
        LIMIT 1
    ");
    $stmt->execute([$id]);
    $job = $stmt->fetch();
    if (!$job) {
        st_json(['error' => "Job #$id not found"], 404);
    }

    $job['phases'] = json_decode((string)($job['phases'] ?? '[]'), true) ?: [];
    $job['summary'] = json_decode((string)($job['summary_json'] ?? ''), true) ?: null;
    unset($job['summary_json']);

    $assetsStmt = $db->prepare("
        SELECT id, ip, hostname, category, vendor, top_cve, top_cvss, open_ports
        FROM assets
        WHERE last_scan_id = ?
        ORDER BY ip ASC
        LIMIT 200
    ");
    $assetsStmt->execute([$id]);
    $assets = array_map(function($a) {
        $a['open_ports'] = json_decode((string)($a['open_ports'] ?? '[]'), true) ?: [];
        return $a;
    }, $assetsStmt->fetchAll());

    $logStmt = $db->prepare("
        SELECT id, ts, level, ip, message
        FROM scan_log
        WHERE job_id = ?
        ORDER BY id DESC
        LIMIT 80
    ");
    $logStmt->execute([$id]);
    $logTail = array_reverse($logStmt->fetchAll());

    st_json([
        'ok' => true,
        'job' => $job,
        'assets' => $assets,
        'log_tail' => $logTail,
    ]);
}

$rows = $db->prepare("
    SELECT id, status, target_cidr, label, hosts_found, hosts_scanned,
           created_at, started_at, finished_at, error_msg,
           COALESCE(profile, 'standard_inventory') AS profile,
           COALESCE(scan_mode, 'auto') AS scan_mode,
           COALESCE(priority, 10) AS priority,
           COALESCE(retry_count, 0) AS retry_count,
           summary_json,
           CAST((julianday(COALESCE(finished_at,'now')) - julianday(COALESCE(started_at, created_at))) * 86400 AS INTEGER) AS duration_secs
    FROM scan_jobs
    ORDER BY id DESC
    LIMIT ?
");
$rows->bindValue(1, $limit, PDO::PARAM_INT);
$rows->execute();

$history = array_map(function($r) {
    $r['summary'] = json_decode((string)($r['summary_json'] ?? ''), true) ?: null;
    unset($r['summary_json']);
    $r['priority'] = (int)($r['priority'] ?? 10);
    $r['retry_count'] = (int)($r['retry_count'] ?? 0);
    return $r;
}, $rows->fetchAll());

st_json([
    'ok' => true,
    'history' => $history,
]);
