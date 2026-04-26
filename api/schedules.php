<?php
/**
 * SurveyTrace — /api/schedules.php
 *
 * GET    /api/schedules.php              — list all schedules
 * GET    /api/schedules.php?history=1&id=N&limit=20 — last N jobs for a schedule
 * POST   /api/schedules.php              — create or update a schedule
 * DELETE /api/schedules.php?id=N         — delete a schedule
 * POST   /api/schedules.php?run_now=1    — immediately enqueue a job
 * POST   /api/schedules.php?toggle=1    — enable/disable a schedule
 * POST   /api/schedules.php?pause=1     — pause (stops cron; keeps config)
 * POST   /api/schedules.php?resume=1     — resume after pause
 */

// Always work in UTC regardless of server timezone
date_default_timezone_set('UTC');

require_once __DIR__ . '/db.php';
st_auth();

$db = st_db();

// Auto-create table if missing
$db->exec("
    CREATE TABLE IF NOT EXISTS scan_schedules (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        name               TEXT NOT NULL,
        enabled            INTEGER DEFAULT 1,
        paused             INTEGER DEFAULT 0,
        cron_expr          TEXT NOT NULL,
        target_cidr        TEXT NOT NULL,
        exclusions         TEXT DEFAULT '',
        phases             TEXT DEFAULT '[\"passive\",\"icmp\",\"banner\",\"fingerprint\",\"cve\"]',
        profile            TEXT DEFAULT 'standard_inventory',
        scan_mode          TEXT DEFAULT 'auto',
        rate_pps           INTEGER DEFAULT 5,
        inter_delay        INTEGER DEFAULT 200,
        priority           INTEGER DEFAULT 20,
        next_run           DATETIME,
        last_run           DATETIME,
        last_job_id        INTEGER DEFAULT 0,
        last_status        TEXT DEFAULT '',
        collector_id       INTEGER DEFAULT 0,
        created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
        notes              TEXT DEFAULT '',
        timezone           TEXT DEFAULT 'UTC',
        missed_run_policy  TEXT DEFAULT 'run_once',
        missed_run_max     INTEGER DEFAULT 5
    )
");

/** Add columns introduced after first deploy (SQLite). */
$schedCols = array_column($db->query('PRAGMA table_info(scan_schedules)')->fetchAll(), 'name');
$schedMigrations = [
    'timezone'          => "TEXT DEFAULT 'UTC'",
    'paused'            => 'INTEGER DEFAULT 0',
    'missed_run_policy' => "TEXT DEFAULT 'run_once'",
    'missed_run_max'    => 'INTEGER DEFAULT 5',
];
foreach ($schedMigrations as $col => $def) {
    if (!in_array($col, $schedCols, true)) {
        $db->exec('ALTER TABLE scan_schedules ADD COLUMN ' . $col . ' ' . $def);
    }
}

$method = $_SERVER['REQUEST_METHOD'];

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------
if ($method === 'DELETE') {
    $id = (int)($_GET['id'] ?? 0);
    if (!$id) st_json(['error' => 'id required'], 400);
    $db->prepare("DELETE FROM scan_schedules WHERE id=?")->execute([$id]);
    st_json(['ok' => true]);
}

// ---------------------------------------------------------------------------
// GET — list schedules with last job status
// ---------------------------------------------------------------------------
if ($method === 'GET') {
    if (isset($_GET['history'])) {
        $hid = (int)($_GET['id'] ?? 0);
        $limit = max(1, min(100, (int)($_GET['limit'] ?? 20)));
        if (!$hid) {
            st_json(['error' => 'id required'], 400);
        }
        $h = $db->prepare("
            SELECT id, status, label, created_at, started_at, finished_at,
                   hosts_found, hosts_scanned, error_msg, created_by
            FROM scan_jobs
            WHERE schedule_id = ?
            ORDER BY id DESC
            LIMIT $limit
        ");
        $h->execute([$hid]);
        st_json(['runs' => $h->fetchAll()]);
    }

    $rows = $db->query("
        SELECT s.*,
            j.status AS last_job_status,
            j.hosts_found AS last_hosts_found,
            j.finished_at AS last_finished_at,
            CASE
                WHEN s.next_run IS NULL THEN NULL
                WHEN s.next_run <= datetime('now') THEN 0
                ELSE CAST((julianday(s.next_run) - julianday('now')) * 86400 AS INTEGER)
            END AS secs_until_next
        FROM scan_schedules s
        LEFT JOIN scan_jobs j ON j.id = s.last_job_id
        ORDER BY s.enabled DESC, COALESCE(s.paused, 0) ASC, s.next_run ASC
    ")->fetchAll();
    st_json(['schedules' => $rows]);
}

// ---------------------------------------------------------------------------
// POST
// ---------------------------------------------------------------------------
st_method('POST');
$body = st_input();

// Run now — enqueue job immediately
if (isset($_GET['run_now'])) {
    $id = (int)($body['id'] ?? 0);
    if (!$id) st_json(['error' => 'id required'], 400);
    $stmt = $db->prepare("SELECT * FROM scan_schedules WHERE id=?");
    $stmt->execute([$id]);
    $s = $stmt->fetch();
    if (!$s) st_json(['error' => 'Schedule not found'], 404);

    $db->prepare("
        INSERT INTO scan_jobs
            (target_cidr, label, exclusions, phases, rate_pps, inter_delay,
             scan_mode, profile, priority, schedule_id, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'web')
    ")->execute([
        $s['target_cidr'],
        '[Scheduled] ' . $s['name'] . ' (manual)',
        $s['exclusions'] ?: '',
        $s['phases'],
        $s['rate_pps'] ?: 5,
        $s['inter_delay'] ?: 200,
        $s['scan_mode'] ?: 'auto',
        $s['profile'] ?: 'standard_inventory',
        5,   // higher priority than scheduled runs for manual trigger
        $id,
    ]);
    $job_id = (int)$db->lastInsertId();

    // Update last_job_id
    $db->prepare("UPDATE scan_schedules SET last_job_id=?, last_run=datetime('now') WHERE id=?")
       ->execute([$job_id, $id]);

    st_json(['ok' => true, 'job_id' => $job_id]);
}

// Pause — keeps schedule row and settings; cron firing stops until resume
if (isset($_GET['pause'])) {
    $id = (int)($body['id'] ?? 0);
    if (!$id) {
        st_json(['error' => 'id required'], 400);
    }
    $db->prepare('UPDATE scan_schedules SET paused = 1 WHERE id = ?')->execute([$id]);
    st_json(['ok' => true, 'paused' => true]);
}

// Resume after pause (does not change enabled flag)
if (isset($_GET['resume'])) {
    $id = (int)($body['id'] ?? 0);
    if (!$id) {
        st_json(['error' => 'id required'], 400);
    }
    $nr = gmdate('Y-m-d H:i:s', time() + 60);
    $db->prepare("
        UPDATE scan_schedules SET paused = 0,
            next_run = CASE
                WHEN next_run IS NULL OR datetime(next_run) <= datetime('now')
                THEN ?
                ELSE next_run
            END
        WHERE id = ?
    ")->execute([$nr, $id]);
    st_json(['ok' => true, 'paused' => false]);
}

// Toggle enable/disable
if (isset($_GET['toggle'])) {
    $id = (int)($body['id'] ?? 0);
    if (!$id) st_json(['error' => 'id required'], 400);
    $db->prepare("UPDATE scan_schedules SET enabled = 1-enabled WHERE id=?")->execute([$id]);
    $row = $db->prepare("SELECT id, enabled FROM scan_schedules WHERE id=?");
    $row->execute([$id]);
    st_json(['ok' => true, 'enabled' => (bool)$row->fetchColumn(1)]);
}

// Create or update
$id          = (int)($body['id'] ?? 0);
$name        = substr(trim($body['name'] ?? ''), 0, 100);
$cron_expr   = trim($body['cron_expr'] ?? '');
$target_cidr = trim($body['target_cidr'] ?? '');
$exclusions  = trim($body['exclusions'] ?? '');
$profile     = $body['profile'] ?? 'standard_inventory';
$scan_mode   = $body['scan_mode'] ?? 'auto';
$rate_pps    = max(1, min(100, (int)($body['rate_pps'] ?? 5)));
$inter_delay = max(0, min(2000, (int)($body['inter_delay'] ?? 200)));
$priority    = max(1, min(100, (int)($body['priority'] ?? 20)));
$enabled     = (int)($body['enabled'] ?? 1);
$has_paused  = array_key_exists('paused', $body);
$paused      = $has_paused ? (int)$body['paused'] : null;
$notes       = substr(trim($body['notes'] ?? ''), 0, 500);
$timezone    = trim($body['timezone'] ?? 'UTC');
// Validate timezone
if (!in_array($timezone, timezone_identifiers_list())) {
    $timezone = 'UTC';
}

$missed_run_policy = trim($body['missed_run_policy'] ?? 'run_once');
$allowedPolicies = ['run_once', 'skip_no_run', 'run_all'];
if (!in_array($missed_run_policy, $allowedPolicies, true)) {
    $missed_run_policy = 'run_once';
}
$missed_run_max = max(1, min(100, (int)($body['missed_run_max'] ?? 5)));

$phases_raw  = $body['phases'] ?? ["passive","icmp","banner","fingerprint","cve"];
$phases      = json_encode(is_array($phases_raw) ? $phases_raw : json_decode($phases_raw, true));

if (!$name)        st_json(['error' => 'name is required'],        400);
if (!$cron_expr)   st_json(['error' => 'cron_expr is required'],   400);
if (!$target_cidr) st_json(['error' => 'target_cidr is required'], 400);

// Validate cron expression (basic check — 5 fields or @preset)
$presets = ['@yearly','@annually','@monthly','@weekly','@daily','@midnight','@hourly'];
if (!in_array($cron_expr, $presets)) {
    $parts = preg_split('/\s+/', trim($cron_expr));
    if (count($parts) !== 5) {
        st_json(['error' => 'cron_expr must be 5 fields (min hr dom mon dow) or a @preset'], 400);
    }
}

// Compute approximate next_run using current time
// The scheduler daemon will refine this on its next poll
// For common presets we can compute it simply
$presets = [
    '@hourly'   => 'PT1H',
    '@daily'    => 'P1D',
    '@midnight' => 'P1D',
    '@weekly'   => 'P7D',
    '@monthly'  => 'P1M',
];
// Set next_run to 1 minute from now (UTC) so scheduler picks it up quickly
// date_default_timezone_set('UTC') is set at top of file so date() is UTC
$next_run = gmdate('Y-m-d H:i:s', time() + 60);

if ($id > 0) {
    $db->prepare("
        UPDATE scan_schedules SET
            name=?, cron_expr=?, target_cidr=?, exclusions=?, phases=?,
            profile=?, scan_mode=?, rate_pps=?, inter_delay=?, priority=?,
            enabled=?, paused=COALESCE(?, paused), notes=?, timezone=?,
            missed_run_policy=?, missed_run_max=?,
            next_run=COALESCE(next_run, ?)
        WHERE id=?
    ")->execute([
        $name, $cron_expr, $target_cidr, $exclusions, $phases,
        $profile, $scan_mode, $rate_pps, $inter_delay, $priority,
        $enabled, $paused, $notes, $timezone,
        $missed_run_policy, $missed_run_max,
        $next_run, $id
    ]);
} else {
    $db->prepare("
        INSERT INTO scan_schedules
            (name, cron_expr, target_cidr, exclusions, phases, profile,
             scan_mode, rate_pps, inter_delay, priority, enabled, paused, notes, timezone,
             missed_run_policy, missed_run_max, next_run)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ")->execute([
        $name, $cron_expr, $target_cidr, $exclusions, $phases, $profile,
        $scan_mode, $rate_pps, $inter_delay, $priority, $enabled, (int)($paused ?? 0), $notes, $timezone,
        $missed_run_policy, $missed_run_max, $next_run
    ]);
    $id = (int)$db->lastInsertId();
}

$stmt2 = $db->prepare("SELECT * FROM scan_schedules WHERE id=?");
$stmt2->execute([$id]);
st_json(['ok' => true, 'schedule' => $stmt2->fetch()]);
