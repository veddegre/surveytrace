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
st_require_role(['viewer', 'scan_editor', 'admin']);

$db = st_db();
$actor = st_current_user();

// Jobs enqueued from schedules reference scan_jobs columns added with manual scans — ensure they exist
$scanJobCols = array_column($db->query('PRAGMA table_info(scan_jobs)')->fetchAll(), 'name');
foreach ([
    'scan_mode'              => "TEXT DEFAULT 'auto'",
    'profile'                => "TEXT DEFAULT 'standard_inventory'",
    'priority'               => "INTEGER DEFAULT 10",
    'retry_count'            => "INTEGER DEFAULT 0",
    'max_retries'            => "INTEGER DEFAULT 2",
    'enrichment_source_ids'  => 'TEXT',
] as $col => $defn) {
    if (!in_array($col, $scanJobCols, true)) {
        $db->exec("ALTER TABLE scan_jobs ADD COLUMN $col $defn");
    }
}

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
        missed_run_max     INTEGER DEFAULT 5,
        enrichment_source_ids TEXT
    )
");

/** Add columns introduced after first deploy (SQLite). */
$schedCols = array_column($db->query('PRAGMA table_info(scan_schedules)')->fetchAll(), 'name');
$schedMigrations = [
    'timezone'          => "TEXT DEFAULT 'UTC'",
    'paused'            => 'INTEGER DEFAULT 0',
    'missed_run_policy' => "TEXT DEFAULT 'run_once'",
    'missed_run_max'    => 'INTEGER DEFAULT 5',
    'enrichment_source_ids' => 'TEXT',
];
foreach ($schedMigrations as $col => $def) {
    if (!in_array($col, $schedCols, true)) {
        $db->exec('ALTER TABLE scan_schedules ADD COLUMN ' . $col . ' ' . $def);
    }
}

$method = $_SERVER['REQUEST_METHOD'];
if (!in_array($method, ['GET', 'POST', 'DELETE'], true)) {
    st_json(['error' => 'method not allowed'], 405);
}

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------
if ($method === 'DELETE') {
    st_require_csrf();
    st_require_role(['scan_editor', 'admin']);
    $id = (int)($_GET['id'] ?? 0);
    if (!$id) st_json(['error' => 'id required'], 400);
    $s = $db->prepare("SELECT id, name FROM scan_schedules WHERE id=? LIMIT 1");
    $s->execute([$id]);
    $row = $s->fetch() ?: null;
    $db->prepare("DELETE FROM scan_schedules WHERE id=?")->execute([$id]);
    st_audit_log('scan.schedule_deleted', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'schedule_id' => $id,
        'name' => (string)($row['name'] ?? ''),
    ]);
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
st_require_role(['scan_editor', 'admin']);
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
             scan_mode, profile, priority, schedule_id, created_by, enrichment_source_ids)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'web', ?)
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
        $s['enrichment_source_ids'] ?? null,
    ]);
    $job_id = (int)$db->lastInsertId();

    // Update last_job_id
    $db->prepare("UPDATE scan_schedules SET last_job_id=?, last_run=datetime('now') WHERE id=?")
       ->execute([$job_id, $id]);
    st_audit_log('scan.schedule_run_now', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'schedule_id' => $id,
        'schedule_name' => (string)($s['name'] ?? ''),
        'job_id' => $job_id,
        'target_cidr' => (string)($s['target_cidr'] ?? ''),
        'profile' => (string)($s['profile'] ?? 'standard_inventory'),
    ]);

    st_json(['ok' => true, 'job_id' => $job_id]);
}

// Pause — keeps schedule row and settings; cron firing stops until resume
if (isset($_GET['pause'])) {
    $id = (int)($body['id'] ?? 0);
    if (!$id) {
        st_json(['error' => 'id required'], 400);
    }
    $db->prepare('UPDATE scan_schedules SET paused = 1 WHERE id = ?')->execute([$id]);
    st_audit_log('scan.schedule_paused', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'schedule_id' => $id,
    ]);
    st_json(['ok' => true, 'paused' => true]);
}

// Resume after pause (does not change enabled flag)
if (isset($_GET['resume'])) {
    $id = (int)($body['id'] ?? 0);
    if (!$id) {
        st_json(['error' => 'id required'], 400);
    }
    // Let scheduler_daemon compute the next real cron fire from next_run=NULL
    // (avoid bogus "now+60s" which ignored the user's cron expression).
    $db->prepare("
        UPDATE scan_schedules SET paused = 0,
            next_run = CASE
                WHEN next_run IS NULL OR datetime(next_run) <= datetime('now')
                THEN NULL
                ELSE next_run
            END
        WHERE id = ?
    ")->execute([$id]);
    st_audit_log('scan.schedule_resumed', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'schedule_id' => $id,
    ]);
    st_json(['ok' => true, 'paused' => false]);
}

// Toggle enable/disable
if (isset($_GET['toggle'])) {
    $id = (int)($body['id'] ?? 0);
    if (!$id) st_json(['error' => 'id required'], 400);
    $db->prepare("UPDATE scan_schedules SET enabled = 1-enabled WHERE id=?")->execute([$id]);
    $row = $db->prepare("SELECT id, enabled FROM scan_schedules WHERE id=?");
    $row->execute([$id]);
    $enabledNow = (bool)$row->fetchColumn(1);
    st_audit_log('scan.schedule_toggled', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'schedule_id' => $id,
        'enabled' => $enabledNow,
    ]);
    st_json(['ok' => true, 'enabled' => $enabledNow]);
}

// Create or update
$id          = (int)($body['id'] ?? 0);
$name        = substr(trim($body['name'] ?? ''), 0, 100);
$cron_expr   = trim($body['cron_expr'] ?? '');
$target_cidr = trim($body['target_cidr'] ?? '');
$exclusions  = trim($body['exclusions'] ?? '');
$valid_profiles = ['iot_safe', 'standard_inventory', 'deep_scan', 'full_tcp', 'fast_full_tcp', 'ot_careful'];
$profile = in_array($body['profile'] ?? '', $valid_profiles, true)
    ? $body['profile']
    : 'standard_inventory';
if (in_array($profile, ['deep_scan', 'full_tcp', 'fast_full_tcp', 'ot_careful'], true)
    && !($body['confirmed'] ?? false)) {
    st_json([
        'error' => "Profile '$profile' requires confirmation. Resend with confirmed:true.",
        'requires_confirmation' => true,
    ], 400);
}
$allowed_modes = ['auto', 'routed', 'force'];
$scan_mode = in_array($body['scan_mode'] ?? '', $allowed_modes, true)
    ? $body['scan_mode']
    : 'auto';
$rate_pps    = max(1, min(50, (int)($body['rate_pps'] ?? 5)));
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

$allowed_phases = ['passive', 'icmp', 'banner', 'fingerprint', 'snmp', 'ot', 'cve'];
$default_phases = ['passive', 'icmp', 'banner', 'fingerprint', 'cve'];
$requested_phases = $body['phases'] ?? $default_phases;
if (!is_array($requested_phases)) {
    $decoded = json_decode((string)$requested_phases, true);
    $requested_phases = is_array($decoded) ? $decoded : $default_phases;
}
$phases_arr = array_values(array_intersect($requested_phases, $allowed_phases));
if (empty($phases_arr)) {
    st_json(['error' => 'No valid scan phases specified', 'field' => 'phases'], 400);
}
$phases = json_encode($phases_arr);

// Optional per-job enrichment allowlist (same semantics as scan_start.php)
$enrichmentIdsJson = null;
if (array_key_exists('enrichment_source_ids', $body)) {
    $eraw = $body['enrichment_source_ids'];
    if ($eraw === null || $eraw === '') {
        $enrichmentIdsJson = null;
    } elseif (!is_array($eraw)) {
        st_json(['error' => 'enrichment_source_ids must be an array or null', 'field' => 'enrichment_source_ids'], 400);
    } elseif (count($eraw) === 0) {
        $enrichmentIdsJson = '[]';
    } else {
        $ids = [];
        foreach ($eraw as $x) {
            $ids[] = (int)$x;
        }
        $ids = array_values(array_unique(array_filter($ids, fn ($n) => $n > 0)));
        if (count($ids) === 0) {
            $enrichmentIdsJson = '[]';
        } elseif (count($ids) > 50) {
            st_json(['error' => 'At most 50 enrichment_source_ids allowed', 'field' => 'enrichment_source_ids'], 400);
        } else {
            $hasTable = (bool)$db->query(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_sources' LIMIT 1"
            )->fetchColumn();
            if (!$hasTable) {
                st_json(['error' => 'Enrichment is not configured yet', 'field' => 'enrichment_source_ids'], 400);
            }
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $vstmt = $db->prepare("SELECT id FROM enrichment_sources WHERE id IN ($placeholders)");
            $vstmt->execute($ids);
            $found = array_map('intval', array_column($vstmt->fetchAll(PDO::FETCH_ASSOC), 'id'));
            sort($found);
            $want = $ids;
            sort($want);
            if ($found !== $want) {
                st_json(['error' => 'Unknown enrichment source id in enrichment_source_ids', 'field' => 'enrichment_source_ids'], 400);
            }
            $enrichmentIdsJson = json_encode(array_values($ids));
        }
    }
}

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

// next_run: leave NULL so scheduler_daemon computes the first fire from
// cron_expr + timezone (polls within ~30s). Never use "now+60s" — that ignores cron.
$reset_next_run = false;
if ($id > 0) {
    $prevStmt = $db->prepare('SELECT cron_expr, timezone FROM scan_schedules WHERE id = ?');
    $prevStmt->execute([$id]);
    $prevRow = $prevStmt->fetch(PDO::FETCH_ASSOC);
    if ($prevRow) {
        $prevCron = (string)($prevRow['cron_expr'] ?? '');
        $prevTz = (string)($prevRow['timezone'] ?? 'UTC');
        if ($prevCron !== $cron_expr || $prevTz !== $timezone) {
            $reset_next_run = true;
        }
    }
}

if ($id > 0) {
    if ($reset_next_run) {
        $db->prepare("
            UPDATE scan_schedules SET
                name=?, cron_expr=?, target_cidr=?, exclusions=?, phases=?,
                profile=?, scan_mode=?, rate_pps=?, inter_delay=?, priority=?,
                enabled=?, paused=COALESCE(?, paused), notes=?, timezone=?,
                missed_run_policy=?, missed_run_max=?, enrichment_source_ids=?,
                next_run = NULL
            WHERE id=?
        ")->execute([
            $name, $cron_expr, $target_cidr, $exclusions, $phases,
            $profile, $scan_mode, $rate_pps, $inter_delay, $priority,
            $enabled, $paused, $notes, $timezone,
            $missed_run_policy, $missed_run_max, $enrichmentIdsJson,
            $id,
        ]);
    } else {
        $db->prepare("
            UPDATE scan_schedules SET
                name=?, cron_expr=?, target_cidr=?, exclusions=?, phases=?,
                profile=?, scan_mode=?, rate_pps=?, inter_delay=?, priority=?,
                enabled=?, paused=COALESCE(?, paused), notes=?, timezone=?,
                missed_run_policy=?, missed_run_max=?, enrichment_source_ids=?
            WHERE id=?
        ")->execute([
            $name, $cron_expr, $target_cidr, $exclusions, $phases,
            $profile, $scan_mode, $rate_pps, $inter_delay, $priority,
            $enabled, $paused, $notes, $timezone,
            $missed_run_policy, $missed_run_max, $enrichmentIdsJson,
            $id,
        ]);
    }
    st_audit_log('scan.schedule_updated', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'schedule_id' => $id,
        'name' => $name,
        'target_cidr' => $target_cidr,
        'profile' => $profile,
        'scan_mode' => $scan_mode,
        'enabled' => $enabled,
    ]);
} else {
    $db->prepare("
        INSERT INTO scan_schedules
            (name, cron_expr, target_cidr, exclusions, phases, profile,
             scan_mode, rate_pps, inter_delay, priority, enabled, paused, notes, timezone,
             missed_run_policy, missed_run_max, next_run, enrichment_source_ids)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
    ")->execute([
        $name, $cron_expr, $target_cidr, $exclusions, $phases, $profile,
        $scan_mode, $rate_pps, $inter_delay, $priority, $enabled, (int)($paused ?? 0), $notes, $timezone,
        $missed_run_policy, $missed_run_max, $enrichmentIdsJson
    ]);
    $id = (int)$db->lastInsertId();
    st_audit_log('scan.schedule_created', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'schedule_id' => $id,
        'name' => $name,
        'target_cidr' => $target_cidr,
        'profile' => $profile,
        'scan_mode' => $scan_mode,
        'enabled' => $enabled,
    ]);
}

$stmt2 = $db->prepare("SELECT * FROM scan_schedules WHERE id=?");
$stmt2->execute([$id]);
st_json(['ok' => true, 'schedule' => $stmt2->fetch()]);
