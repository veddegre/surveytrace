<?php
/**
 * SurveyTrace — POST /api/scan_start.php
 *
 * Validates a scan request, enforces concurrency limits, enqueues a job,
 * writes the initial audit log entry, and returns the job ID.
 *
 * Request body (JSON):
 * {
 *   "cidr":        "192.168.0.0/16",          // required; comma-sep for multiple
 *   "exclusions":  "192.168.1.1\n10.0.0.0/8", // optional; newline or comma sep
 *   "phases":      ["passive","icmp","banner","fingerprint","cve"],
 *   "rate_pps":    5,    // packets/sec per host, 1–50
 *   "inter_delay": 200,  // ms between hosts, 0–2000
 *   "label":       "Weekly full scan",         // optional human label
 *   "retry_job_id": N                          // optional — clone job N (failed, done, or aborted) into a new queued job
 *   "enrichment_source_ids": [1,2] | [] | omitted
 *                              — optional; omit or null = all enabled sources;
 *                                [] = skip network enrichment for this scan
 * }
 *
 * Response 200: {"job_id": 42, "status": "queued", "target_cidr": "...", "phases": [...]}
 * Response 409: {"error": "...", "running_job": N}    — scan already running
 * Response 400: {"error": "...", "field": "cidr"}     — validation failure
 */

require_once __DIR__ . '/db.php';
st_auth();
st_require_role(['scan_editor', 'admin']);
st_method('POST');

$body = st_input();
$db   = st_db();
$actor = st_current_user();

// Ensure newer queue columns exist for older databases
$scanJobCols = array_column($db->query("PRAGMA table_info(scan_jobs)")->fetchAll(), 'name');
$scanJobMigrations = [
    'scan_mode'  => "TEXT DEFAULT 'auto'",
    'profile'    => "TEXT DEFAULT 'standard_inventory'",
    'priority'   => "INTEGER DEFAULT 10",
    'retry_count'=> "INTEGER DEFAULT 0",
    'max_retries'=> "INTEGER DEFAULT 2",
    'enrichment_source_ids' => "TEXT",
];
foreach ($scanJobMigrations as $col => $defn) {
    if (!in_array($col, $scanJobCols, true)) {
        $db->exec("ALTER TABLE scan_jobs ADD COLUMN $col $defn");
    }
}

// ---------------------------------------------------------------------------
// Retry / re-run shortcut — clone a finished job (failed, done, aborted)
// before normal validation. POST body: { "retry_job_id": <id> }
// ---------------------------------------------------------------------------
if (!empty($body['retry_job_id'])) {
    $orig_id = (int)$body['retry_job_id'];
    $stmt = $db->prepare("SELECT * FROM scan_jobs WHERE id = ? AND status IN ('failed','done','aborted') AND deleted_at IS NULL");
    $stmt->execute([$orig_id]);
    $orig = $stmt->fetch();
    if (!$orig) {
        st_json(['error' => 'Job not found or not eligible for re-run (need failed, done, or aborted active scan)'], 404);
    }
    $enrRetry = $orig['enrichment_source_ids'] ?? null;
    $origLabel = trim((string)($orig['label'] ?? ''));
    // Avoid suffix stacking like "(re-run) (re-run) ..." across repeated clones.
    $baseLabel = preg_replace('/(?:\s*\((?:retry|re-run)\))+$/i', '', $origLabel);
    $baseLabel = trim((string)$baseLabel);
    $suffix    = (($orig['status'] ?? '') === 'failed') ? ' (retry)' : ' (re-run)';
    $newLabel  = $baseLabel !== '' ? $baseLabel . $suffix : null;

    $prio = (int)($orig['priority'] ?? 10);
    if ($prio < 1) {
        $prio = 1;
    }
    if ($prio > 99) {
        $prio = 99;
    }

    $db->prepare("
        INSERT INTO scan_jobs
            (target_cidr, label, exclusions, phases, rate_pps, inter_delay,
             scan_mode, profile, priority, created_by, enrichment_source_ids)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'web', ?)
    ")->execute([
        $orig['target_cidr'],
        $newLabel,
        $orig['exclusions'],
        $orig['phases'],
        $orig['rate_pps'],
        $orig['inter_delay'],
        $orig['scan_mode'] ?? 'auto',
        $orig['profile']   ?? 'standard_inventory',
        $prio,
        $enrRetry,
    ]);
    $newJobId = (int)$db->lastInsertId();
    st_audit_log('scan.rerun_queued', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'job_id' => $newJobId,
        'source_job_id' => $orig_id,
        'status_suffix' => (($orig['status'] ?? '') === 'failed') ? 'retry' : 're-run',
        'profile' => (string)($orig['profile'] ?? 'standard_inventory'),
    ]);
    st_json(['ok' => true, 'job_id' => $newJobId, 'status' => 'queued']);
}

// ---------------------------------------------------------------------------
// 1. CIDR validation
// ---------------------------------------------------------------------------
$cidr_raw = trim((string)($body['cidr'] ?? ''));
if ($cidr_raw === '') {
    st_json(['error' => 'cidr is required', 'field' => 'cidr'], 400);
}

$cidrs = array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', $cidr_raw))));
$validated_cidrs = [];

foreach ($cidrs as $c) {
    // Accept plain IPs (treat as /32) or proper CIDR notation
    if (filter_var($c, FILTER_VALIDATE_IP)) {
        $validated_cidrs[] = $c . '/32';
        continue;
    }
    // Validate CIDR format
    if (!preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/', $c)) {
        st_json(['error' => "Invalid CIDR notation: '$c'", 'field' => 'cidr'], 400);
    }
    [$ip, $prefix] = explode('/', $c);
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        st_json(['error' => "Invalid IP in CIDR: '$c'", 'field' => 'cidr'], 400);
    }
    $prefix = (int)$prefix;
    if ($prefix < 8 || $prefix > 32) {
        // Refuse /8 or broader as a safety guard against accidentally huge scans
        st_json(['error' => "CIDR prefix /$prefix is out of allowed range /8–/32", 'field' => 'cidr'], 400);
    }
    $validated_cidrs[] = $c;
}

if (empty($validated_cidrs)) {
    st_json(['error' => 'No valid CIDR targets provided', 'field' => 'cidr'], 400);
}

// ---------------------------------------------------------------------------
// 2. Phases whitelist
// ---------------------------------------------------------------------------
$allowed_phases = ['passive', 'icmp', 'banner', 'fingerprint', 'snmp', 'ot', 'cve'];
$default_phases = ['passive', 'icmp', 'banner', 'fingerprint', 'cve'];

$requested_phases = $body['phases'] ?? $default_phases;
if (!is_array($requested_phases)) {
    st_json(['error' => '"phases" must be an array', 'field' => 'phases'], 400);
}

$phases = array_values(array_intersect($requested_phases, $allowed_phases));
if (empty($phases)) {
    st_json(['error' => 'No valid scan phases specified', 'field' => 'phases'], 400);
}

// ---------------------------------------------------------------------------
// 3. Rate parameters
// ---------------------------------------------------------------------------
$rate_pps    = max(1,    min(50,   (int)($body['rate_pps']    ?? 5)));
$inter_delay = max(0,    min(2000, (int)($body['inter_delay'] ?? 200)));

// --- Profile -------------------------------------------------------------
$valid_profiles = ['iot_safe', 'standard_inventory', 'deep_scan', 'full_tcp', 'fast_full_tcp', 'ot_careful'];
$profile = in_array($body['profile'] ?? '', $valid_profiles)
    ? $body['profile']
    : 'standard_inventory';

// Require confirmation for dangerous profiles
if (in_array($profile, ['deep_scan', 'full_tcp', 'fast_full_tcp', 'ot_careful'])) {
    if (!($body['confirmed'] ?? false)) {
        st_json(['error' => "Profile '$profile' requires confirmation. Resend with confirmed:true.", 'requires_confirmation' => true], 400);
    }
}

// --- Scan mode ----------------------------------------------------------
$allowed_modes = ['auto', 'routed', 'force'];
$scan_mode = in_array($body['scan_mode'] ?? '', $allowed_modes)
    ? $body['scan_mode']
    : 'auto';

// ---------------------------------------------------------------------------
// 4. Exclusions — accept freeform text, strip comment lines
// ---------------------------------------------------------------------------
$exclusions_raw = (string)($body['exclusions'] ?? '');
$exclusion_lines = array_filter(
    array_map(
        fn($l) => trim(preg_replace('/#.*$/', '', $l)),
        preg_split('/[\r\n,]+/', $exclusions_raw)
    )
);
$exclusions = implode("\n", array_values($exclusion_lines));

// Optional label
$label = substr(trim((string)($body['label'] ?? '')), 0, 120);

// ---------------------------------------------------------------------------
// 4b. Optional per-scan enrichment allowlist (Phase 3b)
// ---------------------------------------------------------------------------
// null / key omitted = use all globally enabled sources (default)
// []          = skip enrichment for this scan
// [1,3,...]   = only these enrichment_sources rows (must exist)
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
                st_json(['error' => 'Enrichment is not configured yet (no sources table)', 'field' => 'enrichment_source_ids'], 400);
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

// ---------------------------------------------------------------------------
// 5. Concurrency guard — allow up to 10 queued jobs
// ---------------------------------------------------------------------------
$queued_count = (int)$db->query(
    "SELECT COUNT(*) FROM scan_jobs WHERE status IN ('running','queued','retrying')"
)->fetchColumn();

if ($queued_count >= 10) {
    st_json(['error' => 'Queue is full (max 10 pending jobs). Abort some jobs first.'], 429);
}

// Optional priority: 1=highest, 100=lowest, default 10
$priority = max(1, min(100, (int)($body['priority'] ?? 10)));

// ---------------------------------------------------------------------------
// 6. Enqueue
// ---------------------------------------------------------------------------
$stmt = $db->prepare("
    INSERT INTO scan_jobs (target_cidr, label, exclusions, phases, rate_pps, inter_delay,
        scan_mode, profile, priority, created_by, enrichment_source_ids)
    VALUES (:cidr, :label, :excl, :phases, :pps, :delay, :mode, :profile, :priority, 'web', :enrids)
");
$stmt->execute([
    ':cidr'   => implode(', ', $validated_cidrs),
    ':label'  => $label ?: ('Scan ' . date('Y-m-d H:i')),
    ':excl'   => $exclusions,
    ':phases' => json_encode($phases),
    ':pps'    => $rate_pps,
    ':delay'  => $inter_delay,
    ':mode'   => $scan_mode,
    ':profile'=> $profile,
    ':priority'=> $priority,
    ':enrids' => $enrichmentIdsJson,
]);

$job_id = (int)$db->lastInsertId();
st_audit_log('scan.job_queued', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
    'job_id' => $job_id,
    'target_cidr' => implode(', ', $validated_cidrs),
    'profile' => $profile,
    'scan_mode' => $scan_mode,
    'priority' => $priority,
]);

// Write initial audit log entry
$db->prepare("
    INSERT INTO scan_log (job_id, level, message)
    VALUES (?, 'INFO', ?)
")->execute([
    $job_id,
    sprintf(
        'Job #%d queued by web — targets: %s | phases: %s | pps: %d | delay: %dms | exclusions: %d lines%s',
        $job_id,
        implode(', ', $validated_cidrs),
        implode(', ', $phases),
        $rate_pps,
        $inter_delay,
        count($exclusion_lines),
        $enrichmentIdsJson === '[]'
            ? ' | enrichment: off'
            : ($enrichmentIdsJson !== null ? ' | enrichment: selected sources' : '')
    ),
]);

st_json([
    'job_id'      => $job_id,
    'status'      => 'queued',
    'target_cidr' => implode(', ', $validated_cidrs),
    'phases'      => $phases,
    'rate_pps'    => $rate_pps,
    'inter_delay' => $inter_delay,
    'scan_mode'   => $scan_mode,
    'label'       => $label,
    'enrichment_source_ids' => $enrichmentIdsJson === null
        ? null
        : (json_decode($enrichmentIdsJson, true) ?: []),
]);
