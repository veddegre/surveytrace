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
 *   "label":       "Weekly full scan"          // optional human label
 * }
 *
 * Response 200: {"job_id": 42, "status": "queued", "target_cidr": "...", "phases": [...]}
 * Response 409: {"error": "...", "running_job": N}    — scan already running
 * Response 400: {"error": "...", "field": "cidr"}     — validation failure
 */

require_once __DIR__ . '/db.php';
st_auth();
st_method('POST');

$body = st_input();
$db   = st_db();

// Ensure newer queue columns exist for older databases
$scanJobCols = array_column($db->query("PRAGMA table_info(scan_jobs)")->fetchAll(), 'name');
$scanJobMigrations = [
    'scan_mode'  => "TEXT DEFAULT 'auto'",
    'profile'    => "TEXT DEFAULT 'standard_inventory'",
    'priority'   => "INTEGER DEFAULT 10",
    'retry_count'=> "INTEGER DEFAULT 0",
    'max_retries'=> "INTEGER DEFAULT 2",
];
foreach ($scanJobMigrations as $col => $defn) {
    if (!in_array($col, $scanJobCols, true)) {
        $db->exec("ALTER TABLE scan_jobs ADD COLUMN $col $defn");
    }
}

// ---------------------------------------------------------------------------
// Retry shortcut — clone a failed job before any validation
// ---------------------------------------------------------------------------
if (!empty($body['retry_job_id'])) {
    $orig_id = (int)$body['retry_job_id'];
    $stmt = $db->prepare("SELECT * FROM scan_jobs WHERE id = ? AND status = 'failed'");
    $stmt->execute([$orig_id]);
    $orig = $stmt->fetch();
    if (!$orig) {
        st_json(['error' => 'Job not found or not in failed state'], 404);
    }
    $db->prepare("
        INSERT INTO scan_jobs
            (target_cidr, label, exclusions, phases, rate_pps, inter_delay,
             scan_mode, profile, priority, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'web')
    ")->execute([
        $orig['target_cidr'],
        $orig['label'] ? $orig['label'] . ' (retry)' : null,
        $orig['exclusions'],
        $orig['phases'],
        $orig['rate_pps'],
        $orig['inter_delay'],
        $orig['scan_mode'] ?? 'auto',
        $orig['profile']   ?? 'standard_inventory',
        5,
    ]);
    st_json(['ok' => true, 'job_id' => (int)$db->lastInsertId(), 'status' => 'queued']);
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
if (in_array($profile, ['deep_scan', 'ot_careful'])) {
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
    INSERT INTO scan_jobs (target_cidr, label, exclusions, phases, rate_pps, inter_delay, scan_mode, profile, priority, created_by)
    VALUES (:cidr, :label, :excl, :phases, :pps, :delay, :mode, :profile, :priority, 'web')
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
]);

$job_id = (int)$db->lastInsertId();

// Write initial audit log entry
$db->prepare("
    INSERT INTO scan_log (job_id, level, message)
    VALUES (?, 'INFO', ?)
")->execute([
    $job_id,
    sprintf(
        'Job #%d queued by web — targets: %s | phases: %s | pps: %d | delay: %dms | exclusions: %d lines',
        $job_id,
        implode(', ', $validated_cidrs),
        implode(', ', $phases),
        $rate_pps,
        $inter_delay,
        count($exclusion_lines)
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
]);
