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
 * Response 403: {"ok": false, "error": "Permission denied", ...} — requires scan_editor or admin
 * Response 409: {"error": "...", "running_job": N}    — scan already running
 * Response 400: {"error": "...", "field": "cidr"}     — validation failure
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_collectors.php';
st_auth();
st_require_role(['scan_editor', 'admin']);
st_method('POST');

$body = st_input();
$db   = st_db();
$actor = st_current_user();

function st_ip4_to_u32(string $ip): ?int {
    $bin = @inet_pton($ip);
    if (!is_string($bin) || strlen($bin) !== 4) return null;
    $parts = unpack('Nu', $bin);
    if (!is_array($parts) || !isset($parts['u'])) return null;
    return (int)$parts['u'];
}

function st_u32_to_ip4(int $u): string {
    return (string)inet_ntop(pack('N', $u));
}

function st_expand_to_24s(string $cidr): array {
    if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/', $cidr, $m)) {
        return [$cidr];
    }
    $ip = $m[1];
    $prefix = (int)$m[2];
    if ($prefix >= 24) {
        return [$cidr];
    }
    $u = st_ip4_to_u32($ip);
    if ($u === null) {
        return [$cidr];
    }
    $mask = ((~((1 << (32 - $prefix)) - 1)) & 0xFFFFFFFF);
    $network = ($u & $mask);
    $count = (1 << (24 - $prefix));
    $out = [];
    for ($i = 0; $i < $count; $i++) {
        $start = ($network + ($i * 256)) & 0xFFFFFFFF;
        $out[] = st_u32_to_ip4($start) . '/24';
    }
    return $out;
}

// Ensure newer queue columns exist for older databases
$scanJobCols = array_column($db->query("PRAGMA table_info(scan_jobs)")->fetchAll(), 'name');
$scanJobMigrations = [
    'scan_mode'  => "TEXT DEFAULT 'auto'",
    'profile'    => "TEXT DEFAULT 'standard_inventory'",
    'priority'   => "INTEGER DEFAULT 10",
    'retry_count'=> "INTEGER DEFAULT 0",
    'max_retries'=> "INTEGER DEFAULT 2",
    'enrichment_source_ids' => "TEXT",
    'batch_id' => "INTEGER DEFAULT 0",
    'batch_index' => "INTEGER DEFAULT 0",
    'batch_total' => "INTEGER DEFAULT 0",
    'collector_id' => "INTEGER DEFAULT 0",
];
foreach ($scanJobMigrations as $col => $defn) {
    if (!in_array($col, $scanJobCols, true)) {
        $db->exec("ALTER TABLE scan_jobs ADD COLUMN $col $defn");
    }
}
$db->exec("
    CREATE TABLE IF NOT EXISTS scan_batches (
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
    )
");

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
             scan_mode, profile, priority, collector_id, created_by, enrichment_source_ids)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'web', ?)
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
        (int)($orig['collector_id'] ?? 0),
        $enrRetry,
    ]);
    $newJobId = (int)$db->lastInsertId();
    st_audit_log('scan.rerun_queued', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'job_id' => $newJobId,
        'source_job_id' => $orig_id,
        'status_suffix' => (($orig['status'] ?? '') === 'failed') ? 'retry' : 're-run',
        'profile' => (string)($orig['profile'] ?? 'standard_inventory'),
        'target_cidr' => (string)($orig['target_cidr'] ?? ''),
        'label' => $newLabel !== null && $newLabel !== '' ? $newLabel : null,
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

$autoSplit24 = !empty($body['auto_split_24']);
$scan_targets = [];
if ($autoSplit24) {
    foreach ($validated_cidrs as $vc) {
        foreach (st_expand_to_24s($vc) as $sub) {
            $scan_targets[] = $sub;
        }
    }
} else {
    $scan_targets = $validated_cidrs;
}
$scan_targets = array_values(array_unique($scan_targets));
if (empty($scan_targets)) {
    st_json(['error' => 'No scan targets generated', 'field' => 'cidr'], 400);
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
$collector_id = max(0, (int)($body['collector_id'] ?? 0));
if ($collector_id > 0) {
    $hasCollectors = (bool)$db->query(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='collectors' LIMIT 1"
    )->fetchColumn();
    if (!$hasCollectors) {
        st_json(['error' => 'Collectors are not initialized yet', 'field' => 'collector_id'], 400);
    }
    $cstmt = $db->prepare("SELECT id, status, revoked_at FROM collectors WHERE id=? LIMIT 1");
    $cstmt->execute([$collector_id]);
    $collectorRow = $cstmt->fetch(PDO::FETCH_ASSOC);
    if (!$collectorRow) {
        st_json(['error' => 'Unknown collector_id', 'field' => 'collector_id'], 400);
    }
    if (!empty($collectorRow['revoked_at']) || (string)($collectorRow['status'] ?? '') === 'revoked') {
        st_json(['error' => 'Selected collector is revoked', 'field' => 'collector_id'], 400);
    }
    foreach ($scan_targets as $t) {
        if (!st_collector_target_allowed($collector_id, (string)$t)) {
            st_json(['error' => 'Target is outside collector allowed CIDR ranges', 'field' => 'cidr'], 400);
        }
    }
}

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
// 5. Concurrency guard — allow up to 10 queued/running/retrying jobs
// ---------------------------------------------------------------------------
$queueCap = 10;
$queued_count = (int)$db->query(
    "SELECT COUNT(*) FROM scan_jobs WHERE status IN ('running','queued','retrying')"
)->fetchColumn();

if ($queued_count >= $queueCap) {
    st_json(['error' => 'Queue is full (max 10 pending jobs). Abort some jobs first.'], 429);
}
$availableSlots = max(0, $queueCap - $queued_count);

// Optional priority: 1=highest, 100=lowest, default 10
$priority = max(1, min(100, (int)($body['priority'] ?? 10)));

// ---------------------------------------------------------------------------
// 6. Enqueue (staged for large /24 batches)
// ---------------------------------------------------------------------------
$stmt = $db->prepare("
    INSERT INTO scan_jobs (target_cidr, label, exclusions, phases, rate_pps, inter_delay,
        scan_mode, profile, priority, collector_id, created_by, enrichment_source_ids, batch_id, batch_index, batch_total)
    VALUES (:cidr, :label, :excl, :phases, :pps, :delay, :mode, :profile, :priority, :collector_id, 'web', :enrids, :bid, :bidx, :btotal)
");
$resolved_job_label = $label !== '' ? $label : ('Scan ' . date('Y-m-d H:i'));
$job_ids = [];
$totalJobs = count($scan_targets);
$enqueueNow = min($availableSlots, $totalJobs);
$pendingTargets = array_slice($scan_targets, $enqueueNow);
$batchId = 0;
if ($totalJobs > 1) {
    $batchIns = $db->prepare("
        INSERT INTO scan_batches (
            label, created_by, status, total_targets, pending_targets,
            exclusions, phases, rate_pps, inter_delay, scan_mode, profile, priority,
            enrichment_source_ids, auto_split_24, updated_at
        ) VALUES (?, 'web', 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ");
    $batchIns->execute([
        $resolved_job_label,
        $totalJobs,
        json_encode($pendingTargets),
        $exclusions,
        json_encode($phases),
        $rate_pps,
        $inter_delay,
        $scan_mode,
        $profile,
        $priority,
        $enrichmentIdsJson,
        $autoSplit24 ? 1 : 0,
    ]);
    $batchId = (int)$db->lastInsertId();
}
foreach (array_slice($scan_targets, 0, $enqueueNow) as $idx => $targetCidr) {
    $jobLabel = $resolved_job_label;
    if ($totalJobs > 1) {
        $jobLabel = sprintf('%s [batch %d/%d]', $resolved_job_label, $idx + 1, $totalJobs);
    }
    $stmt->execute([
        ':cidr'   => $targetCidr,
        ':label'  => $jobLabel,
        ':excl'   => $exclusions,
        ':phases' => json_encode($phases),
        ':pps'    => $rate_pps,
        ':delay'  => $inter_delay,
        ':mode'   => $scan_mode,
        ':profile'=> $profile,
        ':priority'=> $priority,
        ':collector_id' => $collector_id,
        ':enrids' => $enrichmentIdsJson,
        ':bid'    => $batchId,
        ':bidx'   => $totalJobs > 1 ? ($idx + 1) : 0,
        ':btotal' => $totalJobs > 1 ? $totalJobs : 0,
    ]);
    $newJobId = (int)$db->lastInsertId();
    $job_ids[] = $newJobId;
    st_audit_log('scan.job_queued', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'job_id' => $newJobId,
        'target_cidr' => $targetCidr,
        'label' => $jobLabel,
        'profile' => $profile,
        'scan_mode' => $scan_mode,
        'priority' => $priority,
        'phases' => $phases,
        'rate_pps' => $rate_pps,
        'inter_delay_ms' => $inter_delay,
        'auto_split_24' => $autoSplit24 ? 1 : 0,
        'batch_total' => $totalJobs,
        'batch_index' => $idx + 1,
    ]);
}

$job_id = (int)($job_ids[0] ?? 0);
if ($batchId > 0) {
    $batchStatus = empty($pendingTargets) ? 'queued_all' : 'active';
    $db->prepare("UPDATE scan_batches SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        ->execute([$batchStatus, $batchId]);
    st_audit_log('scan.batch_queued', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'batch_id' => $batchId,
        'label' => $resolved_job_label,
        'total_targets' => $totalJobs,
        'queued_now' => $enqueueNow,
        'pending_feed' => count($pendingTargets),
        'auto_split_24' => $autoSplit24 ? 1 : 0,
    ]);
}

// Write initial audit log entry for the first queued job.
if ($job_id > 0) {
    $db->prepare("
        INSERT INTO scan_log (job_id, level, message)
        VALUES (?, 'INFO', ?)
    ")->execute([
        $job_id,
        sprintf(
            'Job #%d queued by web — targets: %s | phases: %s | pps: %d | delay: %dms | exclusions: %d lines%s%s%s',
            $job_id,
            implode(', ', $scan_targets),
            implode(', ', $phases),
            $rate_pps,
            $inter_delay,
            count($exclusion_lines),
            ($totalJobs > 1) ? (' | auto_split_24 batch=' . $totalJobs . ' jobs') : '',
            ($totalJobs > $enqueueNow) ? (' | staged_feed_pending=' . ($totalJobs - $enqueueNow)) : '',
            $enrichmentIdsJson === '[]'
                ? ' | enrichment: off'
                : ($enrichmentIdsJson !== null ? ' | enrichment: selected sources' : '')
        ),
    ]);
}

st_json([
    'ok'          => true,
    'job_id'      => $job_id,
    'job_ids'     => $job_ids,
    'jobs_queued' => count($job_ids),
    'jobs_total'  => $totalJobs,
    'status'      => 'queued',
    'target_cidr' => implode(', ', $scan_targets),
    'phases'      => $phases,
    'rate_pps'    => $rate_pps,
    'inter_delay' => $inter_delay,
    'scan_mode'   => $scan_mode,
    'label'       => $label,
    'auto_split_24' => $autoSplit24,
    'batch_id'      => $batchId,
    'batch_pending' => count($pendingTargets),
    'enrichment_source_ids' => $enrichmentIdsJson === null
        ? null
        : (json_decode($enrichmentIdsJson, true) ?: []),
]);
