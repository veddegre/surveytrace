<?php
/**
 * SurveyTrace — POST /api/scan_abort.php
 *
 * Marks a running or queued scan job as aborted.
 * The daemon polls job status every 5 seconds and will stop
 * processing when it sees the aborted state.
 *
 * Body: {"job_id": N}
 * Response: {"ok": true} | {"error": "..."}
 */

require_once __DIR__ . '/db.php';
st_auth();
st_method('POST');

$body   = st_input();
$job_id = (int)($body['job_id'] ?? 0);

if (!$job_id) {
    st_json(['error' => 'job_id required'], 400);
}

$db = st_db();

// Only abort jobs that are actually running or queued
$stmt = $db->prepare("
    SELECT id, status FROM scan_jobs
    WHERE id = ? AND status IN ('queued', 'running')
");
$stmt->execute([$job_id]);
$job = $stmt->fetch();

if (!$job) {
    // Check if it exists at all
    $check = $db->prepare("SELECT id, status FROM scan_jobs WHERE id = ?");
    $check->execute([$job_id]);
    $exists = $check->fetch();
    if (!$exists) {
        st_json(['error' => "Job #$job_id not found"], 404);
    }
    st_json([
        'ok'     => false,
        'error'  => "Job #$job_id is already {$exists['status']} — cannot abort",
        'status' => $exists['status'],
    ], 409);
}

// Mark as aborted
$db->prepare("
    UPDATE scan_jobs
    SET status = 'aborted',
        finished_at = CURRENT_TIMESTAMP
    WHERE id = ?
")->execute([$job_id]);

// Write audit log entry
$db->prepare("
    INSERT INTO scan_log (job_id, level, message)
    VALUES (?, 'WARN', 'Scan aborted by user via web UI')
")->execute([$job_id]);

st_json([
    'ok'     => true,
    'job_id' => $job_id,
    'status' => 'aborted',
]);
