<?php
/**
 * SurveyTrace — POST /api/scan_priority.php
 *
 * Update queue priority for a queued/retrying scan job.
 * Body: { "job_id": 123, "priority": 1..100 }
 */
require_once __DIR__ . '/db.php';
st_auth();
st_require_role(['scan_editor', 'admin']);
st_method('POST');

$body = st_input();
$db = st_db();
$actor = st_current_user();

$jobId = (int)($body['job_id'] ?? 0);
$priority = (int)($body['priority'] ?? 0);
if ($jobId <= 0) {
    st_json(['ok' => false, 'error' => 'job_id is required'], 400);
}
if ($priority < 1 || $priority > 100) {
    st_json(['ok' => false, 'error' => 'priority must be between 1 and 100'], 400);
}

$stmt = $db->prepare("SELECT id, status, priority, label, target_cidr FROM scan_jobs WHERE id=? AND deleted_at IS NULL LIMIT 1");
$stmt->execute([$jobId]);
$job = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$job) {
    st_json(['ok' => false, 'error' => "Job #{$jobId} not found"], 404);
}
$status = (string)($job['status'] ?? '');
if (!in_array($status, ['queued', 'retrying'], true)) {
    st_json(['ok' => false, 'error' => 'Priority can only be changed for queued/retrying jobs'], 409);
}

$oldPriority = (int)($job['priority'] ?? 10);
$db->prepare("UPDATE scan_jobs SET priority=? WHERE id=?")->execute([$priority, $jobId]);

try {
    $logMsg = sprintf("Queue priority changed: %d -> %d", $oldPriority, $priority);
    $db->prepare("INSERT INTO scan_log (job_id, level, message) VALUES (?, 'INFO', ?)")
        ->execute([$jobId, $logMsg]);
} catch (Throwable $e) {
    // no-op
}

st_audit_log('scan.priority_update', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
    'job_id' => $jobId,
    'status' => $status,
    'target_cidr' => (string)($job['target_cidr'] ?? ''),
    'label' => (string)($job['label'] ?? ''),
    'old_priority' => $oldPriority,
    'new_priority' => $priority,
]);

st_json([
    'ok' => true,
    'job_id' => $jobId,
    'status' => $status,
    'old_priority' => $oldPriority,
    'priority' => $priority,
]);

