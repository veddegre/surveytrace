<?php
/**
 * SurveyTrace — POST /api/scan_delete.php
 *
 * Deletes a historical scan job and associated run evidence.
 * Safety: queued/running/retrying jobs cannot be deleted.
 *
 * Body JSON:
 *   { "job_id": 123 }
 */

require_once __DIR__ . '/db.php';
st_auth();
st_require_role(['scan_editor', 'admin']);
st_method('POST');

$db = st_db();
$actor = st_current_user();
$jobId = st_int('job_id', 0, 1);
if ($jobId <= 0) {
    st_json(['ok' => false, 'error' => 'job_id is required'], 400);
}

$stmt = $db->prepare("SELECT id, status FROM scan_jobs WHERE id = ? LIMIT 1");
$stmt->execute([$jobId]);
$job = $stmt->fetch();
if (!$job) {
    st_json(['ok' => false, 'error' => "Job #$jobId not found"], 404);
}
$status = (string)($job['status'] ?? '');
if (in_array($status, ['queued', 'running', 'retrying'], true)) {
    st_json(['ok' => false, 'error' => 'Cannot delete queued/running jobs; cancel or abort first'], 409);
}

try {
    $db->beginTransaction();
    // Always present
    $db->prepare("DELETE FROM scan_log WHERE job_id = ?")->execute([$jobId]);
    $db->prepare("DELETE FROM port_history WHERE scan_id = ?")->execute([$jobId]);
    // Optional newer tables (ignore if absent on older DB)
    try { $db->prepare("DELETE FROM scan_asset_snapshots WHERE job_id = ?")->execute([$jobId]); } catch (Throwable $e) {}
    try { $db->prepare("DELETE FROM scan_finding_snapshots WHERE job_id = ?")->execute([$jobId]); } catch (Throwable $e) {}
    $db->prepare("DELETE FROM scan_jobs WHERE id = ?")->execute([$jobId]);
    $db->commit();
} catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    st_json(['ok' => false, 'error' => 'Delete failed: ' . $e->getMessage()], 500);
}

st_audit_log('scan.job_deleted', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
    'job_id' => $jobId,
    'previous_status' => $status,
]);
st_json(['ok' => true, 'deleted_job_id' => $jobId]);

