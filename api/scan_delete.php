<?php
/**
 * SurveyTrace — POST /api/scan_delete.php
 *
 * Scan trash lifecycle actions.
 * - action=trash   (default): soft-delete a historical scan into Trash
 * - action=restore: restore a trashed scan
 * - action=purge:   permanently delete a trashed scan and evidence (admin only)
 *
 * Body JSON:
 *   { "job_id": 123, "action": "trash|restore|purge" }
 */

require_once __DIR__ . '/db.php';
st_auth();
st_require_role(['scan_editor', 'admin']);
st_method('POST');
st_require_csrf();

$db = st_db();
$actor = st_current_user();
$jobId = st_int('job_id', 0, 1);
$action = st_str('action', 'trash', ['trash', 'restore', 'purge']);
if ($jobId <= 0) {
    st_json(['ok' => false, 'error' => 'job_id is required'], 400);
}

$jobCols = array_column($db->query("PRAGMA table_info(scan_jobs)")->fetchAll(), 'name');
if (!in_array('deleted_at', $jobCols, true)) {
    try {
        $db->exec("ALTER TABLE scan_jobs ADD COLUMN deleted_at DATETIME");
    } catch (Throwable $e) {
        // no-op if migrated concurrently
    }
}

$stmt = $db->prepare("SELECT id, status, deleted_at, target_cidr, label FROM scan_jobs WHERE id = ? LIMIT 1");
$stmt->execute([$jobId]);
$job = $stmt->fetch();
if (!$job) {
    st_json(['ok' => false, 'error' => "Job #$jobId not found"], 404);
}
$status = (string)($job['status'] ?? '');
$deletedAt = trim((string)($job['deleted_at'] ?? ''));
$jobTargetCidr = (string)($job['target_cidr'] ?? '');
$jobLabel = (string)($job['label'] ?? '');

if ($action === 'trash') {
    if (in_array($status, ['queued', 'running', 'retrying'], true)) {
        st_json(['ok' => false, 'error' => 'Cannot move queued/running jobs to trash; cancel or abort first'], 409);
    }
    if ($deletedAt !== '') {
        st_json(['ok' => true, 'trashed_job_id' => $jobId, 'deleted_at' => $deletedAt, 'already_trashed' => true]);
    }
    $db->prepare("UPDATE scan_jobs SET deleted_at = datetime('now') WHERE id = ?")->execute([$jobId]);
    $newDeletedAt = (string)$db->query("SELECT deleted_at FROM scan_jobs WHERE id = " . (int)$jobId)->fetchColumn();
    st_audit_log('scan.job_trashed', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'job_id' => $jobId,
        'previous_status' => $status,
        'target_cidr' => $jobTargetCidr,
        'label' => $jobLabel,
    ]);
    st_json(['ok' => true, 'trashed_job_id' => $jobId, 'deleted_at' => $newDeletedAt]);
}

if ($action === 'restore') {
    if ($deletedAt === '') {
        st_json(['ok' => true, 'restored_job_id' => $jobId, 'already_active' => true]);
    }
    $db->prepare("UPDATE scan_jobs SET deleted_at = NULL WHERE id = ?")->execute([$jobId]);
    st_audit_log('scan.job_restored', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
        'job_id' => $jobId,
        'previous_status' => $status,
        'target_cidr' => $jobTargetCidr,
        'label' => $jobLabel,
    ]);
    st_json(['ok' => true, 'restored_job_id' => $jobId]);
}

if (st_current_role() !== 'admin') {
    st_json(['ok' => false, 'error' => 'Admin role required to permanently delete scan data'], 403);
}
if ($deletedAt === '') {
    st_json(['ok' => false, 'error' => 'Scan must be moved to trash before permanent deletion'], 409);
}

try {
    $db->beginTransaction();
    if ($db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_scope_baselines' LIMIT 1")->fetchColumn()) {
        try {
            $db->prepare('DELETE FROM scan_scope_baselines WHERE baseline_job_id = ?')->execute([$jobId]);
        } catch (Throwable $e) {
            // ignore if table schema differs
        }
    }
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
    @error_log('SurveyTrace scan delete failed: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string)$e->getMessage()));
    st_json(['ok' => false, 'error' => 'Delete failed'], 500);
}

st_audit_log('scan.job_purged', (int)($actor['id'] ?? 0), (string)($actor['username'] ?? ''), null, null, [
    'job_id' => $jobId,
    'previous_status' => $status,
    'target_cidr' => $jobTargetCidr,
    'label' => $jobLabel,
]);
st_json(['ok' => true, 'purged_job_id' => $jobId]);

