<?php
/**
 * Collector result chunk submission endpoint.
 */
require_once __DIR__ . '/lib_collectors.php';

st_collector_require_post();
st_collector_bootstrap_schema();
$auth = st_collector_auth_required('collector:submit:write');
$collectorId = (int)$auth['collector_id'];
$db = st_db();
$body = st_input();

$stmt = $db->prepare("SELECT max_rps, max_submit_mbps FROM collectors WHERE id=? LIMIT 1");
$stmt->execute([$collectorId]);
$collector = $stmt->fetch() ?: ['max_rps' => 5, 'max_submit_mbps' => 8];
st_collector_rate_limit($collectorId, 'submit', (float)($collector['max_rps'] ?? 5));

$jobId = (int)($body['job_id'] ?? 0);
$submissionId = trim((string)($body['submission_id'] ?? ''));
$chunkIndex = (int)($body['chunk_index'] ?? 0);
$chunkCount = (int)($body['chunk_count'] ?? 1);
$leaseToken = trim((string)($body['lease_token'] ?? ''));
$payload = $body['payload'] ?? null;
if ($jobId <= 0 || $submissionId === '' || $chunkIndex < 0 || $chunkCount <= 0) {
    st_json(['ok' => false, 'error' => 'Missing required submission metadata'], 400);
}
if (!is_array($payload)) {
    st_json(['ok' => false, 'error' => 'payload object required'], 400);
}

$lease = $db->prepare(
    "SELECT id FROM collector_job_leases
     WHERE collector_id=? AND job_id=? AND lease_token=? AND lease_expires_at >= datetime('now')
     LIMIT 1"
);
$lease->execute([$collectorId, $jobId, $leaseToken]);
if (!$lease->fetch()) {
    st_json(['ok' => false, 'error' => 'Invalid or expired lease'], 409);
}

$jsonPayload = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
if (!is_string($jsonPayload)) {
    st_json(['ok' => false, 'error' => 'payload serialization failed'], 400);
}
$maxBytes = (int)round(max(1.0, min(256.0, (float)($collector['max_submit_mbps'] ?? 8))) * 1024 * 1024);
if (strlen($jsonPayload) > $maxBytes) {
    st_json(['ok' => false, 'error' => 'payload exceeds collector submit max size'], 413);
}
$artifact = st_collector_store_artifact($submissionId, $chunkIndex, $jsonPayload);

$db->exec("BEGIN IMMEDIATE");
try {
    $db->prepare(
        "INSERT INTO collector_submissions
         (collector_id, job_id, submission_id, chunk_count, received_chunks, processed_chunks, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, 0, 0, 'receiving', datetime('now'), datetime('now'))
         ON CONFLICT(collector_id, job_id, submission_id)
         DO UPDATE SET
            chunk_count=excluded.chunk_count,
            updated_at=datetime('now')"
    )->execute([$collectorId, $jobId, $submissionId, $chunkCount]);

    $db->prepare(
        "INSERT INTO collector_ingest_queue
         (collector_id, job_id, submission_id, chunk_index, chunk_count, content_sha256, local_relpath, artifact_uri, status, attempts, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, datetime('now'))
         ON CONFLICT(collector_id, job_id, submission_id, chunk_index)
         DO UPDATE SET
            content_sha256=excluded.content_sha256,
            local_relpath=excluded.local_relpath,
            artifact_uri=excluded.artifact_uri,
            status='pending',
            next_attempt_at=NULL,
            error_msg=NULL"
    )->execute([
        $collectorId,
        $jobId,
        $submissionId,
        $chunkIndex,
        $chunkCount,
        $artifact['sha256'],
        $artifact['local_relpath'],
        $artifact['artifact_uri'],
    ]);

    $db->prepare(
        "UPDATE collector_submissions
         SET received_chunks = (
             SELECT COUNT(*)
             FROM collector_ingest_queue q
             WHERE q.collector_id=? AND q.job_id=? AND q.submission_id=?
         ),
             updated_at=datetime('now')
         WHERE collector_id=? AND job_id=? AND submission_id=?"
    )->execute([$collectorId, $jobId, $submissionId, $collectorId, $jobId, $submissionId]);

    $db->prepare(
        "UPDATE collector_job_leases
         SET last_heartbeat_at=datetime('now'),
             lease_expires_at=datetime('now', ?)
         WHERE collector_id=? AND job_id=? AND lease_token=?"
    )->execute(['+' . max(60, min(3600, (int)st_config('collector_lease_seconds', '600'))) . ' seconds', $collectorId, $jobId, $leaseToken]);

    $db->prepare("UPDATE collectors SET last_seen_at=datetime('now'), status='online', updated_at=datetime('now') WHERE id=?")->execute([$collectorId]);
    $db->exec("COMMIT");
} catch (Throwable $e) {
    $db->exec("ROLLBACK");
    @error_log('collector_submit failed: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string)$e->getMessage()));
    st_json(['ok' => false, 'error' => 'collector submit failed'], 500);
}

try {
    $db->prepare("INSERT INTO scan_log (job_id, level, message) VALUES (?, 'INFO', ?)")->execute([
        $jobId,
        sprintf(
            'Collector uploaded scan results (submission %s, chunk %d/%d); queued for master ingest.',
            $submissionId,
            $chunkIndex + 1,
            $chunkCount,
        ),
    ]);
} catch (Throwable $e) {
    // Non-fatal
}

st_json([
    'ok' => true,
    'queued' => true,
    'job_id' => $jobId,
    'submission_id' => $submissionId,
    'chunk_index' => $chunkIndex,
    'artifact_uri' => $artifact['artifact_uri'],
]);
