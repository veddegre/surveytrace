<?php
/**
 * Collector job polling and lease endpoint.
 */
require_once __DIR__ . '/lib_collectors.php';

st_collector_require_post();
st_collector_bootstrap_schema();
$auth = st_collector_auth_required('collector:jobs:read');
$collectorId = (int)$auth['collector_id'];
$db = st_db();
$body = st_input();
$maxJobs = max(1, min(10, (int)($body['max_jobs'] ?? 3)));

$stmt = $db->prepare("SELECT max_rps, status, allowed_cidrs_json, name FROM collectors WHERE id=? LIMIT 1");
$stmt->execute([$collectorId]);
$row = $stmt->fetch() ?: ['max_rps' => 5, 'status' => 'offline', 'allowed_cidrs_json' => '[]', 'name' => ''];
$collectorDisplayName = trim((string)($row['name'] ?? ''));
if (($row['status'] ?? '') === 'revoked') {
    st_json(['ok' => false, 'error' => 'Collector revoked'], 403);
}
st_collector_rate_limit($collectorId, 'jobs', (float)($row['max_rps'] ?? 5));

$db->exec("BEGIN IMMEDIATE");
try {
    // Expire stale leases and requeue jobs.
    $db->prepare(
        "UPDATE scan_jobs
         SET status='queued', started_at=NULL, error_msg='collector lease expired'
         WHERE id IN (
             SELECT job_id FROM collector_job_leases
             WHERE lease_expires_at < datetime('now')
         ) AND status='running'"
    )->execute();
    $db->prepare("DELETE FROM collector_job_leases WHERE lease_expires_at < datetime('now')")->execute();

    $jobs = [];
    // Include active leases for this collector first (resume-safe polling).
    $active = $db->prepare(
        "SELECT j.*, l.lease_token, l.lease_expires_at
         FROM scan_jobs j
         JOIN collector_job_leases l ON l.job_id = j.id
         WHERE l.collector_id=? AND j.status='running' AND l.lease_expires_at >= datetime('now')
         AND NOT EXISTS (
             SELECT 1 FROM collector_submissions s
             WHERE s.job_id = j.id AND s.collector_id = l.collector_id
               AND s.chunk_count > 0 AND s.received_chunks >= s.chunk_count
         )
         ORDER BY j.priority ASC, j.id ASC
         LIMIT ?"
    );
    $active->bindValue(1, $collectorId, PDO::PARAM_INT);
    $active->bindValue(2, $maxJobs, PDO::PARAM_INT);
    $active->execute();
    foreach ($active->fetchAll() as $r) {
        $jobs[] = $r;
    }

    if (count($jobs) < $maxJobs) {
        $need = $maxJobs - count($jobs);
        $q = $db->prepare(
            "SELECT *
             FROM scan_jobs
             WHERE status='queued' AND COALESCE(collector_id,0)=?
             ORDER BY priority ASC, id ASC
             LIMIT ?"
        );
        $q->bindValue(1, $collectorId, PDO::PARAM_INT);
        $q->bindValue(2, $need, PDO::PARAM_INT);
        $q->execute();
        $newRows = $q->fetchAll();
        $allowList = json_decode((string)($row['allowed_cidrs_json'] ?? '[]'), true);
        if (!is_array($allowList)) $allowList = [];
        $allowList = array_values(array_filter(array_map('strval', $allowList)));
        foreach ($newRows as $nr) {
            if ($allowList && !st_collector_target_allowed($collectorId, (string)($nr['target_cidr'] ?? ''))) {
                $db->prepare("UPDATE scan_jobs SET status='failed', finished_at=datetime('now'), error_msg='target outside collector allowlist' WHERE id=?")
                    ->execute([(int)$nr['id']]);
                continue;
            }
            $leaseToken = 'lease_' . bin2hex(random_bytes(16));
            $leaseSecs = st_collector_effective_lease_seconds_for_profile((string)($nr['profile'] ?? ''));
            $db->prepare("UPDATE scan_jobs SET status='running', started_at=COALESCE(started_at, datetime('now')) WHERE id=?")->execute([(int)$nr['id']]);
            $db->prepare(
                "INSERT OR REPLACE INTO collector_job_leases (job_id, collector_id, lease_token, leased_at, lease_expires_at, last_heartbeat_at)
                 VALUES (?, ?, ?, datetime('now'), datetime('now', ?), datetime('now'))"
            )->execute([(int)$nr['id'], $collectorId, $leaseToken, '+' . $leaseSecs . ' seconds']);
            $nr['lease_token'] = $leaseToken;
            $nr['lease_expires_at'] = gmdate('Y-m-d H:i:s', time() + $leaseSecs);
            $jid = (int)$nr['id'];
            $cLabel = $collectorDisplayName !== '' ? $collectorDisplayName : ('#' . $collectorId);
            $db->prepare("INSERT INTO scan_log (job_id, level, message) VALUES (?, 'INFO', ?)")->execute([
                $jid,
                sprintf(
                    'Collector %s (id %d) claimed this job — scan is running on the remote collector until results are submitted to the master.',
                    $cLabel,
                    $collectorId,
                ),
            ]);
            $jobs[] = $nr;
        }
    }

    $db->prepare("UPDATE collectors SET last_seen_at=datetime('now'), status='online', updated_at=datetime('now') WHERE id=?")->execute([$collectorId]);
    $db->exec("COMMIT");
} catch (Throwable $e) {
    $db->exec("ROLLBACK");
    @error_log('collector_jobs poll failed: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string)$e->getMessage()));
    st_json(['ok' => false, 'error' => 'collector job poll failed'], 500);
}

$out = [];
$reportLeaseSecs = st_collector_config_lease_seconds();
foreach ($jobs as $j) {
    $effLease = st_collector_effective_lease_seconds_for_profile((string)($j['profile'] ?? ''));
    $reportLeaseSecs = max($reportLeaseSecs, $effLease);
    $out[] = [
        'job_id' => (int)$j['id'],
        'label' => (string)($j['label'] ?? ''),
        'target_cidr' => (string)($j['target_cidr'] ?? ''),
        'exclusions' => (string)($j['exclusions'] ?? ''),
        'phases' => json_decode((string)($j['phases'] ?? '[]'), true) ?: [],
        'rate_pps' => (int)($j['rate_pps'] ?? 5),
        'inter_delay' => (int)($j['inter_delay'] ?? 200),
        'scan_mode' => (string)($j['scan_mode'] ?? 'auto'),
        'profile' => (string)($j['profile'] ?? 'standard_inventory'),
        'priority' => (int)($j['priority'] ?? 10),
        'enrichment_source_ids' => json_decode((string)($j['enrichment_source_ids'] ?? 'null'), true),
        'lease_token' => (string)($j['lease_token'] ?? ''),
        'lease_expires_at' => (string)($j['lease_expires_at'] ?? ''),
        'lease_seconds' => $effLease,
    ];
}

st_json([
    'ok' => true,
    'collector_id' => $collectorId,
    'jobs' => $out,
    'lease_seconds' => $reportLeaseSecs,
    'server_time' => gmdate('c'),
]);
