<?php
/**
 * SurveyTrace — Phase 13 reporting & baselines (JSON API; no HTML UI).
 *
 * GET  reporting.php?action=compare&job_a=1&job_b=2
 * GET  reporting.php?action=summary&job_id=10&vs_baseline=1
 * GET  reporting.php?action=trends&limit=30
 * GET  reporting.php?action=compliance&job_id=10
 * GET  reporting.php?action=baseline
 * GET  reporting.php?action=artifacts&limit=20
 * GET  reporting.php?action=artifact&id=N
 * POST reporting.php?action=set_baseline  JSON: {"job_id": 10}
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_reporting.php';

st_auth();
st_require_role(['viewer', 'scan_editor', 'admin']);

$db = st_db();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = strtolower(trim((string) ($_GET['action'] ?? $_POST['action'] ?? '')));

if ($method === 'POST' && $action === 'set_baseline') {
    st_method('POST');
    st_require_csrf();
    st_require_role(['scan_editor', 'admin']);
    $body = st_input();
    $jobId = (int) ($body['job_id'] ?? 0);
    if ($jobId <= 0) {
        st_json(['ok' => false, 'error' => 'job_id required'], 400);
    }
    try {
        st_reporting_set_baseline($db, $jobId);
    } catch (Throwable $e) {
        st_json(['ok' => false, 'error' => $e->getMessage()], 400);
    }
    $actor = st_current_user();
    st_audit_log('report.baseline_set', (int) ($actor['id'] ?? 0), (string) ($actor['username'] ?? ''), null, null, [
        'baseline_job_id' => $jobId,
    ]);
    st_json(['ok' => true, 'baseline_job_id' => $jobId]);
}

st_method('GET');

switch ($action) {
    case 'compare':
        $ja = st_int('job_a', 0, 1);
        $jb = st_int('job_b', 0, 1);
        if ($ja <= 0 || $jb <= 0) {
            st_json(['ok' => false, 'error' => 'job_a and job_b required'], 400);
        }
        try {
            $diff = st_reporting_compare_jobs($db, $ja, $jb);
        } catch (Throwable $e) {
            st_json(['ok' => false, 'error' => $e->getMessage()], 400);
        }
        st_json(['ok' => true, 'diff' => $diff]);

    case 'summary':
        $jid = st_int('job_id', 0, 1);
        if ($jid <= 0) {
            st_json(['ok' => false, 'error' => 'job_id required'], 400);
        }
        $vs = st_int('vs_baseline', 1, 0, 1) === 1;
        $baseline = $vs ? st_reporting_get_baseline_job_id($db) : null;
        try {
            $payload = st_reporting_build_report_payload($db, $jid, $baseline);
        } catch (Throwable $e) {
            st_json(['ok' => false, 'error' => $e->getMessage()], 400);
        }
        st_json(['ok' => true, 'report' => $payload]);

    case 'trends':
        $lim = st_int('limit', 30, 1, 200);
        st_json(['ok' => true, 'trends' => st_reporting_trends($db, $lim)]);

    case 'compliance':
        $jid = st_int('job_id', 0, 1);
        if ($jid <= 0) {
            st_json(['ok' => false, 'error' => 'job_id required'], 400);
        }
        $vs = st_int('vs_baseline', 1, 0, 1) === 1;
        $baseline = $vs ? st_reporting_get_baseline_job_id($db) : null;
        st_json(['ok' => true, 'compliance' => st_reporting_compliance($db, $jid, $baseline)]);

    case 'baseline':
        $bid = st_reporting_get_baseline_job_id($db);
        st_json(['ok' => true, 'baseline_job_id' => $bid]);

    case 'artifacts':
        st_require_role(['scan_editor', 'admin']);
        $lim = st_int('limit', 20, 1, 100);
        $has = (int) $db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='report_artifacts' LIMIT 1")->fetchColumn();
        if ($has !== 1) {
            st_json(['ok' => true, 'artifacts' => []]);
        }
        $limI = max(1, min(100, $lim));
        $st = $db->query(
            "SELECT id, created_at, schedule_id, baseline_job_id, compare_job_id, kind, title
             FROM report_artifacts ORDER BY id DESC LIMIT {$limI}"
        );
        st_json(['ok' => true, 'artifacts' => $st ? $st->fetchAll(PDO::FETCH_ASSOC) : []]);

    case 'artifact':
        st_require_role(['scan_editor', 'admin']);
        $aid = st_int('id', 0, 1);
        if ($aid <= 0) {
            st_json(['ok' => false, 'error' => 'id required'], 400);
        }
        $st = $db->prepare('SELECT * FROM report_artifacts WHERE id = ? LIMIT 1');
        $st->execute([$aid]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            st_json(['ok' => false, 'error' => 'not found'], 404);
        }
        $row['payload'] = json_decode((string) ($row['payload_json'] ?? '{}'), true) ?: [];
        unset($row['payload_json']);
        st_json(['ok' => true, 'artifact' => $row]);

    default:
        st_json(['ok' => false, 'error' => 'unknown action; use compare|summary|trends|compliance|baseline|artifacts|artifact'], 400);
}
