<?php
/**
 * SurveyTrace — /api/credential_check_runs.php
 *
 * Admin-only: list/get runs, launch (enqueue worker_jobs), cancel.
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_credential_check_ops.php';

st_auth();
st_require_role(['admin']);
st_ensure_user_audit_schema();

$db = st_db();

if (! st_cc_ops_tables_ready($db)) {
    st_json(['ok' => false, 'error' => 'Credentialed checks schema not available'], 503);
}

$actor = st_current_user();
$actorId = (int) ($actor['id'] ?? 0) > 0 ? (int) $actor['id'] : null;
$actorName = trim((string) ($actor['username'] ?? '')) !== '' ? trim((string) $actor['username']) : 'unknown';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
    if ($id > 0) {
        $wantDebug = isset($_GET['debug']) && (string) $_GET['debug'] === '1';
        $wantTimeline = isset($_GET['events']) && (string) $_GET['events'] === '1';
        $det = st_cc_run_get_detail($db, $id, $wantDebug, $wantTimeline);
        if ($det === null) {
            st_json(['ok' => false, 'error' => 'Run not found'], 404);
        }
        st_json(['ok' => true, 'run' => $det]);
    }
    $jobId = isset($_GET['job_id']) ? (int) $_GET['job_id'] : 0;
    $lim = isset($_GET['limit']) ? (int) $_GET['limit'] : 100;
    $filters = [
        'status'         => isset($_GET['status']) ? (string) $_GET['status'] : '',
        'transport'      => isset($_GET['transport']) ? (string) $_GET['transport'] : '',
        'plugin_substr'  => isset($_GET['plugin']) ? (string) $_GET['plugin'] : '',
        'profile_id'     => isset($_GET['profile_id']) ? (int) $_GET['profile_id'] : 0,
    ];
    $list = st_cc_run_list($db, $jobId > 0 ? $jobId : null, $lim, $filters);
    st_json(['ok' => true, 'runs' => $list]);
}

if ($method !== 'POST') {
    st_json(['ok' => false, 'error' => 'Method not allowed'], 405);
}

st_require_csrf();
$in = st_input();
$action = strtolower(trim((string) ($in['action'] ?? '')));

if ($action === 'launch') {
    $jobId = isset($in['job_id']) ? (int) $in['job_id'] : 0;
    if ($jobId < 1) {
        st_json(['ok' => false, 'error' => 'job_id required'], 400);
    }
    $accept = ! empty($in['accept_experimental']) && ($in['accept_experimental'] === true || $in['accept_experimental'] === 1 || $in['accept_experimental'] === '1');
    [$ok, $err, $run, $hints] = st_cc_run_launch($db, $jobId, $actorName, $accept);
    if (! $ok || $run === null) {
        $payload = ['ok' => false, 'error' => $err ?? 'Launch failed'];
        if (is_array($hints) && $hints !== []) {
            $payload = array_merge($payload, $hints);
        }
        st_json($payload, 400);
    }
    $rid = (int) ($run['id'] ?? 0);
    st_audit_log('credential_check.run_started', $actorId, $actorName, null, null, [
        'run_id'        => $rid,
        'job_id'        => $jobId,
        'worker_job_id' => (int) ($run['worker_job_id'] ?? 0),
    ]);
    st_json(['ok' => true, 'run' => $run]);
}

if ($action === 'cancel') {
    $runId = isset($in['run_id']) ? (int) $in['run_id'] : 0;
    if ($runId < 1) {
        st_json(['ok' => false, 'error' => 'run_id required'], 400);
    }
    [$ok, $err] = st_cc_run_cancel($db, $runId, $actorName);
    if (! $ok) {
        st_json(['ok' => false, 'error' => $err ?? 'Cancel failed'], 400);
    }
    st_audit_log('credential_check.run_cancelled', $actorId, $actorName, null, null, ['run_id' => $runId]);
    st_json(['ok' => true, 'run' => ['id' => $runId, 'status' => 'cancelled']]);
}

st_json(['ok' => false, 'error' => 'Unknown action'], 400);
