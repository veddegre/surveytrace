<?php
/**
 * SurveyTrace — /api/credential_check_jobs.php
 *
 * Admin-only CRUD for credential_check_jobs (templates). No execution.
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
$actorName = trim((string) ($actor['username'] ?? '')) !== '' ? trim((string) $actor['username']) : null;

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
    if ($id > 0) {
        $one = st_cc_job_get($db, $id);
        if ($one === null) {
            st_json(['ok' => false, 'error' => 'Job not found'], 404);
        }
        st_json(['ok' => true, 'job' => $one]);
    }
    st_json(['ok' => true, 'jobs' => st_cc_job_list($db)]);
}

if ($method !== 'POST') {
    st_json(['ok' => false, 'error' => 'Method not allowed'], 405);
}

st_require_csrf();
$in = st_input();
$action = strtolower(trim((string) ($in['action'] ?? '')));

if ($action === 'create') {
    [$norm, $err, $vlist, $warnings] = st_cc_ops_normalize_job_input($db, $in);
    if ($norm === null || $err !== null) {
        st_json(['ok' => false, 'error' => $err ?? 'validation failed', 'validation_errors' => $vlist], 400);
    }
    [$jid, $e2] = st_cc_job_create($db, $in, $actorId);
    if ($jid < 1) {
        st_json(['ok' => false, 'error' => $e2 ?? 'create failed'], 400);
    }
    st_audit_log('credential_check.job_created', $actorId, $actorName, null, null, [
        'job_id' => $jid,
        'name'   => $norm['name'],
    ]);
    if (! empty($norm['schedule_enabled'])) {
        $nj = st_cc_job_get($db, $jid);
        st_audit_log('credential_check.job_scheduled', $actorId, $actorName, null, null, [
            'job_id'        => $jid,
            'next_run_at'   => $nj['schedule_next_run_at'] ?? null,
            'schedule_cron' => $nj['schedule_cron'] ?? null,
        ]);
    }
    st_json(['ok' => true, 'id' => $jid, 'experimental_warnings' => $warnings]);
}

if ($action === 'update') {
    $id = isset($in['id']) ? (int) $in['id'] : 0;
    if ($id < 1) {
        st_json(['ok' => false, 'error' => 'id required'], 400);
    }
    $old = st_cc_job_get($db, $id);
    [$norm, $err, $vlist, $warnings] = st_cc_ops_normalize_job_input($db, $in);
    if ($norm === null || $err !== null) {
        st_json(['ok' => false, 'error' => $err ?? 'validation failed', 'validation_errors' => $vlist], 400);
    }
    $e = st_cc_job_update($db, $id, $in);
    if ($e !== null) {
        st_json(['ok' => false, 'error' => $e], 400);
    }
    st_audit_log('credential_check.job_updated', $actorId, $actorName, null, null, ['job_id' => $id]);
    $wasOn = is_array($old) && ! empty($old['schedule_enabled']);
    $nowOn = ! empty($norm['schedule_enabled']);
    $nj = st_cc_job_get($db, $id);
    if ($nowOn && ! $wasOn) {
        st_audit_log('credential_check.job_scheduled', $actorId, $actorName, null, null, [
            'job_id'        => $id,
            'next_run_at'   => $nj['schedule_next_run_at'] ?? null,
            'schedule_cron' => $nj['schedule_cron'] ?? null,
        ]);
    } elseif ($wasOn && ! $nowOn) {
        st_audit_log('credential_check.job_schedule_disabled', $actorId, $actorName, null, null, ['job_id' => $id]);
    } elseif ($wasOn && $nowOn) {
        $cronCh = (string) ($old['schedule_cron'] ?? '') !== (string) ($norm['schedule_cron'] ?? '')
            || (string) ($old['schedule_timezone'] ?? 'UTC') !== (string) ($norm['schedule_timezone'] ?? 'UTC')
            || (int) ($old['schedule_max_concurrency'] ?? 1) !== (int) ($norm['schedule_max_concurrency'] ?? 1)
            || (int) ($old['run_timeout_sec'] ?? 3600) !== (int) ($norm['run_timeout_sec'] ?? 3600);
        if ($cronCh) {
            st_audit_log('credential_check.job_schedule_updated', $actorId, $actorName, null, null, [
                'job_id'      => $id,
                'next_run_at' => $nj['schedule_next_run_at'] ?? null,
            ]);
        }
    }
    st_json(['ok' => true, 'experimental_warnings' => $warnings]);
}

if ($action === 'delete') {
    $id = isset($in['id']) ? (int) $in['id'] : 0;
    if ($id < 1) {
        st_json(['ok' => false, 'error' => 'id required'], 400);
    }
    if (! st_cc_job_delete($db, $id)) {
        st_json(['ok' => false, 'error' => 'Job not found or delete failed'], 404);
    }
    st_audit_log('credential_check.job_deleted', $actorId, $actorName, null, null, ['job_id' => $id]);
    st_json(['ok' => true]);
}

st_json(['ok' => false, 'error' => 'Unknown action'], 400);
