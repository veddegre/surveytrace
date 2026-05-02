<?php
/**
 * SurveyTrace — Phase 13 reporting & baselines (JSON API; no HTML UI).
 *
 * GET  reporting.php?action=compare&job_a=1&job_b=2
 * GET  reporting.php?action=compare_summary&job_a=1&job_b=2  (counts/events only; UI-safe)
 * GET  reporting.php?action=summary&job_id=10&vs_baseline=1
 * GET  reporting.php?action=trends&limit=30
 * GET  reporting.php?action=trends_summary&limit=30  (canonical keys; limit max 50; UI-safe)
 * GET  reporting.php?action=compliance&job_id=10
 * GET  reporting.php?action=baseline
 * GET  reporting.php?action=artifacts&limit=20
 * GET  reporting.php?action=artifact&id=N
 * GET  reporting.php?action=artifact_summary&id=N  (slim payload; scan_editor+)
 * GET  reporting.php?action=artifact_payload_preview&id=N  (truncated raw JSON; admin)
 * GET  reporting.php?action=compare_debug&job_a=1&job_b=2&sample_limit=15  (admin)
 * GET  reporting.php?action=baseline_debug  (admin)
 * POST reporting.php?action=set_baseline  JSON: {"job_id": 10} or {"job_id": 10, "scope_id": 3} for scoped baseline
 * GET  …&scope_id  — optional on trends_summary, trends, compliance, summary, baseline:
 *      omit param = all completed jobs (legacy); 0 = unscoped only; N = that scope
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_scan_scopes.php';
require_once __DIR__ . '/lib_reporting.php';

/** null = all jobs (legacy); 0 = unscoped-only (NULL/0 scope_id); N > 0 = that scope only */
function st_reporting_scope_filter_param(): ?int
{
    if (! array_key_exists('scope_id', $_GET)) {
        return null;
    }

    return (int) $_GET['scope_id'];
}

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
    $scopeId = (int) ($body['scope_id'] ?? 0);
    try {
        if ($scopeId > 0) {
            st_reporting_set_scope_baseline($db, $scopeId, $jobId);
        } else {
            st_reporting_set_baseline($db, $jobId);
        }
    } catch (Throwable $e) {
        st_json(['ok' => false, 'error' => $e->getMessage()], 400);
    }
    $actor = st_current_user();
    st_audit_log('report.baseline_set', (int) ($actor['id'] ?? 0), (string) ($actor['username'] ?? ''), null, null, [
        'baseline_job_id' => $jobId,
        'scope_id'        => $scopeId > 0 ? $scopeId : null,
    ]);
    st_json([
        'ok'               => true,
        'baseline_job_id'  => $jobId,
        'scope_id'         => $scopeId > 0 ? $scopeId : null,
    ]);
}

st_method('GET');

switch ($action) {
    case 'compare':
        $ja = st_int('job_a', 0, 1);
        $jb = st_int('job_b', 0, 1);
        if ($ja <= 0 || $jb <= 0) {
            st_json(['ok' => false, 'error' => 'job_a and job_b required'], 400);
        }
        if ($ja === $jb) {
            st_json(['ok' => false, 'error' => 'job_a and job_b must differ'], 400);
        }
        try {
            $diff = st_reporting_compare_jobs($db, $ja, $jb);
        } catch (Throwable $e) {
            st_json(['ok' => false, 'error' => $e->getMessage()], 400);
        }
        st_json(['ok' => true, 'diff' => $diff]);

    case 'compare_summary':
        $ja = st_int('job_a', 0, 1);
        $jb = st_int('job_b', 0, 1);
        if ($ja <= 0 || $jb <= 0) {
            st_json(['ok' => false, 'error' => 'job_a and job_b required'], 400);
        }
        if ($ja === $jb) {
            st_json(['ok' => false, 'error' => 'job_a and job_b must differ'], 400);
        }
        try {
            $diff = st_reporting_compare_jobs($db, $ja, $jb);
        } catch (Throwable $e) {
            st_json(['ok' => false, 'error' => $e->getMessage()], 400);
        }
        $scopeAlign = st_reporting_compare_scope_alignment($db, $ja, $jb);
        st_json([
            'ok'           => true,
            'diff_summary' => [
                'job_a'            => $diff['job_a'],
                'job_b'            => $diff['job_b'],
                'semantics'        => $diff['semantics'],
                'warnings'         => $diff['warnings'],
                'counts'           => $diff['counts'],
                'finding_events'   => $diff['finding_events'],
                'scope_alignment'  => $scopeAlign,
            ],
        ]);

    case 'summary':
        $jid = st_int('job_id', 0, 1);
        if ($jid <= 0) {
            st_json(['ok' => false, 'error' => 'job_id required'], 400);
        }
        $vs = st_int('vs_baseline', 1, 0, 1) === 1;
        $scopeF = st_reporting_scope_filter_param();
        $cfgGlobal = st_reporting_get_baseline_config_job_id($db);
        $scopeCfg = ($scopeF !== null && $scopeF > 0)
            ? st_reporting_get_scope_baseline_config_job_id($db, $scopeF)
            : null;
        $baselineCfg = $scopeCfg ?? $cfgGlobal;
        $effResolved = $vs ? st_reporting_effective_baseline_for_scope($db, $scopeF) : null;
        try {
            $payload = st_reporting_build_report_payload(
                $db,
                $jid,
                $vs ? $baselineCfg : null,
                $vs ? $effResolved : null
            );
        } catch (Throwable $e) {
            st_json(['ok' => false, 'error' => $e->getMessage()], 400);
        }
        st_json(['ok' => true, 'report' => $payload]);

    case 'trends':
        $lim = st_int('limit', 30, 1, 200);
        $scopeF = st_reporting_scope_filter_param();
        st_json(['ok' => true, 'trends' => st_reporting_trends($db, $lim, $scopeF)]);

    case 'trends_summary':
        $lim = st_int('limit', 30, 1, 50);
        $scopeF = st_reporting_scope_filter_param();
        st_json(['ok' => true, 'trends_summary' => st_reporting_trends_summary($db, $lim, $scopeF)]);

    case 'compliance':
        $jid = st_int('job_id', 0, 1);
        if ($jid <= 0) {
            st_json(['ok' => false, 'error' => 'job_id required'], 400);
        }
        $vs = st_int('vs_baseline', 1, 0, 1) === 1;
        $scopeF = st_reporting_scope_filter_param();
        $cfgGlobal = st_reporting_get_baseline_config_job_id($db);
        $scopeCfg = ($scopeF !== null && $scopeF > 0)
            ? st_reporting_get_scope_baseline_config_job_id($db, $scopeF)
            : null;
        $baselineCfg = $scopeCfg ?? $cfgGlobal;
        $effResolved = $vs ? st_reporting_effective_baseline_for_scope($db, $scopeF) : null;
        st_json([
            'ok'         => true,
            'compliance' => st_reporting_compliance($db, $jid, $vs ? $baselineCfg : null, $vs ? $effResolved : null),
        ]);

    case 'baseline':
        try {
            $scopeF = st_reporting_scope_filter_param();
            st_json(st_reporting_baseline_status_response($db, $scopeF));
        } catch (Throwable $e) {
            @error_log('SurveyTrace reporting baseline: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $e->getMessage()));
            st_json([
                'ok'                                  => true,
                'baseline_soft_error'                 => 'Baseline metadata could not be loaded completely. Other reporting features may still work.',
                'baseline_config_job_id'              => null,
                'baseline_job_id'                     => null,
                'baseline_unavailable'                => false,
                'scoping_enabled'                     => false,
                'scope_filter'                        => null,
                'scope_id'                            => null,
                'scope_baseline_config_job_id'        => null,
                'scope_baseline_job_id'               => null,
                'scope_baseline_unavailable'          => false,
                'baseline_overview'                   => true,
                'global_baseline_job_scope_id'        => null,
                'unscoped_comparison_baseline_job_id' => null,
                'legacy_global_points_to_named_scope'  => false,
                'unscoped_pool_config_job_id'         => null,
                'unscoped_pool_baseline_job_id'       => null,
            ]);
        }

    case 'baseline_debug':
        st_require_role(['admin']);
        st_json(['ok' => true, 'baseline' => st_reporting_baseline_explain($db)]);

    case 'compare_debug':
        st_require_role(['admin']);
        $ja = st_int('job_a', 0, 1);
        $jb = st_int('job_b', 0, 1);
        $sample = st_int('sample_limit', 15, 1, 50);
        if ($ja <= 0 || $jb <= 0) {
            st_json(['ok' => false, 'error' => 'job_a and job_b required'], 400);
        }
        if ($ja === $jb) {
            st_json(['ok' => false, 'error' => 'job_a and job_b must differ'], 400);
        }
        try {
            $debug = st_reporting_compare_debug($db, $ja, $jb, $sample);
        } catch (Throwable $e) {
            st_json(['ok' => false, 'error' => $e->getMessage()], 400);
        }
        st_json(['ok' => true, 'compare_debug' => $debug]);

    case 'artifacts':
        st_require_role(['viewer', 'scan_editor', 'admin']);
        $lim = st_int('limit', 20, 1, 100);
        try {
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
        } catch (Throwable $e) {
            @error_log('SurveyTrace reporting artifacts: ' . preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $e->getMessage()));
            st_json([
                'ok'                   => true,
                'artifacts'            => [],
                'artifacts_soft_error' => 'Saved report list could not be read. Try again or check server error_log.',
            ]);
        }

    case 'artifact_summary':
        st_require_role(['scan_editor', 'admin']);
        $aid = st_int('id', 0, 1);
        if ($aid <= 0) {
            st_json(['ok' => false, 'error' => 'id required'], 400);
        }
        $has = (int) $db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='report_artifacts' LIMIT 1")->fetchColumn();
        if ($has !== 1) {
            st_json(['ok' => false, 'error' => 'report_artifacts table missing'], 404);
        }
        $st = $db->prepare(
            'SELECT id, created_at, schedule_id, baseline_job_id, compare_job_id, kind, title, payload_json
             FROM report_artifacts WHERE id = ? LIMIT 1'
        );
        $st->execute([$aid]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            st_json(['ok' => false, 'error' => 'not found'], 404);
        }
        $rawPayload = (string) ($row['payload_json'] ?? '');
        $flags = 0;
        if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
            $flags = JSON_INVALID_UTF8_SUBSTITUTE;
        }
        $payload = json_decode($rawPayload, true, 512, $flags);
        $decodeWarning = null;
        if (!is_array($payload)) {
            $decodeWarning = $rawPayload === ''
                ? null
                : ('invalid payload_json: ' . json_last_error_msg());
            $payload = [];
        }
        unset($row['payload_json']);
        $row['payload'] = $payload;
        $row['_decode_warning'] = $decodeWarning;
        try {
            $artifactSummary = st_reporting_artifact_summary_for_response($row);
        } catch (Throwable $e) {
            st_json(['ok' => false, 'error' => 'could not build artifact summary'], 500);
        }
        unset($row['_decode_warning']);
        st_json(['ok' => true, 'artifact_summary' => $artifactSummary]);

    case 'artifact_payload_preview':
        st_require_role(['admin']);
        $aid = st_int('id', 0, 1);
        if ($aid <= 0) {
            st_json(['ok' => false, 'error' => 'id required'], 400);
        }
        $has = (int) $db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='report_artifacts' LIMIT 1")->fetchColumn();
        if ($has !== 1) {
            st_json(['ok' => false, 'error' => 'report_artifacts table missing'], 404);
        }
        $st = $db->prepare('SELECT payload_json FROM report_artifacts WHERE id = ? LIMIT 1');
        $st->execute([$aid]);
        $raw = $st->fetchColumn();
        if ($raw === false) {
            st_json(['ok' => false, 'error' => 'not found'], 404);
        }
        $jf = defined('JSON_INVALID_UTF8_SUBSTITUTE') ? JSON_INVALID_UTF8_SUBSTITUTE : 0;
        $decoded = json_decode((string) $raw, true, 512, $jf);
        if (!is_array($decoded)) {
            $decoded = ['_parse_error' => 'payload_json is not a JSON object', '_json_error' => json_last_error_msg()];
        }
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
        if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
            $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
        }
        $pretty = json_encode($decoded, $flags | JSON_PRETTY_PRINT);
        if ($pretty === false) {
            $pretty = '{"error":"json_encode_failed"}';
        }
        $maxLen = 14000;
        $truncated = strlen($pretty) > $maxLen;
        if ($truncated) {
            $pretty = substr($pretty, 0, $maxLen) . "\n… (truncated at {$maxLen} characters)";
        }
        st_json([
            'ok'         => true,
            'preview'    => $pretty,
            'truncated'  => $truncated,
            'artifact_id'=> $aid,
        ]);

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
        st_json([
            'ok'    => false,
            'error' => 'unknown action; GET: compare|compare_summary|summary|trends|trends_summary|compliance|baseline|baseline_debug|compare_debug|artifacts|artifact|artifact_summary|artifact_payload_preview; POST (CSRF): set_baseline',
        ], 400);
}
