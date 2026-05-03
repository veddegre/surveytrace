<?php
/**
 * GET /api/integrations_report_summary.php?scope_id=N (optional)
 *
 * Slim posture + latest snapshot job + bounded drift + compliance summary + scope_context.
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_integrations.php';
require_once __DIR__ . '/lib_reporting.php';

$db = st_db();
$pullCtx = st_integrations_pull_require_token_for($db, 'report_summary');

$scopeFilter = null;
if (array_key_exists('scope_id', $_GET)) {
    $scopeFilter = (int) $_GET['scope_id'];
    if ($scopeFilter < 0) {
        st_json(['ok' => false, 'error' => 'invalid scope_id'], 400);
    }
}

$scopeCtx = st_reporting_scope_context_for_response($db, $scopeFilter);
$latest = st_integrations_latest_done_job_id($db, $scopeFilter);

$out = [
    'ok'                      => true,
    'schema_version'          => 'surveytrace.integrations.report_summary_envelope.v1',
    'scope_id'                => $scopeCtx['scope_id'],
    'scope_name'              => $scopeCtx['scope_name'],
    'scope_context'           => $scopeCtx,
    'latest_completed_scan'   => null,
    'posture'                 => null,
    'posture_flat'            => null,
    'compliance_summary'      => null,
    'drift'                   => null,
];

if ($latest === null || $latest <= 0) {
    st_json($out);
}

$jmeta = $db->prepare(
    "SELECT id, finished_at, label, COALESCE(scope_id, 0) AS scope_id FROM scan_jobs WHERE id = ? AND (deleted_at IS NULL OR deleted_at = '') LIMIT 1"
);
$jmeta->execute([$latest]);
$jrow = $jmeta->fetch(PDO::FETCH_ASSOC);
$jobScopeId = $jrow ? (int) ($jrow['scope_id'] ?? 0) : null;
$out['latest_completed_scan'] = [
    'job_id'      => $latest,
    'finished_at' => $jrow ? (string) ($jrow['finished_at'] ?? '') : null,
    'label'       => $jrow ? (string) ($jrow['label'] ?? '') : null,
    'scope_id'    => $jobScopeId,
    'scope_name'  => ($jobScopeId !== null && $jobScopeId > 0) ? st_scan_scopes_resolve_name($db, $jobScopeId) : null,
];

try {
    $summary = st_reporting_summary_for_job($db, $latest);
    $bySev = is_array($summary['open_findings_by_severity'] ?? null) ? $summary['open_findings_by_severity'] : [];
    $norm = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'unknown' => 0];
    foreach ($bySev as $k => $v) {
        $kk = strtolower((string) $k);
        if (! array_key_exists($kk, $norm)) {
            $norm['unknown'] += (int) $v;
        } else {
            $norm[$kk] = (int) $v;
        }
    }
    $out['posture'] = [
        'job_id'                     => $summary['job_id'] ?? $latest,
        'asset_snapshots'            => $summary['asset_snapshots'] ?? 0,
        'open_findings_total'        => $summary['open_findings_total'] ?? 0,
        'open_findings_by_severity' => $summary['open_findings_by_severity'] ?? [],
    ];
    $out['posture_flat'] = [
        'job_id'                => (int) ($summary['job_id'] ?? $latest),
        'scope_id'              => $jobScopeId,
        'scope_name'            => ($jobScopeId !== null && $jobScopeId > 0) ? st_scan_scopes_resolve_name($db, $jobScopeId) : null,
        'snapshot_asset_count'  => (int) ($summary['asset_snapshots'] ?? 0),
        'open_findings_total'   => (int) ($summary['open_findings_total'] ?? 0),
        'critical_open'         => $norm['critical'],
        'high_open'             => $norm['high'],
        'medium_open'           => $norm['medium'],
        'low_open'              => $norm['low'],
    ];
} catch (Throwable $e) {
    $out['posture'] = ['error' => 'summary_unavailable'];
}

$cfgGlobal = st_reporting_get_baseline_config_job_id($db);
$scopeCfg = ($scopeFilter !== null && $scopeFilter > 0)
    ? st_reporting_get_scope_baseline_config_job_id($db, $scopeFilter)
    : null;
$baselineCfg = $scopeCfg ?? $cfgGlobal;
$effResolved = st_reporting_effective_baseline_for_scope($db, $scopeFilter);

try {
    $comp = st_reporting_compliance($db, $latest, $baselineCfg, $effResolved);
    $rulesSlim = [];
    foreach ($comp['rules'] ?? [] as $rid => $rv) {
        if (! is_array($rv)) {
            continue;
        }
        $det = (string) ($rv['detail'] ?? '');
        if (strlen($det) > 240) {
            $det = substr($det, 0, 240) . '…';
        }
        $rulesSlim[] = [
            'id'     => (string) $rid,
            'pass'   => (bool) ($rv['pass'] ?? false),
            'detail' => $det,
        ];
    }
    $out['compliance_summary'] = [
        'job_id'       => $comp['job_id'] ?? $latest,
        'scope_id'     => $comp['scope_id'] ?? null,
        'scope_name'   => $comp['scope_name'] ?? null,
        'overall_pass' => (bool) ($comp['overall_pass'] ?? false),
        'rules'        => $rulesSlim,
    ];
} catch (Throwable $e) {
    $out['compliance_summary'] = ['error' => 'compliance_unavailable'];
}

if ($effResolved !== null && $effResolved > 0 && $effResolved !== $latest) {
    try {
        $diff = st_reporting_compare_jobs($db, $effResolved, $latest);
        $fe = $diff['finding_events'] ?? [];
        if (is_array($fe) && count($fe) > 40) {
            $fe = array_slice($fe, 0, 40);
        }
        $out['drift'] = [
            'available'       => true,
            'baseline_job_id' => $effResolved,
            'counts'          => $diff['counts'] ?? null,
            'finding_events'  => $fe,
            'warnings'        => $diff['warnings'] ?? [],
            'scope_alignment' => st_reporting_compare_scope_alignment($db, $effResolved, $latest),
            'semantics'       => $diff['semantics'] ?? null,
        ];
    } catch (Throwable $e) {
        $out['drift'] = [
            'available' => false,
            'reason'    => 'compare_unavailable_or_too_large',
        ];
    }
} else {
    $out['drift'] = [
        'available' => false,
        'reason'    => 'no_effective_baseline_or_same_as_latest',
    ];
}

$out['pull_client'] = st_integrations_pull_client_public($pullCtx);

st_json($out);
