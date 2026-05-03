<?php
/**
 * Phase 14.1 — single JSON bundle for Grafana Infinity / scripted dashboards (integration pull token).
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_integrations.php';
require_once __DIR__ . '/lib_reporting.php';

/**
 * @return array<string, mixed>
 */
function st_integrations_build_dashboard_bundle(PDO $db, ?int $scopeFilter, int $trendLimit, int $eventHours, int $eventLimit): array
{
    $trendLimit = max(1, min(50, $trendLimit));
    $eventHours = max(1, min(168, $eventHours));
    $eventLimit = max(1, min(200, $eventLimit));

    $scopeCtx = st_reporting_scope_context_for_response($db, $scopeFilter);
    $metrics = st_integrations_metrics_snapshot($db);
    $metrics['scope_context'] = $scopeCtx;
    $metrics['scope_id'] = $scopeCtx['scope_id'];
    $metrics['scope_name'] = $scopeCtx['scope_name'];

    $trends = st_reporting_trends_summary($db, $trendLimit, $scopeFilter);

    $sinceDt = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->modify('-' . $eventHours . ' hours');
    $sinceSql = $sinceDt->format('Y-m-d H:i:s');
    $rawEvents = st_integrations_events_export($db, $sinceSql, $eventLimit);
    $events = array_map(static function (array $ev): array {
        return st_reporting_event_envelope_scope_fields($ev);
    }, $rawEvents);

    $latest = st_integrations_latest_done_job_id($db, $scopeFilter);
    $complianceSlim = [
        'available'    => false,
        'job_id'       => null,
        'scope_id'     => $scopeCtx['scope_id'],
        'scope_name'   => $scopeCtx['scope_name'],
        'overall_pass' => null,
    ];
    if ($latest !== null && $latest > 0) {
        try {
            $cfgGlobal = st_reporting_get_baseline_config_job_id($db);
            $scopeCfg = ($scopeFilter !== null && $scopeFilter > 0)
                ? st_reporting_get_scope_baseline_config_job_id($db, $scopeFilter)
                : null;
            $baselineCfg = $scopeCfg ?? $cfgGlobal;
            $effResolved = st_reporting_effective_baseline_for_scope($db, $scopeFilter);
            $comp = st_reporting_compliance($db, $latest, $baselineCfg, $effResolved);
            $complianceSlim = [
                'available'    => true,
                'job_id'       => (int) ($comp['job_id'] ?? $latest),
                'scope_id'     => $comp['scope_id'] ?? $scopeCtx['scope_id'],
                'scope_name'   => $comp['scope_name'] ?? $scopeCtx['scope_name'],
                'overall_pass' => (bool) ($comp['overall_pass'] ?? false),
            ];
        } catch (Throwable $e) {
            $complianceSlim = [
                'available'  => false,
                'error'      => 'unavailable',
                'scope_id'   => $scopeCtx['scope_id'],
                'scope_name' => $scopeCtx['scope_name'],
            ];
        }
    }

    return [
        'ok'               => true,
        'schema_version'   => 'surveytrace.integrations.dashboard.v1',
        'generated_at'     => gmdate('Y-m-d\TH:i:s\Z'),
        'scope_id'         => $scopeCtx['scope_id'],
        'scope_name'       => $scopeCtx['scope_name'],
        'scope_context'    => $scopeCtx,
        'live_metrics'     => $metrics,
        'trends_summary'   => $trends,
        'recent_events'    => $events,
        'compliance_snapshot' => $complianceSlim,
        'latest_done_job_id' => $latest,
    ];
}

/** Valid `?view=` values for raw JSON slices (no bundle envelope). */
function st_integrations_dashboard_view_valid(string $view): bool
{
    return in_array($view, ['trends', 'events', 'metrics', 'compliance'], true);
}

/**
 * Raw slice for Infinity (?view=) — array or associative array (object in JSON).
 *
 * @param array<string, mixed> $bundle Output of {@see st_integrations_build_dashboard_bundle} before `pull_client` is added
 *
 * @return array<int|string, mixed>
 */
function st_integrations_dashboard_raw_payload_for_view(string $view, array $bundle): array
{
    return match ($view) {
        'trends' => is_array($bundle['trends_summary'] ?? null) ? $bundle['trends_summary'] : [],
        'events' => is_array($bundle['recent_events'] ?? null) ? $bundle['recent_events'] : [],
        'metrics' => is_array($bundle['live_metrics'] ?? null) ? $bundle['live_metrics'] : [],
        'compliance' => is_array($bundle['compliance_snapshot'] ?? null) ? $bundle['compliance_snapshot'] : [],
        default => [],
    };
}
