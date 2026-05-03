<?php
/**
 * Reporting external contract — canonical event shape and scope context.
 *
 * Outbound delivery (Phase 14.1+): push targets configured in **`integrations`** (admin UI / API) send
 * this contract manually (test/sample) or via future automation; **`api/lib_integrations_outbound.php`**
 * remains for optional legacy Settings webhook. Integrations must not alter **`schema_version`** or
 * the field layout defined here.
 *
 * Use this file as the contract reference for:
 * - Normalized event payloads derived from existing producers
 * - `scope_context` on selected reporting GET responses
 *
 * Snapshot vs live:
 * - Reporting `trends_summary`, `compare_summary`, and `compliance` are **snapshot**-based (frozen
 *   per-job tables). Live inventory is **`dashboard.php`** and related asset APIs — never mix
 *   semantics in downstream consumers without labeling `data_plane`.
 */

declare(strict_types=1);

require_once __DIR__ . '/lib_scan_scopes.php';

/**
 * Request scope filter echoed on external-friendly reporting responses.
 * `scope_filter` null = all scopes (no filter); 0 = unscoped-only; N = named scope id.
 *
 * @return array{scope_filter: ?int, scope_id: ?int, scope_name: ?string, scope_kind: string}
 */
function st_reporting_scope_context_for_response(PDO $db, ?int $scopeFilter): array
{
    if ($scopeFilter === null) {
        return [
            'scope_filter' => null,
            'scope_id'     => null,
            'scope_name'   => null,
            'scope_kind'   => 'all',
        ];
    }
    if ($scopeFilter === 0) {
        return [
            'scope_filter' => 0,
            'scope_id'     => 0,
            'scope_name'   => null,
            'scope_kind'   => 'unscoped',
        ];
    }

    return [
        'scope_filter' => $scopeFilter,
        'scope_id'     => $scopeFilter,
        'scope_name'   => st_scan_scopes_resolve_name($db, $scopeFilter),
        'scope_kind'   => 'named',
    ];
}

/**
 * Canonical event skeleton (integrators map producers into this shape).
 * Keys are stable; optional sections may be omitted or null when unknown.
 *
 * @return array<string, mixed>
 */
function st_reporting_event_canonical_skeleton(): array
{
    return [
        'schema_version' => 'surveytrace.reporting.event.v1',
        'event_id'       => null,
        'source'         => null,
        'occurred_at'    => null,
        'event_type'     => null,
        'severity'       => null,
        'scope'          => [
            'scope_id'   => null,
            'scope_name' => null,
        ],
        'subject'        => [
            'job_id'     => null,
            'finding_id' => null,
            'asset_id'   => null,
        ],
        'data_plane'     => 'snapshot',
        'payload'        => [],
    ];
}

/**
 * Map a `change_alerts.php` list row into the canonical event shape (read-only transform).
 *
 * @param array<string, mixed> $apiRow
 *
 * @return array<string, mixed>
 */
function st_reporting_event_from_change_alert_row(array $apiRow): array
{
    $e = st_reporting_event_canonical_skeleton();
    $e['event_id'] = 'change_alert:' . (string) ($apiRow['id'] ?? '');
    $e['source'] = 'change_alerts';
    $e['occurred_at'] = (string) ($apiRow['created_at'] ?? '');
    $e['event_type'] = 'change.' . (string) ($apiRow['alert_type'] ?? 'unknown');
    $e['subject']['job_id'] = (int) ($apiRow['job_id'] ?? 0);
    $e['subject']['asset_id'] = isset($apiRow['asset_id']) ? (int) $apiRow['asset_id'] : null;
    $e['subject']['finding_id'] = isset($apiRow['finding_id']) ? (int) $apiRow['finding_id'] : null;
    $e['data_plane'] = 'live';
    $e['payload'] = [
        'detail'       => is_array($apiRow['detail'] ?? null) ? $apiRow['detail'] : [],
        'asset_ip'     => (string) ($apiRow['asset_ip'] ?? ''),
        'dismissed_at' => $apiRow['dismissed_at'] ?? null,
    ];

    return $e;
}

/**
 * Map reporting `compliance` payload fragment into the canonical event shape.
 *
 * @param array<string, mixed> $compliance
 *
 * @return array<string, mixed>
 */
function st_reporting_event_from_compliance_summary(array $compliance): array
{
    $e = st_reporting_event_canonical_skeleton();
    $jid = (int) ($compliance['job_id'] ?? 0);
    $e['event_id'] = 'compliance:' . (string) $jid;
    $e['source'] = 'reporting.compliance';
    $e['event_type'] = 'compliance.evaluated';
    $e['subject']['job_id'] = $jid;
    $sid = (int) ($compliance['scope_id'] ?? 0);
    $e['scope']['scope_id'] = $sid > 0 ? $sid : 0;
    $e['scope']['scope_name'] = $compliance['scope_name'] ?? null;
    $e['data_plane'] = 'snapshot';
    $e['payload'] = [
        'overall_pass' => (bool) ($compliance['overall_pass'] ?? false),
        'rules'        => $compliance['rules'] ?? [],
    ];

    return $e;
}

/**
 * Map a `report_artifacts` list row (metadata) into the canonical event shape.
 *
 * @param array<string, mixed> $artifactRow
 *
 * @return array<string, mixed>
 */
function st_reporting_event_from_report_artifact_row(array $artifactRow): array
{
    $e = st_reporting_event_canonical_skeleton();
    $id = (int) ($artifactRow['id'] ?? 0);
    $e['event_id'] = 'report_artifact:' . (string) $id;
    $e['source'] = 'reporting.artifacts';
    $e['occurred_at'] = (string) ($artifactRow['created_at'] ?? '');
    $e['event_type'] = 'report.created';
    $e['subject']['job_id'] = (int) ($artifactRow['compare_job_id'] ?? $artifactRow['job_id'] ?? 0);
    $e['data_plane'] = 'snapshot';
    $e['payload'] = [
        'artifact_id'     => $id,
        'schedule_id'     => $artifactRow['schedule_id'] ?? null,
        'baseline_job_id' => $artifactRow['baseline_job_id'] ?? null,
        'title'           => $artifactRow['title'] ?? null,
    ];

    return $e;
}

/**
 * Add top-level `scope_id` / `scope_name` (mirrors `scope.*`) for JSON dashboards and SPL `jsonpath`
 * without changing the canonical nested `scope` object.
 *
 * @param array<string, mixed> $e
 *
 * @return array<string, mixed>
 */
function st_reporting_event_envelope_scope_fields(array $e): array
{
    $sc = is_array($e['scope'] ?? null) ? $e['scope'] : [];
    $e['scope_id'] = array_key_exists('scope_id', $sc) ? $sc['scope_id'] : null;
    $e['scope_name'] = array_key_exists('scope_name', $sc) ? $sc['scope_name'] : null;

    return $e;
}
