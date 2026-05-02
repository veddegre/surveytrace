<?php
/**
 * Phase 13 — baselines, snapshot diffs, summaries, trends, compliance (library; no auth).
 * Uses scan_asset_snapshots / scan_finding_snapshots only (no duplicate snapshot storage).
 *
 * Concurrency: callers use short autocommit reads/writes (no long transactions). Baseline updates
 * use BEGIN IMMEDIATE … COMMIT. Scheduled materialization builds JSON in memory, then INSERT once.
 */

declare(strict_types=1);

/** @var string */
const ST_REPORTING_BASELINE_CONFIG_KEY = 'phase13_baseline_job_id';

/** Reject compare if either job has more than this many snapshot rows (assets + findings). */
const ST_REPORTING_COMPARE_MAX_SNAPSHOT_ROWS_PER_JOB = 200000;

/**
 * Structured reporting log line (PHP error_log; parse as JSON after the prefix).
 *
 * @param array<string,mixed> $data
 */
function st_reporting_log(string $event, array $data): void
{
    $data['_event'] = $event;
    $data['_ts_ms'] = (int) round(microtime(true) * 1000);
    $line = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($line === false) {
        $line = '{"_event":"' . $event . '","_encode_error":true}';
    }
    error_log('SurveyTrace.reporting ' . $line);
}

/**
 * @return array{assets:int, findings:int}
 */
function st_reporting_snapshot_row_counts(PDO $db, int $jobId): array
{
    $a = $db->prepare('SELECT COUNT(*) FROM scan_asset_snapshots WHERE job_id = ?');
    $a->execute([$jobId]);
    $f = $db->prepare('SELECT COUNT(*) FROM scan_finding_snapshots WHERE job_id = ?');
    $f->execute([$jobId]);

    return [
        'assets'   => (int) $a->fetchColumn(),
        'findings' => (int) $f->fetchColumn(),
    ];
}

/**
 * @throws InvalidArgumentException when snapshot volume is too large for compare APIs.
 */
function st_reporting_assert_compare_within_limits(PDO $db, int $jobA, int $jobB): void
{
    $ca = st_reporting_snapshot_row_counts($db, $jobA);
    $cb = st_reporting_snapshot_row_counts($db, $jobB);
    $ta = $ca['assets'] + $ca['findings'];
    $tb = $cb['assets'] + $cb['findings'];
    $max = ST_REPORTING_COMPARE_MAX_SNAPSHOT_ROWS_PER_JOB;
    if ($ta > $max || $tb > $max) {
        throw new InvalidArgumentException(
            "compare refused: snapshot row count exceeds soft limit ({$max} per job); job_a rows={$ta}, job_b rows={$tb}"
        );
    }
}

/**
 * Human-readable baseline validation (config vs effective job id).
 *
 * @return array<string,mixed>
 */
function st_reporting_baseline_explain(PDO $db): array
{
    $cfg = st_reporting_get_baseline_config_job_id($db);
    $base = [
        'baseline_config_job_id' => $cfg,
        'baseline_job_id'        => null,
        'validation_ok'          => false,
        'reason_code'            => 'not_configured',
        'reason_detail'          => 'config key phase13_baseline_job_id is empty or invalid',
    ];
    if ($cfg === null || $cfg <= 0) {
        $base['validation_ok'] = true;
        $base['reason_code'] = 'not_configured';
        $base['reason_detail'] = 'No baseline job id configured.';

        return $base;
    }
    $st = $db->prepare('SELECT id, status, deleted_at FROM scan_jobs WHERE id = ? LIMIT 1');
    $st->execute([$cfg]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        $base['reason_code'] = 'job_not_found';
        $base['reason_detail'] = "scan_jobs.id={$cfg} does not exist.";

        return $base;
    }
    $del = trim((string) ($row['deleted_at'] ?? ''));
    if ($del !== '') {
        $base['reason_code'] = 'job_trashed';
        $base['reason_detail'] = 'Job is soft-deleted (deleted_at set).';

        return $base;
    }
    if ((string) ($row['status'] ?? '') !== 'done') {
        $base['reason_code'] = 'job_not_done';
        $base['reason_detail'] = 'Baseline job must have status done.';

        return $base;
    }
    $chk = $db->prepare('SELECT 1 FROM scan_asset_snapshots WHERE job_id = ? LIMIT 1');
    $chk->execute([$cfg]);
    if ((int) $chk->fetchColumn() !== 1) {
        $base['reason_code'] = 'no_asset_snapshots';
        $base['reason_detail'] = 'Job has no scan_asset_snapshots rows.';

        return $base;
    }
    $base['baseline_job_id'] = $cfg;
    $base['validation_ok'] = true;
    $base['reason_code'] = 'ok';
    $base['reason_detail'] = null;

    return $base;
}

/**
 * Slim stored artifact: job/baseline metadata, summary counts, diff summary only (no full row lists).
 *
 * @param array<string,mixed> $full From st_reporting_build_report_payload (+ schedule fields).
 *
 * @return array<string,mixed>
 */
function st_reporting_artifact_ui_payload(array $full): array
{
    $compliance = $full['compliance'] ?? [];
    $out = [
        'schema_version'          => 1,
        'job_id'                  => (int) ($full['job_id'] ?? 0),
        'schedule_id'             => isset($full['schedule_id']) ? (int) $full['schedule_id'] : null,
        'schedule_name'           => isset($full['schedule_name']) ? (string) $full['schedule_name'] : null,
        'baseline_job_id'         => $full['baseline_job_id'] ?? null,
        'baseline_config_job_id'  => $full['baseline_config_job_id'] ?? null,
        'baseline_unavailable'    => (bool) ($full['baseline_unavailable'] ?? false),
        'generated_at'            => (string) ($full['generated_at'] ?? ''),
        'summary'                 => $full['summary'] ?? [],
        'delta'                   => $full['delta'] ?? [],
        'compliance_summary'      => [
            'job_id'            => (int) ($compliance['job_id'] ?? 0),
            'overall_pass'      => (bool) ($compliance['overall_pass'] ?? false),
            'baseline_job_id'   => $full['baseline_job_id'] ?? null,
        ],
    ];
    $d = $full['diff_vs_baseline'] ?? null;
    if ($d === null) {
        $out['diff_summary'] = null;
    } elseif (isset($d['error'])) {
        $out['diff_summary'] = [
            'error' => (string) $d['error'],
        ];
    } else {
        $out['diff_summary'] = [
            'job_a'          => (int) ($d['job_a'] ?? 0),
            'job_b'          => (int) ($d['job_b'] ?? 0),
            'semantics'      => (string) ($d['semantics'] ?? ''),
            'warnings'       => $d['warnings'] ?? [],
            'counts'         => $d['counts'] ?? [],
            'finding_events' => $d['finding_events'] ?? [],
        ];
    }

    return $out;
}

/**
 * Slim artifact view for API/UI (no full diff row arrays).
 *
 * @param array<string,mixed> $row DB row: id, created_at, schedule_id, baseline_job_id, compare_job_id, kind, title, plus decoded payload in key `payload` (not payload_json).
 *
 * @return array<string,mixed>
 */
function st_reporting_artifact_summary_for_response(array $row): array
{
    $payload = $row['payload'] ?? [];
    if (!is_array($payload)) {
        $payload = [];
    }
    $decodeWarn = $row['_decode_warning'] ?? null;
    $payloadWarning = ($decodeWarn !== null && $decodeWarn !== '') ? (string) $decodeWarn : null;

    $rid = (int) ($row['id'] ?? 0);
    $jobId = (int) ($payload['job_id'] ?? 0);
    if ($jobId <= 0) {
        $jobId = (int) ($row['compare_job_id'] ?? 0);
    }
    $baselineRow = $row['baseline_job_id'] ?? null;
    $baselinePayload = $payload['baseline_job_id'] ?? null;
    $effBaseline = null;
    if ($baselineRow !== null && $baselineRow !== '') {
        $effBaseline = (int) $baselineRow;
    } elseif ($baselinePayload !== null && $baselinePayload !== '') {
        $effBaseline = (int) $baselinePayload;
    }
    $summary = $payload['summary'] ?? [];
    if (!is_array($summary)) {
        $summary = [];
    }
    $delta = $payload['delta'] ?? [];
    if (!is_array($delta)) {
        $delta = [];
    }
    $diffSummaryIn = $payload['diff_summary'] ?? null;
    if ($diffSummaryIn !== null && !is_array($diffSummaryIn)) {
        $diffSummaryIn = null;
    }
    $complianceSummaryIn = $payload['compliance_summary'] ?? null;
    if ($complianceSummaryIn !== null && !is_array($complianceSummaryIn)) {
        $complianceSummaryIn = null;
    }
    $bcfgRaw = $payload['baseline_config_job_id'] ?? null;
    $bcfgOut = null;
    if ($bcfgRaw !== null && $bcfgRaw !== '') {
        $n = (int) $bcfgRaw;
        $bcfgOut = $n > 0 ? $n : null;
    }

    $out = [
        'artifact_id'            => $rid,
        'created_at'             => (string) ($row['created_at'] ?? ''),
        'schedule_id'            => isset($row['schedule_id']) ? (int) $row['schedule_id'] : null,
        'schedule_name'          => isset($payload['schedule_name']) ? (string) $payload['schedule_name'] : null,
        'title'                  => (string) ($row['title'] ?? ''),
        'kind'                   => (string) ($row['kind'] ?? ''),
        'compare_job_id'         => (int) ($row['compare_job_id'] ?? 0),
        'job_id'                 => $jobId,
        'baseline_job_id'        => $effBaseline,
        'baseline_config_job_id' => $bcfgOut,
        'baseline_unavailable'   => (bool) ($payload['baseline_unavailable'] ?? false),
        'generated_at'           => (string) ($payload['generated_at'] ?? ''),
        'schema_version'         => isset($payload['schema_version']) ? (int) $payload['schema_version'] : null,
        'summary'                => $summary,
        'delta'                  => $delta,
        'compliance_summary'     => $complianceSummaryIn,
        'diff_summary'           => $diffSummaryIn,
        'error'                  => isset($payload['error']) ? (string) $payload['error'] : null,
        'payload_warning'        => $payloadWarning,
    ];
    if ($out['diff_summary'] === null && isset($payload['diff_vs_baseline']) && is_array($payload['diff_vs_baseline'])) {
        $d = $payload['diff_vs_baseline'];
        if (isset($d['error'])) {
            $out['diff_summary'] = [
                'error' => (string) $d['error'],
            ];
        } else {
            $out['diff_summary'] = [
                'job_a'          => (int) ($d['job_a'] ?? 0),
                'job_b'          => (int) ($d['job_b'] ?? 0),
                'semantics'      => (string) ($d['semantics'] ?? ''),
                'warnings'       => is_array($d['warnings'] ?? null) ? $d['warnings'] : [],
                'counts'         => is_array($d['counts'] ?? null) ? $d['counts'] : [],
                'finding_events' => is_array($d['finding_events'] ?? null) ? $d['finding_events'] : [],
            ];
        }
    }
    if ($out['compliance_summary'] === null && isset($payload['compliance']) && is_array($payload['compliance'])) {
        $c = $payload['compliance'];
        $out['compliance_summary'] = [
            'job_id'          => (int) ($c['job_id'] ?? 0),
            'overall_pass'    => (bool) ($c['overall_pass'] ?? false),
            'baseline_job_id' => $out['baseline_job_id'],
        ];
    }

    return $out;
}

/**
 * Admin debug: sample rows for compare buckets (bounded).
 *
 * @return array<string,mixed>
 */
function st_reporting_compare_debug(PDO $db, int $jobA, int $jobB, int $sampleLimit): array
{
    if ($jobA <= 0 || $jobB <= 0 || $jobA === $jobB) {
        throw new InvalidArgumentException('job_a and job_b must be positive and distinct');
    }
    $sampleLimit = max(1, min(50, $sampleLimit));
    st_reporting_assert_compare_within_limits($db, $jobA, $jobB);
    $diff = st_reporting_compare_jobs($db, $jobA, $jobB);
    $slice = static function (array $rows, int $n): array {
        return array_slice($rows, 0, $n);
    };

    return [
        'job_a'               => $jobA,
        'job_b'               => $jobB,
        'sample_limit'        => $sampleLimit,
        'counts'              => $diff['counts'] ?? [],
        'finding_events'      => $diff['finding_events'] ?? [],
        'warnings'            => $diff['warnings'] ?? [],
        'assets_only_in_a'   => $slice($diff['assets_missing_in_b'] ?? [], $sampleLimit),
        'assets_only_in_b'   => $slice($diff['assets_new_in_b'] ?? [], $sampleLimit),
        'findings_only_in_a' => $slice($diff['findings_only_in_a'] ?? [], $sampleLimit),
        'findings_only_in_b' => $slice($diff['findings_new_in_b'] ?? [], $sampleLimit),
    ];
}

/**
 * @return list<int>
 */
function st_reporting_parse_ports_json(?string $json): array
{
    if ($json === null || $json === '') {
        return [];
    }
    $arr = json_decode($json, true);
    if (!is_array($arr)) {
        return [];
    }
    $out = [];
    foreach ($arr as $p) {
        $n = (int) $p;
        if ($n >= 1 && $n <= 65535) {
            $out[] = $n;
        }
    }
    $out = array_values(array_unique($out));
    sort($out, SORT_NUMERIC);

    return $out;
}

/**
 * Stable key for snapshot rows (prefer asset_id).
 */
function st_reporting_asset_key(array $row): string
{
    $aid = (int) ($row['asset_id'] ?? 0);
    if ($aid > 0) {
        return 'a:' . $aid;
    }
    $ip = trim((string) ($row['ip'] ?? ''));

    return 'ip:' . $ip;
}

/**
 * @param array<string,array<string,mixed>> $byKey
 * @return list<string>
 */
function st_reporting_sorted_keys(array $byKey): array
{
    $k = array_keys($byKey);
    sort($k, SORT_STRING);

    return $k;
}

/**
 * Compare two completed scan jobs (A = reference / baseline, B = current).
 *
 * @return array<string,mixed>
 */
function st_reporting_compare_jobs(PDO $db, int $jobA, int $jobB): array
{
    if ($jobA <= 0 || $jobB <= 0 || $jobA === $jobB) {
        throw new InvalidArgumentException('job_a and job_b must be positive and distinct');
    }
    $t0 = microtime(true);

    $chk = $db->prepare('SELECT id, status FROM scan_jobs WHERE id IN (?,?)');
    $chk->execute([$jobA, $jobB]);
    $rows = $chk->fetchAll(PDO::FETCH_ASSOC);
    if (count($rows) < 2) {
        throw new InvalidArgumentException('one or both job ids not found');
    }
    st_reporting_assert_compare_within_limits($db, $jobA, $jobB);
    $statusById = [];
    foreach ($rows as $r) {
        $statusById[(int) $r['id']] = (string) ($r['status'] ?? '');
    }
    $warnings = [];
    foreach ([$jobA => 'job_a', $jobB => 'job_b'] as $jid => $label) {
        if (($statusById[$jid] ?? '') !== 'done') {
            $warnings[] = "{$label} (id {$jid}) status is not 'done'; snapshots may be incomplete";
        }
    }

    $stmtA = $db->prepare(
        'SELECT asset_id, ip, hostname, category, vendor, top_cve, top_cvss, open_ports, device_id
         FROM scan_asset_snapshots WHERE job_id = ?'
    );
    $stmtA->execute([$jobA]);
    $assetsA = [];
    foreach ($stmtA->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $assetsA[st_reporting_asset_key($r)] = $r;
    }

    $stmtB = $db->prepare(
        'SELECT asset_id, ip, hostname, category, vendor, top_cve, top_cvss, open_ports, device_id
         FROM scan_asset_snapshots WHERE job_id = ?'
    );
    $stmtB->execute([$jobB]);
    $assetsB = [];
    foreach ($stmtB->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $assetsB[st_reporting_asset_key($r)] = $r;
    }

    $keysA = array_fill_keys(array_keys($assetsA), true);
    $keysB = array_fill_keys(array_keys($assetsB), true);

    $newHosts = [];
    $removedHosts = [];
    $portChanges = [];

    foreach (array_keys($keysB) as $k) {
        if (!isset($keysA[$k])) {
            $r = $assetsB[$k];
            $newHosts[] = [
                'key'       => $k,
                'asset_id'  => (int) ($r['asset_id'] ?? 0),
                'ip'        => (string) ($r['ip'] ?? ''),
                'hostname'  => (string) ($r['hostname'] ?? ''),
                'category'  => (string) ($r['category'] ?? ''),
            ];
        }
    }
    foreach (array_keys($keysA) as $k) {
        if (!isset($keysB[$k])) {
            $r = $assetsA[$k];
            $removedHosts[] = [
                'key'       => $k,
                'asset_id'  => (int) ($r['asset_id'] ?? 0),
                'ip'        => (string) ($r['ip'] ?? ''),
                'hostname'  => (string) ($r['hostname'] ?? ''),
                'category'  => (string) ($r['category'] ?? ''),
            ];
        }
    }

    foreach (array_keys($keysA) as $k) {
        if (!isset($assetsB[$k])) {
            continue;
        }
        $pa = st_reporting_parse_ports_json((string) ($assetsA[$k]['open_ports'] ?? ''));
        $pb = st_reporting_parse_ports_json((string) ($assetsB[$k]['open_ports'] ?? ''));
        $added = array_values(array_diff($pb, $pa));
        $removed = array_values(array_diff($pa, $pb));
        if ($added !== [] || $removed !== []) {
            $ra = $assetsA[$k];
            $portChanges[] = [
                'key'          => $k,
                'asset_id'     => (int) ($ra['asset_id'] ?? 0),
                'ip'           => (string) ($ra['ip'] ?? ''),
                'ports_added'  => $added,
                'ports_removed'=> $removed,
            ];
        }
    }

    $findA = $db->prepare(
        'SELECT asset_id, cve_id, cvss, severity, COALESCE(resolved,0) AS resolved
         FROM scan_finding_snapshots WHERE job_id = ?'
    );
    $findA->execute([$jobA]);
    $fA = [];
    foreach ($findA->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $k = (string) (int) $r['asset_id'] . '|' . strtolower(trim((string) $r['cve_id']));
        $fA[$k] = $r;
    }

    $findB = $db->prepare(
        'SELECT asset_id, cve_id, cvss, severity, COALESCE(resolved,0) AS resolved
         FROM scan_finding_snapshots WHERE job_id = ?'
    );
    $findB->execute([$jobB]);
    $fB = [];
    foreach ($findB->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $k = (string) (int) $r['asset_id'] . '|' . strtolower(trim((string) $r['cve_id']));
        $fB[$k] = $r;
    }

    $newFindings = [];
    $missingInB = [];
    $resolutionChanges = [];

    foreach ($fB as $k => $rb) {
        if (!isset($fA[$k])) {
            $newFindings[] = [
                'asset_id' => (int) $rb['asset_id'],
                'cve_id'   => (string) $rb['cve_id'],
                'cvss'     => $rb['cvss'] !== null ? (float) $rb['cvss'] : null,
                'severity' => (string) ($rb['severity'] ?? ''),
                'resolved' => (int) $rb['resolved'],
            ];
        } else {
            $ra = $fA[$k];
            $raR = (int) $ra['resolved'];
            $rbR = (int) $rb['resolved'];
            if ($raR !== $rbR) {
                $resolutionChanges[] = [
                    'asset_id'      => (int) $rb['asset_id'],
                    'cve_id'        => (string) $rb['cve_id'],
                    'resolved_before'=> $raR,
                    'resolved_after' => $rbR,
                ];
            }
        }
    }

    foreach ($fA as $k => $ra) {
        if (!isset($fB[$k])) {
            $missingInB[] = [
                'asset_id' => (int) $ra['asset_id'],
                'cve_id'   => (string) $ra['cve_id'],
                'cvss'     => $ra['cvss'] !== null ? (float) $ra['cvss'] : null,
                'severity' => (string) ($ra['severity'] ?? ''),
                'resolved' => (int) $ra['resolved'],
            ];
        }
    }

    $markedResolved = 0;
    $reopened = 0;
    foreach ($resolutionChanges as $rc) {
        $b0 = (int) ($rc['resolved_before'] ?? 0);
        $b1 = (int) ($rc['resolved_after'] ?? 0);
        if ($b0 === 0 && $b1 === 1) {
            $markedResolved++;
        } elseif ($b0 === 1 && $b1 === 0) {
            $reopened++;
        }
    }
    $openAbsentInB = 0;
    foreach ($missingInB as $m) {
        if ((int) ($m['resolved'] ?? 0) === 0) {
            $openAbsentInB++;
        }
    }

    $portHistoryHints = [];
    $phStmt = $db->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='port_history' LIMIT 1");
    if ($phStmt && (int) $phStmt->fetchColumn() === 1 && $portChanges !== []) {
        $hist = $db->prepare(
            'SELECT scan_id, ports, seen_at FROM port_history
             WHERE asset_id = ? AND scan_id IN (?,?) ORDER BY seen_at DESC LIMIT 4'
        );
        foreach ($portChanges as $pc) {
            $aid = (int) ($pc['asset_id'] ?? 0);
            if ($aid <= 0) {
                continue;
            }
            $hist->execute([$aid, $jobA, $jobB]);
            $rows = $hist->fetchAll(PDO::FETCH_ASSOC);
            if ($rows) {
                $portHistoryHints[] = [
                    'asset_id' => $aid,
                    'ip'       => (string) ($pc['ip'] ?? ''),
                    'entries'  => array_map(static function (array $h): array {
                        return [
                            'scan_id' => (int) ($h['scan_id'] ?? 0),
                            'ports'   => st_reporting_parse_ports_json((string) ($h['ports'] ?? '')),
                            'seen_at' => (string) ($h['seen_at'] ?? ''),
                        ];
                    }, $rows),
                ];
            }
        }
    }

    $counts = [
        'assets_a'                        => count($assetsA),
        'assets_b'                        => count($assetsB),
        'new_hosts'                       => count($newHosts),
        'removed_hosts'                   => count($removedHosts),
        'hosts_with_port_delta'           => count($portChanges),
        'new_findings_rows'               => count($newFindings),
        'findings_absent_in_b'            => count($missingInB),
        'resolution_changes'              => count($resolutionChanges),
        'marked_resolved_in_b'            => $markedResolved,
        'reopened_in_b'                   => $reopened,
        'open_in_a_absent_in_b'           => $openAbsentInB,
        // UI-oriented aliases (same semantics as legacy keys above).
        'assets_only_in_a'                => count($removedHosts),
        'assets_only_in_b'                => count($newHosts),
        'findings_only_in_a'              => count($missingInB),
        'findings_only_in_b'              => count($newFindings),
    ];

    $durationMs = (int) round((microtime(true) - $t0) * 1000);
    st_reporting_log('reporting.compare', [
        'job_a'        => $jobA,
        'job_b'        => $jobB,
        'duration_ms'  => $durationMs,
        'counts'       => $counts,
    ]);

    return [
        'job_a'               => $jobA,
        'job_b'               => $jobB,
        'warnings'            => $warnings,
        'semantics'           => 'A=reference/baseline, B=current',
        'assets_new_in_b'     => $newHosts,
        'assets_missing_in_b' => $removedHosts,
        'asset_port_changes'  => $portChanges,
        'port_history_hints'  => $portHistoryHints,
        'findings_new_in_b'   => $newFindings,
        // Rows present in A’s snapshot but not in B’s (CVE not re-observed in B’s run — not live findings table).
        'findings_only_in_a'  => $missingInB,
        'finding_resolution_changes' => $resolutionChanges,
        'finding_events'      => [
            'marked_resolved_in_b'            => $markedResolved,
            'reopened_in_b'                   => $reopened,
            'open_in_a_absent_in_b_snapshots' => $openAbsentInB,
        ],
        'counts'              => $counts,
    ];
}

/**
 * @return array<string,mixed>
 */
function st_reporting_summary_for_job(PDO $db, int $jobId): array
{
    if ($jobId <= 0) {
        throw new InvalidArgumentException('invalid job id');
    }

    $stc = $db->prepare('SELECT COUNT(*) FROM scan_asset_snapshots WHERE job_id = ?');
    $stc->execute([$jobId]);
    $assetCount = (int) $stc->fetchColumn();

    $sevStmt = $db->prepare(
        "SELECT COALESCE(severity,'') AS sev, COUNT(*) AS c
         FROM scan_finding_snapshots
         WHERE job_id = ? AND COALESCE(resolved,0) = 0
         GROUP BY COALESCE(severity,'')"
    );
    $sevStmt->execute([$jobId]);
    $bySev = [];
    foreach ($sevStmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $bySev[(string) $r['sev']] = (int) $r['c'];
    }

    $openTotal = array_sum($bySev);

    return [
        'job_id'              => $jobId,
        'asset_snapshots'    => $assetCount,
        'open_findings_total'=> $openTotal,
        'open_findings_by_severity' => $bySev,
    ];
}

/**
 * Summary + diff vs baseline when baseline job id is set.
 *
 * @return array<string,mixed>
 */
function st_reporting_build_report_payload(PDO $db, int $jobB, ?int $baselineJobId): array
{
    $t0 = microtime(true);
    $summary = st_reporting_summary_for_job($db, $jobB);
    $diff = null;
    $effBaseline = $baselineJobId !== null && $baselineJobId > 0
        ? st_reporting_resolve_baseline_job_id($db, $baselineJobId)
        : null;
    $baselineUnavailable = ($baselineJobId !== null && $baselineJobId > 0 && $effBaseline === null);
    if ($baselineUnavailable) {
        st_reporting_log('reporting.baseline_resolve', [
            'job_id'                 => $jobB,
            'baseline_config_job_id' => $baselineJobId,
            'baseline_job_id'        => null,
            'baseline_unavailable'   => true,
        ]);
    }
    if ($effBaseline !== null && $effBaseline !== $jobB) {
        try {
            $diff = st_reporting_compare_jobs($db, $effBaseline, $jobB);
        } catch (Throwable $e) {
            $diff = ['error' => $e->getMessage()];
        }
    }
    $newResolved = ['new_open_cves' => 0, 'resolved_since_baseline' => 0];
    if (is_array($diff) && !isset($diff['error'])) {
        $newResolved['new_open_cves'] = count(array_filter(
            $diff['findings_new_in_b'] ?? [],
            static fn (array $x): bool => (int) ($x['resolved'] ?? 0) === 0
        ));
        $newResolved['resolved_since_baseline'] = count(array_filter(
            $diff['finding_resolution_changes'] ?? [],
            static fn (array $x): bool => (int) ($x['resolved_before'] ?? 0) === 0 && (int) ($x['resolved_after'] ?? 0) === 1
        ));
    }

    $payload = [
        'job_id'                 => $jobB,
        // Effective baseline used for diff/compliance (null if config unset or invalid).
        'baseline_job_id'        => $effBaseline,
        'baseline_config_job_id' => ($baselineJobId !== null && $baselineJobId > 0) ? $baselineJobId : null,
        'baseline_unavailable'   => $baselineUnavailable,
        'summary'                => $summary,
        'diff_vs_baseline'       => $diff,
        'delta'                  => $newResolved,
        'compliance'             => st_reporting_compliance($db, $jobB, $baselineJobId),
        'generated_at'           => gmdate('Y-m-d\TH:i:s\Z'),
    ];
    $rpLog = [
        'job_id'                  => $jobB,
        'baseline_config_job_id'=> $payload['baseline_config_job_id'],
        'baseline_job_id'       => $effBaseline,
        'duration_ms'           => (int) round((microtime(true) - $t0) * 1000),
        'has_diff'              => is_array($diff) && !isset($diff['error']),
    ];
    if (is_array($diff) && isset($diff['error'])) {
        $rpLog['diff_error'] = (string) $diff['error'];
    }
    st_reporting_log('reporting.report_payload', $rpLog);

    return $payload;
}

/**
 * Lightweight trends from recent completed jobs (snapshot counts).
 * Uses a small bounded number of aggregate queries (not N+1 per job).
 *
 * @return list<array<string,mixed>>
 */
function st_reporting_trends(PDO $db, int $limit = 30): array
{
    $limit = max(1, min(200, $limit));
    $jobs = $db->prepare(
        "SELECT id, finished_at, label, status
         FROM scan_jobs
         WHERE status = 'done' AND (deleted_at IS NULL OR deleted_at = '')
           AND finished_at IS NOT NULL
         ORDER BY datetime(finished_at) DESC, id DESC
         LIMIT $limit"
    );
    $jobs->execute();
    $jobRows = $jobs->fetchAll(PDO::FETCH_ASSOC);
    if ($jobRows === []) {
        return [];
    }
    $ids = array_map(static fn (array $j): int => (int) $j['id'], $jobRows);
    $placeholders = implode(',', array_fill(0, count($ids), '?'));

    $assetCounts = [];
    $ac = $db->prepare("SELECT job_id, COUNT(*) AS c FROM scan_asset_snapshots WHERE job_id IN ($placeholders) GROUP BY job_id");
    $ac->execute($ids);
    foreach ($ac->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $assetCounts[(int) $r['job_id']] = (int) $r['c'];
    }

    $sevByJob = [];
    $fs = $db->prepare(
        "SELECT job_id, COALESCE(severity,'') AS sev, COUNT(*) AS c
         FROM scan_finding_snapshots
         WHERE job_id IN ($placeholders) AND COALESCE(resolved,0) = 0
         GROUP BY job_id, COALESCE(severity,'')"
    );
    $fs->execute($ids);
    foreach ($fs->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $jid = (int) $r['job_id'];
        if (!isset($sevByJob[$jid])) {
            $sevByJob[$jid] = [];
        }
        $sevByJob[$jid][(string) $r['sev']] = (int) $r['c'];
    }

    $out = [];
    foreach ($jobRows as $j) {
        $jid = (int) $j['id'];
        $bySev = $sevByJob[$jid] ?? [];
        $out[] = [
            'job_id'      => $jid,
            'finished_at' => (string) ($j['finished_at'] ?? ''),
            'label'       => (string) ($j['label'] ?? ''),
            'assets'      => (int) ($assetCounts[$jid] ?? 0),
            'open_findings_total' => array_sum($bySev),
            'open_findings_by_severity' => $bySev,
        ];
    }

    return $out;
}

/**
 * Trend points for UI: canonical keys, max 50 jobs per request.
 * Reuses {@see st_reporting_trends} (two batched GROUP BY queries on job_id IN (...), no per-job N+1).
 *
 * @return list<array{job_id:int,timestamp:string,asset_count:int,open_findings_total:int,open_findings_by_severity:array<string,int>,label:string}>
 */
function st_reporting_trends_summary(PDO $db, int $limit = 30): array
{
    $limit = max(1, min(50, $limit));
    $raw = st_reporting_trends($db, $limit);
    $out = [];
    foreach ($raw as $row) {
        $out[] = [
            'job_id'                     => (int) ($row['job_id'] ?? 0),
            'timestamp'                  => (string) ($row['finished_at'] ?? ''),
            'asset_count'                => (int) ($row['assets'] ?? 0),
            'open_findings_total'        => (int) ($row['open_findings_total'] ?? 0),
            'open_findings_by_severity' => is_array($row['open_findings_by_severity'] ?? null)
                ? $row['open_findings_by_severity']
                : [],
            'label'                      => (string) ($row['label'] ?? ''),
        ];
    }

    return $out;
}

/**
 * Rule-based compliance (Phase 13 initial).
 *
 * @return array<string,mixed>
 */
function st_reporting_compliance(PDO $db, int $jobB, ?int $baselineJobId): array
{
    $summary = st_reporting_summary_for_job($db, $jobB);
    $bySev = $summary['open_findings_by_severity'] ?? [];
    $critOpen = (int) ($bySev['critical'] ?? 0);

    $rules = [
        'no_critical_open' => [
            'pass'  => $critOpen === 0,
            'detail'=> $critOpen === 0 ? 'No open critical findings in snapshot.' : "Open critical count: {$critOpen}",
        ],
    ];

    $newHigh = 0;
    $effBaseline = $baselineJobId !== null && $baselineJobId > 0
        ? st_reporting_resolve_baseline_job_id($db, $baselineJobId)
        : null;
    if ($effBaseline !== null && $effBaseline !== $jobB) {
        try {
            $diff = st_reporting_compare_jobs($db, $effBaseline, $jobB);
            foreach ($diff['findings_new_in_b'] ?? [] as $f) {
                if ((int) ($f['resolved'] ?? 0) !== 0) {
                    continue;
                }
                $sev = strtolower((string) ($f['severity'] ?? ''));
                if ($sev === 'high' || $sev === 'critical') {
                    $newHigh++;
                }
            }
        } catch (Throwable $e) {
            $newHigh = -1;
        }
        $rules['no_new_high_or_critical_vs_baseline'] = [
            'pass'   => $newHigh === 0,
            'detail' => $newHigh < 0
                ? 'Could not compare to baseline.'
                : ($newHigh === 0
                    ? 'No new open high/critical findings vs baseline snapshot.'
                    : "New open high/critical rows vs baseline: {$newHigh}"),
        ];
    }

    return [
        'job_id'                  => $jobB,
        'baseline_config_id'      => $baselineJobId,
        'baseline_config_job_id'  => $baselineJobId,
        'baseline_effective'      => $effBaseline,
        'baseline_job_id'         => $effBaseline,
        'rules'                   => $rules,
        'overall_pass'            => !in_array(false, array_column($rules, 'pass'), true),
    ];
}

/** Configured baseline job id from `config` (may point at a deleted or invalid job). */
function st_reporting_get_baseline_config_job_id(PDO $db): ?int
{
    $st = $db->prepare('SELECT value FROM config WHERE key = ? LIMIT 1');
    $st->execute([ST_REPORTING_BASELINE_CONFIG_KEY]);
    $v = $st->fetchColumn();
    if ($v === false || $v === null || $v === '') {
        return null;
    }
    $n = (int) $v;

    return $n > 0 ? $n : null;
}

/**
 * Baseline id safe for comparisons: job must exist, be done, not trashed, and have snapshots.
 */
function st_reporting_resolve_baseline_job_id(PDO $db, ?int $configJobId): ?int
{
    if ($configJobId === null || $configJobId <= 0) {
        return null;
    }
    $chk = $db->prepare(
        "SELECT j.id FROM scan_jobs j
         WHERE j.id = ? AND j.status = 'done' AND (j.deleted_at IS NULL OR j.deleted_at = '')
           AND EXISTS (SELECT 1 FROM scan_asset_snapshots s WHERE s.job_id = j.id LIMIT 1)
         LIMIT 1"
    );
    $chk->execute([$configJobId]);
    $id = $chk->fetchColumn();

    return $id !== false && $id !== null ? (int) $id : null;
}

/** @deprecated use st_reporting_get_baseline_config_job_id + resolve; kept for callers expecting config-only */
function st_reporting_get_baseline_job_id(PDO $db): ?int
{
    return st_reporting_get_baseline_config_job_id($db);
}

/**
 * Mark a completed job as the global baseline (clears other is_baseline flags).
 */
function st_reporting_set_baseline(PDO $db, int $jobId): void
{
    if ($jobId <= 0) {
        throw new InvalidArgumentException('invalid job id');
    }
    $chk = $db->prepare("SELECT id, status FROM scan_jobs WHERE id = ? AND (deleted_at IS NULL OR deleted_at = '') LIMIT 1");
    $chk->execute([$jobId]);
    $row = $chk->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        throw new InvalidArgumentException('job not found');
    }
    if ((string) ($row['status'] ?? '') !== 'done') {
        throw new InvalidArgumentException('baseline must be a completed (done) scan job');
    }
    $cntStmt = $db->prepare('SELECT COUNT(*) FROM scan_asset_snapshots WHERE job_id = ?');
    $cntStmt->execute([$jobId]);
    if ((int) $cntStmt->fetchColumn() < 1) {
        throw new InvalidArgumentException('job has no asset snapshots; run must have finished with inventory data');
    }

    $db->exec('BEGIN IMMEDIATE');
    try {
        $db->exec('UPDATE scan_jobs SET is_baseline = 0 WHERE COALESCE(is_baseline,0) = 1');
        $db->prepare('UPDATE scan_jobs SET is_baseline = 1 WHERE id = ?')->execute([$jobId]);
        $db->prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)')
            ->execute([ST_REPORTING_BASELINE_CONFIG_KEY, (string) $jobId]);
        $db->exec('COMMIT');
    } catch (Throwable $e) {
        try {
            $db->exec('ROLLBACK');
        } catch (Throwable $e2) {
        }
        throw $e;
    }
    st_reporting_log('reporting.baseline_set', [
        'job_id' => $jobId,
    ]);
}

/**
 * Persist a scheduled report row (called from CLI after migration).
 */
function st_reporting_insert_artifact(
    PDO $db,
    int $scheduleId,
    ?int $baselineJobId,
    int $compareJobId,
    string $title,
    array $payload
): int {
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    $json = json_encode($payload, $flags);
    if ($json === false) {
        $json = '{"error":"json_encode_failed"}';
    }
    $db->prepare(
        'INSERT INTO report_artifacts (schedule_id, baseline_job_id, compare_job_id, kind, title, payload_json)
         VALUES (?,?,?,?,?,?)'
    )->execute([
        $scheduleId,
        $baselineJobId,
        $compareJobId,
        'scheduled',
        $title,
        $json,
    ]);

    return (int) $db->lastInsertId();
}

/**
 * Run from reporting_cli.php for a due report schedule.
 *
 * @return int Inserted report_artifacts.id (0 if none inserted — should not happen)
 */
function st_reporting_materialize_scheduled(PDO $db, int $scheduleId): int
{
    $t0 = microtime(true);
    st_reporting_log('reporting.materialize_start', [
        'schedule_id' => $scheduleId,
    ]);

    $sch = $db->prepare('SELECT id, name FROM scan_schedules WHERE id = ? LIMIT 1');
    $sch->execute([$scheduleId]);
    $srow = $sch->fetch(PDO::FETCH_ASSOC);
    if (!$srow) {
        throw new InvalidArgumentException('schedule not found');
    }

    $baselineCfg = st_reporting_get_baseline_config_job_id($db);
    $baseline = st_reporting_resolve_baseline_job_id($db, $baselineCfg);
    st_reporting_log('reporting.baseline_resolve', [
        'schedule_id'            => $scheduleId,
        'baseline_config_job_id' => $baselineCfg,
        'baseline_job_id'        => $baseline,
        'baseline_unavailable'   => ($baselineCfg !== null && $baselineCfg > 0 && $baseline === null),
    ]);

    $latestStmt = $db->query(
        "SELECT id FROM scan_jobs
         WHERE status = 'done' AND (deleted_at IS NULL OR deleted_at = '')
           AND finished_at IS NOT NULL
         ORDER BY datetime(finished_at) DESC, id DESC LIMIT 1"
    );
    $latestRow = $latestStmt ? $latestStmt->fetch(PDO::FETCH_ASSOC) : false;
    $latestId = $latestRow ? (int) ($latestRow['id'] ?? 0) : 0;

    if ($latestId <= 0) {
        $artifactId = st_reporting_insert_artifact(
            $db,
            $scheduleId,
            $baseline,
            0,
            'Scheduled report — ' . (string) $srow['name'],
            [
                'schema_version'         => 1,
                'error'                  => 'no_completed_scan_with_snapshots',
                'schedule_id'            => $scheduleId,
                'schedule_name'          => (string) ($srow['name'] ?? ''),
                'job_id'                 => 0,
                'baseline_job_id'        => $baseline,
                'baseline_config_job_id' => $baselineCfg,
                'baseline_unavailable'   => ($baselineCfg !== null && $baselineCfg > 0 && $baseline === null),
                'generated_at'           => gmdate('Y-m-d\TH:i:s\Z'),
            ]
        );
        $durationMs = (int) round((microtime(true) - $t0) * 1000);
        st_reporting_log('reporting.materialize_end', [
            'schedule_id'   => $scheduleId,
            'artifact_id'   => $artifactId,
            'compare_job_id'=> 0,
            'duration_ms'   => $durationMs,
            'outcome'       => 'no_scan',
        ]);

        return $artifactId;
    }

    $payload = st_reporting_build_report_payload($db, $latestId, $baselineCfg);
    $payload['schedule_id'] = $scheduleId;
    $payload['schedule_name'] = (string) ($srow['name'] ?? '');
    $uiPayload = st_reporting_artifact_ui_payload($payload);

    $artifactId = st_reporting_insert_artifact(
        $db,
        $scheduleId,
        $baseline,
        $latestId,
        'Scheduled report — ' . (string) $srow['name'],
        $uiPayload
    );
    $durationMs = (int) round((microtime(true) - $t0) * 1000);
    st_reporting_log('reporting.materialize_end', [
        'schedule_id'    => $scheduleId,
        'artifact_id'    => $artifactId,
        'compare_job_id' => $latestId,
        'baseline_job_id'=> $baseline,
        'duration_ms'    => $durationMs,
        'outcome'        => 'ok',
    ]);

    return $artifactId;
}
