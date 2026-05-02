<?php
/**
 * Phase 13 — baselines, snapshot diffs, summaries, trends, compliance (library; no auth).
 * Uses scan_asset_snapshots / scan_finding_snapshots only (no duplicate snapshot storage).
 */

declare(strict_types=1);

/** @var string */
const ST_REPORTING_BASELINE_CONFIG_KEY = 'phase13_baseline_job_id';

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

    $chk = $db->prepare('SELECT id, status FROM scan_jobs WHERE id IN (?,?)');
    $chk->execute([$jobA, $jobB]);
    $rows = $chk->fetchAll(PDO::FETCH_ASSOC);
    if (count($rows) < 2) {
        throw new InvalidArgumentException('one or both job ids not found');
    }
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
        $k = (int) $r['asset_id'] . '|' . strtolower(trim((string) $r['cve_id']));
        $fA[$k] = $r;
    }

    $findB = $db->prepare(
        'SELECT asset_id, cve_id, cvss, severity, COALESCE(resolved,0) AS resolved
         FROM scan_finding_snapshots WHERE job_id = ?'
    );
    $findB->execute([$jobB]);
    $fB = [];
    foreach ($findB->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $k = (int) $r['asset_id'] . '|' . strtolower(trim((string) $r['cve_id']));
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
        'findings_only_in_a'=> $missingInB,
        'finding_resolution_changes' => $resolutionChanges,
        'counts'              => [
            'assets_a'              => count($assetsA),
            'assets_b'              => count($assetsB),
            'new_hosts'             => count($newHosts),
            'removed_hosts'         => count($removedHosts),
            'hosts_with_port_delta' => count($portChanges),
            'new_findings_rows'     => count($newFindings),
            'findings_absent_in_b'  => count($missingInB),
            'resolution_changes'    => count($resolutionChanges),
        ],
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
    $summary = st_reporting_summary_for_job($db, $jobB);
    $diff = null;
    if ($baselineJobId !== null && $baselineJobId > 0 && $baselineJobId !== $jobB) {
        try {
            $diff = st_reporting_compare_jobs($db, $baselineJobId, $jobB);
        } catch (Throwable $e) {
            $diff = ['error' => $e->getMessage()];
        }
    }
    $newResolved = ['new_open_cves' => 0, 'resolved_since_baseline' => 0];
    if (is_array($diff) && !isset($diff['error'])) {
        $newResolved['new_open_cves'] = count($diff['findings_new_in_b'] ?? []);
        $newResolved['resolved_since_baseline'] = count(array_filter(
            $diff['finding_resolution_changes'] ?? [],
            static fn (array $x): bool => (int) ($x['resolved_before'] ?? 0) === 0 && (int) ($x['resolved_after'] ?? 0) === 1
        ));
    }

    return [
        'job_id'           => $jobB,
        'baseline_job_id'=> $baselineJobId,
        'summary'        => $summary,
        'diff_vs_baseline'=> $diff,
        'delta'          => $newResolved,
        'compliance'     => st_reporting_compliance($db, $jobB, $baselineJobId),
        'generated_at'   => gmdate('Y-m-d\TH:i:s\Z'),
    ];
}

/**
 * Lightweight trends from recent completed jobs (snapshot counts).
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
    $out = [];
    foreach ($jobs->fetchAll(PDO::FETCH_ASSOC) as $j) {
        $jid = (int) $j['id'];
        $summary = st_reporting_summary_for_job($db, $jid);
        $out[] = [
            'job_id'     => $jid,
            'finished_at'=> (string) ($j['finished_at'] ?? ''),
            'label'      => (string) ($j['label'] ?? ''),
            'assets'     => $summary['asset_snapshots'],
            'open_findings_total' => $summary['open_findings_total'],
            'open_findings_by_severity' => $summary['open_findings_by_severity'],
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
    $highOpen = (int) ($bySev['high'] ?? 0);

    $rules = [
        'no_critical_open' => [
            'pass'  => $critOpen === 0,
            'detail'=> $critOpen === 0 ? 'No open critical findings in snapshot.' : "Open critical count: {$critOpen}",
        ],
    ];

    $newHigh = 0;
    if ($baselineJobId !== null && $baselineJobId > 0 && $baselineJobId !== $jobB) {
        try {
            $diff = st_reporting_compare_jobs($db, $baselineJobId, $jobB);
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
        'job_id' => $jobB,
        'baseline_job_id' => $baselineJobId,
        'rules' => $rules,
        'overall_pass' => !in_array(false, array_column($rules, 'pass'), true),
    ];
}

function st_reporting_get_baseline_job_id(PDO $db): ?int
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

    $db->exec('UPDATE scan_jobs SET is_baseline = 0 WHERE COALESCE(is_baseline,0) = 1');
    $db->prepare('UPDATE scan_jobs SET is_baseline = 1 WHERE id = ?')->execute([$jobId]);
    $ins = $db->prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)');
    $ins->execute([ST_REPORTING_BASELINE_CONFIG_KEY, (string) $jobId]);
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
 */
function st_reporting_materialize_scheduled(PDO $db, int $scheduleId): void
{
    $sch = $db->prepare('SELECT id, name FROM scan_schedules WHERE id = ? LIMIT 1');
    $sch->execute([$scheduleId]);
    $srow = $sch->fetch(PDO::FETCH_ASSOC);
    if (!$srow) {
        throw new InvalidArgumentException('schedule not found');
    }

    $baseline = st_reporting_get_baseline_job_id($db);

    $latestStmt = $db->query(
        "SELECT id FROM scan_jobs
         WHERE status = 'done' AND (deleted_at IS NULL OR deleted_at = '')
           AND finished_at IS NOT NULL
         ORDER BY datetime(finished_at) DESC, id DESC LIMIT 1"
    );
    $latestRow = $latestStmt ? $latestStmt->fetch(PDO::FETCH_ASSOC) : false;
    $latestId = $latestRow ? (int) ($latestRow['id'] ?? 0) : 0;

    if ($latestId <= 0) {
        st_reporting_insert_artifact(
            $db,
            $scheduleId,
            $baseline,
            0,
            'Scheduled report — ' . (string) $srow['name'],
            [
                'error' => 'no_completed_scan_with_snapshots',
                'schedule_id' => $scheduleId,
                'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
            ]
        );

        return;
    }

    $payload = st_reporting_build_report_payload($db, $latestId, $baseline);
    $payload['schedule_id'] = $scheduleId;
    $payload['schedule_name'] = (string) ($srow['name'] ?? '');

    st_reporting_insert_artifact(
        $db,
        $scheduleId,
        $baseline,
        $latestId,
        'Scheduled report — ' . (string) $srow['name'],
        $payload
    );
}
