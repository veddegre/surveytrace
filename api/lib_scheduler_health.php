<?php
/**
 * SurveyTrace — scheduler runtime health (read-only).
 *
 * Reads data/scheduler_status.json emitted by daemon/scheduler_daemon.py.
 * No DB access required. Used by health.php and diagnose_scheduler.php.
 */

declare(strict_types=1);

/**
 * @return array<string,mixed>
 */
function st_health_scheduler_runtime(string $dataDir): array
{
    $out = [
        'status_file' => rtrim($dataDir, '/') . '/scheduler_status.json',
        'status_file_exists' => false,
        'last_start_utc' => '',
        'last_loop_success_utc' => '',
        'last_db_open_success_utc' => '',
        'last_schedule_scan_attempt_utc' => '',
        'last_credential_schedule_tick_utc' => '',
        'db_open_consecutive_failures' => 0,
        'db_open_first_failure_utc' => '',
        'last_db_open_error' => '',
        'pid' => 0,
        'updated_at' => '',
        'warnings' => [],
    ];
    $path = $out['status_file'];
    if (! is_file($path) || ! is_readable($path)) {
        $out['warnings'][] = 'Scheduler runtime status file missing or unreadable (scheduler may not have started yet).';

        return $out;
    }
    $raw = @file_get_contents($path);
    if (! is_string($raw) || trim($raw) === '') {
        $out['warnings'][] = 'Scheduler runtime status file is empty.';

        return $out;
    }
    $doc = json_decode($raw, true);
    if (! is_array($doc)) {
        $out['warnings'][] = 'Scheduler runtime status file is invalid JSON.';

        return $out;
    }
    $out['status_file_exists'] = true;
    foreach ([
        'last_start_utc',
        'last_loop_success_utc',
        'last_db_open_success_utc',
        'last_schedule_scan_attempt_utc',
        'last_credential_schedule_tick_utc',
        'db_open_first_failure_utc',
        'last_db_open_error',
        'updated_at',
    ] as $k) {
        if (isset($doc[$k])) {
            $out[$k] = (string) $doc[$k];
        }
    }
    if (isset($doc['pid'])) {
        $out['pid'] = max(0, (int) $doc['pid']);
    }
    if (isset($doc['db_open_consecutive_failures'])) {
        $out['db_open_consecutive_failures'] = max(0, (int) $doc['db_open_consecutive_failures']);
    }

    $now = time();
    $pollStaleAfter = 120; // scheduler polls every 30s; allow 2 missed ticks + slack
    $dbStaleAfter = 300;

    $updatedTs = strtotime((string) $out['updated_at']);
    if ($updatedTs !== false && ($now - $updatedTs) > $pollStaleAfter) {
        $out['warnings'][] = 'Scheduler status heartbeat is stale (no recent updates from scheduler_daemon.py).';
    }

    $loopTs = strtotime((string) $out['last_loop_success_utc']);
    if ($loopTs !== false && ($now - $loopTs) > $pollStaleAfter) {
        $out['warnings'][] = 'Scheduler main loop success timestamp is stale (scheduled scans may not be running).';
    }

    $dbOkTs = strtotime((string) $out['last_db_open_success_utc']);
    if ($dbOkTs !== false && ($now - $dbOkTs) > $dbStaleAfter) {
        $out['warnings'][] = 'Scheduler DB-open success timestamp is stale.';
    }

    if ($out['db_open_consecutive_failures'] > 0) {
        $out['warnings'][] = 'Scheduler reported consecutive SQLite open failures (see last_db_open_error).';
    }

    $err = trim((string) $out['last_db_open_error']);
    if ($err !== '' && $out['db_open_consecutive_failures'] > 0) {
        $out['warnings'][] = 'Last scheduler DB-open error: ' . substr($err, 0, 200);
    }

    return $out;
}

/**
 * If scan schedules are enabled and the scheduler tick is stale, add a targeted warning.
 *
 * @param array<string,mixed> $schedules health['schedules']
 * @param array<string,mixed> $runtime   st_health_scheduler_runtime result
 * @return list<string>
 */
function st_health_scheduler_schedule_tick_warnings(array $schedules, array $runtime): array
{
    $hints = [];
    $enabled = (int) ($schedules['enabled_active'] ?? 0);
    if ($enabled <= 0) {
        return $hints;
    }
    $tick = strtotime((string) ($runtime['last_schedule_scan_attempt_utc'] ?? ''));
    if ($tick === false) {
        $hints[] = 'Scan schedules are enabled but scheduler has not recorded a scan-scheduling attempt yet.';

        return $hints;
    }
    $now = time();
    if (($now - $tick) > 120) {
        $hints[] = 'Scan schedules are enabled but scheduler scan-tick timestamp is stale (missed polls or DB-open failures).';
    }

    return $hints;
}
