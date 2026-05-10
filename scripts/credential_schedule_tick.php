#!/usr/bin/env php
<?php
/**
 * SurveyTrace — enqueue due credentialed-check jobs (one bounded batch).
 *
 * Invoked by surveytrace-scheduler (daemon/scheduler_daemon.py). Reuses PHP run
 * creation + worker_jobs queueing (no shell cron, no secret handling).
 *
 * Usage:
 *   php scripts/credential_schedule_tick.php [--once]
 */

declare(strict_types=1);

$root = dirname(__DIR__);
require_once $root . '/api/db.php';
require_once $root . '/api/lib_credential_check_ops.php';

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script is CLI-only.\n");
    exit(1);
}

st_ensure_user_audit_schema();
$pdo = st_db();
$stats = st_cc_schedule_process_tick($pdo, 25);
fwrite(STDOUT, json_encode($stats, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
exit(0);
