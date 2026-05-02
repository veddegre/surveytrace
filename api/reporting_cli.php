#!/usr/bin/env php
<?php
/**
 * CLI entry for scheduled report materialization (scheduler_daemon subprocess).
 * Usage: php reporting_cli.php materialize <schedule_id>
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "reporting_cli.php is CLI-only\n");
    exit(1);
}

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_reporting.php';

$action = $argv[1] ?? '';
if ($action !== 'materialize' || !isset($argv[2])) {
    fwrite(STDERR, "Usage: php reporting_cli.php materialize <schedule_id>\n");
    exit(1);
}

$sid = (int) $argv[2];
if ($sid <= 0) {
    fwrite(STDERR, "invalid schedule_id\n");
    exit(1);
}

$maxAttempts = 5;
$delayMs = 100;
$lastErr = '';
$cliT0 = microtime(true);
for ($attempt = 0; $attempt < $maxAttempts; $attempt++) {
    try {
        $artifactId = st_reporting_materialize_scheduled(st_db(), $sid);
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
        $out = [
            'ok'           => true,
            'schedule_id'  => $sid,
            'artifact_id'  => $artifactId,
            'duration_ms'  => (int) round((microtime(true) - $cliT0) * 1000),
        ];
        echo json_encode($out, $flags) . "\n";
        exit(0);
    } catch (Throwable $e) {
        $lastErr = $e->getMessage();
        $msg = strtolower($lastErr);
        $busy = str_contains($msg, 'database is locked') || str_contains($msg, 'busy')
            || str_contains($msg, 'locked');
        if ($busy && $attempt < $maxAttempts - 1) {
            usleep($delayMs * 1000);
            $delayMs = min($delayMs * 2, 2000);
            continue;
        }
        break;
    }
}

fwrite(STDERR, $lastErr . "\n");
exit(1);
