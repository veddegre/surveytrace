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

try {
    st_reporting_materialize_scheduled(st_db(), $sid);
} catch (Throwable $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(1);
}

echo "OK\n";
exit(0);
