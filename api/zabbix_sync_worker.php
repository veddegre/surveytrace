#!/usr/bin/env php
<?php
/**
 * CLI worker: Zabbix source sync (bounded host/problem pull + local tables + rematch).
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "zabbix_sync_worker.php: CLI only\n");
    exit(1);
}

$root = realpath(__DIR__ . '/..');
if ($root === false || ! is_dir($root)) {
    fwrite(STDERR, "zabbix_sync_worker.php: bad install root\n");
    exit(1);
}

chdir($root);
require_once $root . '/api/db.php';
require_once $root . '/api/lib_zabbix.php';

try {
    $db = st_db();
    $out = st_zabbix_run_full_sync($db);
    $hs = (int) ($out['hosts_synced'] ?? 0);
    $pairs = (int) (($out['match'] ?? [])['pairs'] ?? 0);
    fwrite(STDOUT, "zabbix_sync_worker: completed ok hosts_synced={$hs} matched_pairs={$pairs}\n");
    $line = json_encode(['ok' => true, 'result' => $out], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    @error_log('SurveyTrace zabbix_sync_worker ' . ($line !== false ? $line : '{}'));
} catch (Throwable $e) {
    $msg = st_zabbix_redact_secrets(preg_replace('/[\x00-\x1F\x7F]/u', ' ', $e->getMessage()) ?? '');
    @error_log('SurveyTrace zabbix_sync_worker FAILED: ' . $msg);
    fwrite(STDERR, 'zabbix_sync_worker: FAILED ' . $msg . "\n");
    exit(1);
}
