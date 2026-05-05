#!/usr/bin/env php
<?php
/**
 * CLI worker: push SurveyTrace summary metrics to Zabbix.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "zabbix_output_worker.php: CLI only\n");
    exit(1);
}

$root = realpath(__DIR__ . '/..');
if ($root === false || ! is_dir($root)) {
    fwrite(STDERR, "zabbix_output_worker.php: bad install root\n");
    exit(1);
}

chdir($root);
require_once $root . '/api/db.php';
require_once $root . '/api/lib_zabbix.php';

$db = null;
$exitCode = 0;
try {
    $db = st_db();
    st_zabbix_ensure_schema($db);
    $res = st_zabbix_run_output_push($db);
    if (! ($res['ok'] ?? false)) {
        $exitCode = 1;
        $msg = st_zabbix_redact_secrets((string) ($res['error'] ?? 'output push failed'));
        fwrite(STDERR, 'zabbix_output_worker: FAILED ' . $msg . "\n");
        @error_log('SurveyTrace zabbix_output_worker FAILED: ' . $msg);
    } else {
        $sent = (int) ($res['sent'] ?? 0);
        $transport = (string) ($res['transport'] ?? 'sender');
        fwrite(STDOUT, "zabbix_output_worker: completed ok sent={$sent} transport={$transport}\n");
        $line = json_encode(['ok' => true, 'result' => $res], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        @error_log('SurveyTrace zabbix_output_worker ' . ($line !== false ? $line : '{}'));
    }
} catch (Throwable $e) {
    $exitCode = 1;
    $msg = st_zabbix_redact_secrets(preg_replace('/[\x00-\x1F\x7F]/u', ' ', $e->getMessage()) ?? '');
    @error_log('SurveyTrace zabbix_output_worker FAILED: ' . $msg);
    fwrite(STDERR, 'zabbix_output_worker: FAILED ' . $msg . "\n");
} finally {
    if ($db instanceof PDO) {
        try {
            st_zabbix_clear_scheduled_output_lock($db);
        } catch (Throwable) {
        }
    }
}
exit($exitCode);

