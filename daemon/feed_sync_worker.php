#!/usr/bin/env php
<?php
/**
 * CLI worker: runs feed sync scripts after the web request returns (async path).
 * Usage: php feed_sync_worker.php <target> <install_root>
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "feed_sync_worker.php: CLI only\n");
    exit(1);
}

if ($argc < 3) {
    fwrite(STDERR, "usage: php feed_sync_worker.php <nvd|oui|webfp|all> <install_root>\n");
    exit(1);
}

$target = strtolower(trim((string)$argv[1]));
$root = realpath((string)$argv[2]);
if (!$root || !is_dir($root)) {
    fwrite(STDERR, "feed_sync_worker.php: bad install root\n");
    exit(1);
}

if (!in_array($target, ['nvd', 'oui', 'webfp', 'all'], true)) {
    fwrite(STDERR, "feed_sync_worker.php: invalid target\n");
    exit(1);
}

chdir($root);
require_once $root . '/api/feed_sync_lib.php';

try {
    $resolved = st_feed_sync_resolve($target);
    if (!$resolved) {
        st_feed_sync_write_result($target, [
            'ok' => false,
            'results' => [],
            'error' => 'sync scripts not found',
        ]);
        exit(1);
    }
    @set_time_limit(0);
    ignore_user_abort(true);
    $payload = st_feed_sync_run_sync($resolved['scripts'], $resolved['python']);
    st_feed_sync_write_result($target, $payload);
    exit($payload['ok'] ? 0 : 1);
} catch (Throwable $e) {
    st_feed_sync_write_result($target, [
        'ok' => false,
        'results' => [],
        'error' => $e->getMessage(),
    ]);
    exit(1);
} finally {
    st_feed_sync_state_clear();
}
