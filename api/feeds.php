<?php
/**
 * SurveyTrace — /api/feeds.php
 *
 * GET  /api/feeds.php?status=1   -> { ok, feed_sync, last_feed_sync? }
 * POST /api/feeds.php?sync=1     Body: {"target":"nvd"|"oui"|"webfp"|"all"}
 * POST /api/feeds.php?cancel=1 -> ask running sync to stop (NVD or "all" only)
 *
 * Sync runs in the background (HTTP returns immediately) so reverse proxies
 * and browsers do not time out on long NVD downloads.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/feed_sync_lib.php';

st_auth();

if (isset($_GET['status'])) {
    st_release_session_lock();
    try {
        st_json([
            'ok' => true,
            'feed_sync' => st_feed_sync_state_read(),
            'last_feed_sync' => st_feed_sync_truncate_result_for_api(st_feed_sync_last_result_read()),
        ]);
    } catch (Throwable $e) {
        error_log('feeds.php status: ' . $e->getMessage());
        st_json(['ok' => false, 'error' => 'feed status failed: ' . $e->getMessage()], 500);
    }
}

st_method('POST');
$body = st_input();

if (isset($_GET['cancel'])) {
    st_release_session_lock();
    try {
        $state = st_feed_sync_state_read();
        if (!$state['running']) {
            st_json(['ok' => false, 'error' => 'No feed sync is running.'], 409);
        }
        $tgt = strtolower((string)($state['target'] ?? ''));
        if (!in_array($tgt, ['nvd', 'all'], true)) {
            st_json([
                'ok' => false,
                'error' => 'Cancel only applies while NVD or “Sync all feeds” is running. '
                    . 'OUI/WebFP-only jobs finish quickly.',
            ], 400);
        }
        st_feed_sync_cancel_request();
        st_json(['ok' => true, 'cancel_requested' => true]);
    } catch (Throwable $e) {
        error_log('feeds.php cancel: ' . $e->getMessage());
        st_json(['ok' => false, 'error' => 'cancel failed: ' . $e->getMessage()], 500);
    }
}

if (!isset($_GET['sync'])) {
    st_json(['error' => 'unsupported operation'], 400);
}

try {
    $target = strtolower(trim((string)($body['target'] ?? 'all')));
    if (!in_array($target, ['nvd', 'oui', 'webfp', 'all'], true)) {
        st_json(['error' => 'target must be nvd, oui, webfp, or all'], 400);
    }

    $resolved = st_feed_sync_resolve($target);
    if (!$resolved) {
        st_json([
            'ok' => false,
            'error' => 'sync scripts not found under any install root (need daemon/sync_*.py). '
                . 'Set env SURVEYTRACE_ROOT to the app directory if the server layout is unusual.',
            'searched_roots' => st_feed_sync_install_root_candidates(),
            'st_data_dir' => ST_DATA_DIR,
        ], 500);
    }

    if (st_feed_sync_state_read()['running']) {
        st_json([
            'ok' => false,
            'busy' => true,
            'error' => 'A feed sync is already running on the server.',
        ], 409);
    }

    if (!st_feed_sync_state_begin($target)) {
        st_json([
            'ok' => false,
            'error' => 'Cannot write feed sync state file under ' . ST_DATA_DIR
                . '. Ensure this directory exists and is writable by the web server user (e.g. www-data).',
        ], 500);
    }

    $asyncPayload = [
        'ok' => true,
        'async' => true,
        'started' => true,
        'target' => $target,
    ];

    $root = $resolved['root'];
    $scripts = $resolved['scripts'];
    $python = $resolved['python'];
    $worker = $root . '/daemon/feed_sync_worker.php';

    /**
     * After responding, run sync in-process (FPM / CGI). Avoids shell spawn.
     */
    $runInProcessAfterFlush = static function () use ($target, $scripts, $python): void {
        @set_time_limit(0);
        ignore_user_abort(true);
        try {
            $payload = st_feed_sync_run_sync($scripts, $python);
            st_feed_sync_write_result($target, $payload);
        } catch (Throwable $e) {
            st_feed_sync_write_result($target, [
                'ok' => false,
                'results' => [],
                'error' => $e->getMessage(),
            ]);
        } finally {
            st_feed_sync_state_clear();
        }
    };

    // Only FPM/CGI can safely continue PHP after sending the response. Other SAPIs
    // (e.g. apache2handler, php -S) may report fastcgi_finish_request() as existing
    // but break or omit the body — use the CLI worker instead.
    $useFpmAsync = in_array(PHP_SAPI, ['fpm-fcgi', 'cgi-fcgi'], true)
        && function_exists('fastcgi_finish_request');

    if ($useFpmAsync) {
        $encFlags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
            | JSON_INVALID_UTF8_SUBSTITUTE;
        $json = json_encode($asyncPayload, $encFlags);
        if ($json === false) {
            st_feed_sync_state_clear();
            st_json(['ok' => false, 'error' => 'json_encode failed: ' . json_last_error_msg()], 500);
        }
        if (!headers_sent()) {
            http_response_code(200);
            header('Content-Type: application/json; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
            header('Cache-Control: no-store');
            // Intentionally omit Content-Length: zlib.output_compression (or proxies)
            // may alter the body length and cause an immediate HTTP 500.
        }
        echo $json;
        flush();
        fastcgi_finish_request();
        $runInProcessAfterFlush();
        exit(0);
    }

    if (!is_file($worker)) {
        st_feed_sync_state_clear();
        st_json([
            'ok' => false,
            'error' => 'feed_sync_worker.php missing; install full tree or use PHP-FPM.',
        ], 500);
    }

    if (!st_feed_sync_shell_available()) {
        st_feed_sync_state_clear();
        st_json([
            'ok' => false,
            'error' => 'Feed sync needs PHP exec() (Unix) or popen() (Windows), or run under PHP-FPM. '
                . 'Those functions appear in disable_functions — remove exec from that list for this vhost, '
                . 'or switch the site to php-fpm.',
        ], 503);
    }

    $phpCli = st_feed_sync_php_cli();
    st_feed_sync_spawn_worker($phpCli, $worker, $target, $root);
    st_json($asyncPayload);
} catch (Throwable $e) {
    error_log('feeds.php sync: ' . $e->getMessage() . "\n" . $e->getTraceAsString());
    @st_feed_sync_state_clear();
    st_json(['ok' => false, 'error' => 'feed sync failed: ' . $e->getMessage()], 500);
}
