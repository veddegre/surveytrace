<?php
/**
 * Lightweight fixed-window rate limiting (SQLite). Soft limits: 429 + Retry-After via st_json_rate_limited().
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';

function st_rate_limit_ensure_schema(PDO $db): void
{
    static $done = false;
    if ($done) {
        return;
    }
    $db->exec(
        'CREATE TABLE IF NOT EXISTS st_rate_limit_window (
            bucket TEXT NOT NULL,
            window_start INTEGER NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket, window_start)
        )'
    );
    $db->exec('CREATE INDEX IF NOT EXISTS idx_st_rate_limit_window_prune ON st_rate_limit_window(window_start)');
    $done = true;
}

/**
 * @param positive-int $maxPerWindow
 */
function st_rate_limit_consume_or_429(PDO $db, string $bucket, int $maxPerWindow, int $windowSeconds = 60): void
{
    if ($maxPerWindow < 1) {
        return;
    }
    if (strlen($bucket) > 512) {
        $bucket = substr($bucket, 0, 512);
    }
    st_rate_limit_ensure_schema($db);
    $period = max(10, min(3600, $windowSeconds));
    $win = intdiv(time(), $period) * $period;
    $pruneBefore = $win - ($period * 24 * 7);

    try {
        $db->exec('BEGIN IMMEDIATE');
        $db->prepare('DELETE FROM st_rate_limit_window WHERE window_start < ?')->execute([$pruneBefore]);
        $sel = $db->prepare('SELECT count FROM st_rate_limit_window WHERE bucket = ? AND window_start = ?');
        $sel->execute([$bucket, $win]);
        $cur = (int) ($sel->fetchColumn() ?: 0);
        if ($cur >= $maxPerWindow) {
            $db->exec('ROLLBACK');
            st_json_rate_limited('Too many requests', $period);
        }
        if ($cur === 0) {
            $db->prepare(
                'INSERT INTO st_rate_limit_window (bucket, window_start, count) VALUES (?, ?, 1)'
            )->execute([$bucket, $win]);
        } else {
            $db->prepare(
                'UPDATE st_rate_limit_window SET count = count + 1 WHERE bucket = ? AND window_start = ?'
            )->execute([$bucket, $win]);
        }
        $db->exec('COMMIT');
    } catch (Throwable $e) {
        try {
            if ($db->inTransaction()) {
                $db->exec('ROLLBACK');
            }
        } catch (Throwable $e2) {
        }
        $msg = preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $e->getMessage());
        @error_log('SurveyTrace rate_limit failed (fail-open): ' . trim($msg));
    }
}
