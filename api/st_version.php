<?php
/**
 * SurveyTrace — defines ST_VERSION for PHP (loaded before api/db.php from public/index.php,
 * and at the top of api/db.php for all API endpoints).
 *
 * Canonical semver lives in the **VERSION** file at the repository / install root
 * (same directory that contains `api/` and `daemon/`). Bump **VERSION** when you cut a release.
 *
 * Human-readable notes: RELEASE_NOTES.md and README.md → Changelog.
 */
if (!defined('ST_VERSION')) {
    $vfile = dirname(__DIR__) . '/VERSION';
    $v = '';
    if (is_readable($vfile)) {
        $lines = file($vfile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (is_array($lines)) {
            foreach ($lines as $line) {
                $line = trim((string)$line);
                if ($line === '' || str_starts_with($line, '#')) {
                    continue;
                }
                $v = $line;
                break;
            }
        }
    }
    if ($v === '' || !preg_match('/^\d+\.\d+\.\d+/', $v)) {
        $v = '0.16.0';
    }
    define('ST_VERSION', $v);
}
