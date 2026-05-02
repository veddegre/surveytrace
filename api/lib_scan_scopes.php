<?php
/**
 * Scan scopes — multi-network reporting boundaries (Phase 14).
 * No auth; callers enforce RBAC.
 */

declare(strict_types=1);

/**
 * @param array<int, string> $cache
 */
function st_scan_scopes_table_scan_jobs_has_scope_id(PDO $db, ?array &$cache = null): bool
{
    static $local = null;
    if ($cache !== null) {
        $k = 'scan_jobs.scope_id';
        if (isset($cache[$k])) {
            return $cache[$k];
        }
    }
    if ($local !== null) {
        return $local;
    }
    $hasScopes = (int) $db->query(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_scopes' LIMIT 1"
    )->fetchColumn() === 1;
    if (!$hasScopes) {
        $local = false;

        return false;
    }
    $cols = array_column($db->query('PRAGMA table_info(scan_jobs)')->fetchAll(PDO::FETCH_ASSOC), 'name');
    $local = in_array('scope_id', $cols, true);
    if ($cache !== null) {
        $cache['scan_jobs.scope_id'] = $local;
    }

    return $local;
}

/** @return list<array<string,mixed>> */
function st_scan_scopes_list(PDO $db): array
{
    $has = (int) $db->query(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scan_scopes' LIMIT 1"
    )->fetchColumn();
    if ($has !== 1) {
        return [];
    }
    $st = $db->query(
        'SELECT id, name, description, scope_type, cidrs, tags, owner, environment, created_at, updated_at
         FROM scan_scopes ORDER BY name COLLATE NOCASE ASC, id ASC'
    );

    return $st ? $st->fetchAll(PDO::FETCH_ASSOC) : [];
}

/**
 * Most recent finished job with a non-null scope_id, else first scope row by id.
 */
function st_scan_scopes_default_id(PDO $db): ?int
{
    if (!st_scan_scopes_table_scan_jobs_has_scope_id($db)) {
        return null;
    }
    $jid = $db->query(
        "SELECT scope_id FROM scan_jobs
         WHERE status = 'done' AND (deleted_at IS NULL OR deleted_at = '')
           AND finished_at IS NOT NULL AND scope_id IS NOT NULL AND scope_id > 0
         ORDER BY datetime(finished_at) DESC, id DESC LIMIT 1"
    )->fetchColumn();
    if ($jid !== false && $jid !== null && (int) $jid > 0) {
        return (int) $jid;
    }
    $sid = $db->query('SELECT id FROM scan_scopes ORDER BY id ASC LIMIT 1')->fetchColumn();

    return ($sid !== false && $sid !== null) ? (int) $sid : null;
}

/** Normalize JSON list stored as TEXT; returns JSON string. */
function st_scan_scopes_json_list_normalize(mixed $raw, string $fallbackJson): string
{
    if ($raw === null || $raw === '') {
        return $fallbackJson;
    }
    if (is_array($raw)) {
        $enc = json_encode(array_values($raw));
        return $enc !== false ? $enc : $fallbackJson;
    }
    if (is_string($raw)) {
        $d = json_decode($raw, true);
        if (is_array($d)) {
            $enc = json_encode(array_values($d));

            return $enc !== false ? $enc : $fallbackJson;
        }
    }

    return $fallbackJson;
}
