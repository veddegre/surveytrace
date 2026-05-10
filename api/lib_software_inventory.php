<?php
/**
 * Normalized software inventory — read helpers (credentialed package inventory persistence).
 */

declare(strict_types=1);

function st_si_tables_ready(PDO $pdo): bool
{
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    try {
        $t = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='software_inventory' LIMIT 1")->fetchColumn();
        $cache = ($t === 'software_inventory');
    } catch (Throwable $e) {
        $cache = false;
    }

    return $cache;
}

/**
 * Sanitize user/package search token: lowercase alnum + common separators only.
 */
function st_si_sanitize_name_query(string $q, int $maxLen = 80): string
{
    $q = strtolower(trim($q));
    if ($q === '') {
        return '';
    }
    $q = preg_replace('/[^a-z0-9._+\\-]+/', '', $q) ?? '';
    if (strlen($q) > $maxLen) {
        $q = substr($q, 0, $maxLen);
    }

    return $q;
}

/**
 * Active installed rows for one asset (bounded list).
 *
 * @return list<array<string, mixed>>
 */
function st_si_list_for_asset(PDO $pdo, int $assetId, int $limit, int $offset, string $nameQuery): array
{
    if (! st_si_tables_ready($pdo) || $assetId < 1) {
        return [];
    }
    $lim = max(1, min(500, $limit));
    $off = max(0, min(1_000_000, $offset));
    $tok = st_si_sanitize_name_query($nameQuery);
    $params = [$assetId];
    $whereExtra = '';
    if ($tok !== '') {
        $whereExtra = ' AND si.normalized_name LIKE ? ESCAPE \'\\\' ';
        $params[] = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $tok) . '%';
    }
    $sql = 'SELECT si.ecosystem AS ecosystem, si.canonical_name AS canonical_name, si.normalized_name AS normalized_name,
                   siv.version_raw AS version_raw, IFNULL(siv.architecture, \'\') AS architecture,
                   st.first_seen_at AS first_seen_at, st.last_seen_at AS last_seen_at
            FROM software_inventory_asset_state st
            INNER JOIN software_inventory_versions siv ON siv.id = st.software_inventory_version_id
            INNER JOIN software_inventory si ON si.id = siv.software_inventory_id
            WHERE st.asset_id = ? AND st.active = 1' . $whereExtra . '
            ORDER BY si.normalized_name ASC, siv.version_raw ASC
            LIMIT ' . (int) $lim . ' OFFSET ' . (int) $off;
    try {
        $st = $pdo->prepare($sql);
        $st->execute($params);

        return array_values(array_filter(array_map(
            static fn ($r) => is_array($r) ? $r : null,
            $st->fetchAll(PDO::FETCH_ASSOC) ?: []
        )));
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_si_list_for_asset: ' . $e->getMessage());

        return [];
    }
}

function st_si_active_count_for_asset(PDO $pdo, int $assetId): int
{
    if (! st_si_tables_ready($pdo) || $assetId < 1) {
        return 0;
    }
    try {
        $st = $pdo->prepare('SELECT COUNT(*) FROM software_inventory_asset_state WHERE asset_id = ? AND active = 1');
        $st->execute([$assetId]);

        return (int) $st->fetchColumn();
    } catch (Throwable $e) {
        return 0;
    }
}

function st_si_latest_last_seen_for_asset(PDO $pdo, int $assetId): ?string
{
    if (! st_si_tables_ready($pdo) || $assetId < 1) {
        return null;
    }
    try {
        $st = $pdo->prepare(
            'SELECT MAX(last_seen_at) FROM software_inventory_asset_state WHERE asset_id = ? AND active = 1'
        );
        $st->execute([$assetId]);
        $mx = $st->fetchColumn();
        if ($mx === false || $mx === null || trim((string) $mx) === '') {
            return null;
        }

        return (string) $mx;
    } catch (Throwable $e) {
        return null;
    }
}

/**
 * Total rows in software_inventory (diagnostics / health).
 */
function st_si_total_inventory_rows(PDO $pdo): int
{
    if (! st_si_tables_ready($pdo)) {
        return 0;
    }
    try {
        return (int) $pdo->query('SELECT COUNT(*) FROM software_inventory')->fetchColumn();
    } catch (Throwable $e) {
        return 0;
    }
}

function st_si_global_latest_last_seen(PDO $pdo): ?string
{
    if (! st_si_tables_ready($pdo)) {
        return null;
    }
    try {
        $mx = $pdo->query('SELECT MAX(last_seen_at) FROM software_inventory_asset_state WHERE active = 1')->fetchColumn();
        if ($mx === false || $mx === null || trim((string) $mx) === '') {
            return null;
        }

        return (string) $mx;
    } catch (Throwable $e) {
        return null;
    }
}

/**
 * Distinct assets that have an active match on normalized_name prefix (bounded).
 *
 * @return list<array{asset_id: int, ecosystem: string, normalized_name: string, version_raw: string}>
 */
function st_si_assets_with_package_name_prefix(PDO $pdo, string $ecosystem, string $namePrefix, int $limit): array
{
    if (! st_si_tables_ready($pdo)) {
        return [];
    }
    $eco = strtolower(trim($ecosystem));
    if (! in_array($eco, ['dpkg', 'rpm', 'generic'], true)) {
        return [];
    }
    $pfx = st_si_sanitize_name_query($namePrefix);
    if ($pfx === '') {
        return [];
    }
    $lim = max(1, min(200, $limit));
    try {
        $st = $pdo->prepare(
            'SELECT DISTINCT a.id AS asset_id, si.ecosystem AS ecosystem, si.normalized_name AS normalized_name, siv.version_raw AS version_raw
             FROM software_inventory_asset_state st
             INNER JOIN assets a ON a.id = st.asset_id
             INNER JOIN software_inventory_versions siv ON siv.id = st.software_inventory_version_id
             INNER JOIN software_inventory si ON si.id = siv.software_inventory_id
             WHERE st.active = 1 AND si.ecosystem = ? AND si.normalized_name LIKE ? ESCAPE \'\\\'
             ORDER BY a.id ASC
             LIMIT ' . (int) $lim
        );
        $like = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $pfx) . '%';
        $st->execute([$eco, $like]);

        return array_values(array_filter(array_map(
            static function ($r) {
                if (! is_array($r)) {
                    return null;
                }

                return [
                    'asset_id'        => (int) ($r['asset_id'] ?? 0),
                    'ecosystem'       => (string) ($r['ecosystem'] ?? ''),
                    'normalized_name' => (string) ($r['normalized_name'] ?? ''),
                    'version_raw'     => (string) ($r['version_raw'] ?? ''),
                ];
            },
            $st->fetchAll(PDO::FETCH_ASSOC) ?: []
        )));
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_si_assets_with_package_name_prefix: ' . $e->getMessage());

        return [];
    }
}
