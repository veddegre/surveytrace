<?php
/**
 * Scan scopes — multi-network reporting boundaries (Phase 14).
 * No auth; callers enforce RBAC.
 */

declare(strict_types=1);

/**
 * True when sqlite_master lists the table (SurveyTrace uses SQLite only).
 */
function st_sqlite_table_exists(PDO $db, string $tableName): bool
{
    if ($tableName === '' || strlen($tableName) > 128) {
        return false;
    }
    try {
        $st = $db->prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1");
        $st->execute([$tableName]);

        return (int) $st->fetchColumn() === 1;
    } catch (Throwable $e) {
        return false;
    }
}

/** Scoped baseline rows (Phase 14); optional on partially migrated DBs. */
function st_scan_scopes_table_scan_scope_baselines_exists(PDO $db): bool
{
    return st_sqlite_table_exists($db, 'scan_scope_baselines');
}

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
    try {
        if (! st_sqlite_table_exists($db, 'scan_scopes')) {
            $local = false;
            if ($cache !== null) {
                $cache['scan_jobs.scope_id'] = false;
            }

            return false;
        }
        if (! st_sqlite_table_exists($db, 'scan_jobs')) {
            $local = false;
            if ($cache !== null) {
                $cache['scan_jobs.scope_id'] = false;
            }

            return false;
        }
        $ti = $db->query('PRAGMA table_info(scan_jobs)');
        $cols = array_column($ti ? $ti->fetchAll(PDO::FETCH_ASSOC) : [], 'name');
        $local = in_array('scope_id', $cols, true);
    } catch (Throwable $e) {
        $local = false;
    }
    if ($cache !== null) {
        $cache['scan_jobs.scope_id'] = $local;
    }

    return $local;
}

/** @return list<array<string,mixed>> */
function st_scan_scopes_list(PDO $db): array
{
    if (! st_sqlite_table_exists($db, 'scan_scopes')) {
        return [];
    }
    try {
        $st = $db->query(
            'SELECT id, name, description, scope_type, cidrs, tags, owner, environment, created_at, updated_at
             FROM scan_scopes ORDER BY name COLLATE NOCASE ASC, id ASC'
        );

        return $st ? $st->fetchAll(PDO::FETCH_ASSOC) : [];
    } catch (Throwable $e) {
        return [];
    }
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

/**
 * Cached id → display name map for Phase 14 payloads (reporting scope labels).
 *
 * @return array<int, string>
 */
function st_scan_scopes_id_to_name_map(PDO $db): array
{
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $cache = [];
    foreach (st_scan_scopes_list($db) as $row) {
        $id = (int) ($row['id'] ?? 0);
        if ($id > 0) {
            $cache[$id] = (string) ($row['name'] ?? '');
        }
    }

    return $cache;
}


function st_scan_scopes_resolve_name(PDO $db, int $scopeId): ?string
{
    if ($scopeId <= 0) {
        return null;
    }
    $m = st_scan_scopes_id_to_name_map($db);
    $n = $m[$scopeId] ?? '';

    return $n !== '' ? $n : null;
}

/** True when assets has optional Phase-16 scope_id (inventory / reporting tag). */
function st_assets_has_scope_id(PDO $db): bool
{
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    try {
        $ti = $db->query('PRAGMA table_info(assets)');
        $cols = array_column($ti ? $ti->fetchAll(PDO::FETCH_ASSOC) : [], 'name');
        $cache = in_array('scope_id', $cols, true);
    } catch (Throwable $e) {
        $cache = false;
    }

    return $cache;
}

/**
 * Count of assets per named scope (excludes NULL/0).
 *
 * @return array<int, int>
 */
function st_scan_scopes_asset_counts(PDO $db): array
{
    if (! st_sqlite_table_exists($db, 'scan_scopes') || ! st_assets_has_scope_id($db)) {
        return [];
    }
    try {
        $st = $db->query(
            'SELECT scope_id AS sid, COUNT(*) AS cnt FROM assets
             WHERE scope_id IS NOT NULL AND scope_id > 0 GROUP BY scope_id'
        );
        $rows = $st ? $st->fetchAll(PDO::FETCH_ASSOC) : [];
    } catch (Throwable $e) {
        return [];
    }
    $out = [];
    foreach ($rows as $r) {
        $sid = (int) ($r['sid'] ?? 0);
        if ($sid > 0) {
            $out[$sid] = (int) ($r['cnt'] ?? 0);
        }
    }

    return $out;
}

function st_scan_scopes_unscoped_asset_count(PDO $db): int
{
    if (! st_assets_has_scope_id($db)) {
        return 0;
    }
    try {
        $n = $db->query(
            'SELECT COUNT(*) FROM assets WHERE scope_id IS NULL OR scope_id = 0'
        )->fetchColumn();
    } catch (Throwable $e) {
        return 0;
    }

    return (int) $n;
}

/**
 * Insert a catalog row (same shape as legacy POST /api/scan_scopes.php).
 *
 * @return array<string, mixed> Full scan_scopes row
 */
function st_scan_scopes_insert_catalog_row(
    PDO $db,
    string $name,
    string $description,
    string $scopeType,
    string $cidrsJson,
    string $tagsJson,
    string $owner,
    string $environment
): array {
    if (! st_sqlite_table_exists($db, 'scan_scopes')) {
        throw new RuntimeException('scan_scopes table missing');
    }
    $nameTrim = trim($name);
    if ($nameTrim === '') {
        throw new InvalidArgumentException('name is required');
    }
    $dup = $db->prepare('SELECT 1 FROM scan_scopes WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) LIMIT 1');
    $dup->execute([$nameTrim]);
    if ((int) $dup->fetchColumn() === 1) {
        throw new InvalidArgumentException('A scope with this name already exists');
    }
    $db->prepare(
        'INSERT INTO scan_scopes (name, description, scope_type, cidrs, tags, owner, environment, updated_at)
         VALUES (?,?,?,?,?,?,?,CURRENT_TIMESTAMP)'
    )->execute([
        substr($nameTrim, 0, 200),
        $description !== '' ? substr($description, 0, 2000) : null,
        substr($scopeType !== '' ? $scopeType : 'network', 0, 64),
        $cidrsJson,
        $tagsJson,
        $owner !== '' ? substr($owner, 0, 200) : null,
        substr($environment !== '' ? $environment : 'unknown', 0, 120),
    ]);
    $id = (int) $db->lastInsertId();
    $st = $db->prepare(
        'SELECT id, name, description, scope_type, cidrs, tags, owner, environment, created_at, updated_at
         FROM scan_scopes WHERE id = ?'
    );
    $st->execute([$id]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (! is_array($row)) {
        throw new RuntimeException('scope insert failed');
    }

    return $row;
}

/**
 * Count references to a catalog scope (for delete confirmation and audit).
 *
 * @return array{assets: int, jobs: int, schedules: int, baselines: int, zabbix_rules: int}
 */
function st_scan_scopes_delete_impact_counts(PDO $db, int $scopeId): array
{
    $out = ['assets' => 0, 'jobs' => 0, 'schedules' => 0, 'baselines' => 0, 'zabbix_rules' => 0];
    if ($scopeId <= 0) {
        return $out;
    }
    try {
        if (st_assets_has_scope_id($db)) {
            $st = $db->prepare('SELECT COUNT(*) FROM assets WHERE scope_id = ?');
            $st->execute([$scopeId]);
            $out['assets'] = (int) $st->fetchColumn();
        }
        if (st_scan_scopes_table_scan_jobs_has_scope_id($db)) {
            $st = $db->prepare('SELECT COUNT(*) FROM scan_jobs WHERE scope_id = ?');
            $st->execute([$scopeId]);
            $out['jobs'] = (int) $st->fetchColumn();
        }
        if (st_sqlite_table_exists($db, 'scan_schedules')) {
            $schedCols = $db->query('PRAGMA table_info(scan_schedules)')->fetchAll(PDO::FETCH_ASSOC);
            $schedNames = array_column($schedCols ?: [], 'name');
            if (in_array('scope_id', $schedNames, true)) {
                $st = $db->prepare('SELECT COUNT(*) FROM scan_schedules WHERE scope_id = ?');
                $st->execute([$scopeId]);
                $out['schedules'] = (int) $st->fetchColumn();
            }
        }
        if (st_scan_scopes_table_scan_scope_baselines_exists($db)) {
            $st = $db->prepare('SELECT COUNT(*) FROM scan_scope_baselines WHERE scope_id = ?');
            $st->execute([$scopeId]);
            $out['baselines'] = (int) $st->fetchColumn();
        }
        if (st_sqlite_table_exists($db, 'zabbix_scope_map_rules')) {
            $st = $db->prepare('SELECT COUNT(*) FROM zabbix_scope_map_rules WHERE scope_id = ?');
            $st->execute([$scopeId]);
            $out['zabbix_rules'] = (int) $st->fetchColumn();
        }
    } catch (Throwable $e) {
        return $out;
    }

    return $out;
}

/**
 * @param 'scan_jobs'|'scan_schedules' $table
 *
 * @return array<string, int> scope id as string => row count
 */
function st_scan_scopes_table_scope_id_group_counts(PDO $db, string $table): array
{
    if ($table !== 'scan_jobs' && $table !== 'scan_schedules') {
        return [];
    }
    if (! st_sqlite_table_exists($db, $table)) {
        return [];
    }
    try {
        $cols = $db->query('PRAGMA table_info(' . $table . ')')->fetchAll(PDO::FETCH_ASSOC);
        $names = array_column($cols ?: [], 'name');
        if (! in_array('scope_id', $names, true)) {
            return [];
        }
        $st = $db->query(
            "SELECT scope_id AS sid, COUNT(*) AS c FROM {$table}
             WHERE scope_id IS NOT NULL AND scope_id > 0 GROUP BY scope_id"
        );
        $rows = $st ? $st->fetchAll(PDO::FETCH_ASSOC) : [];
    } catch (Throwable $e) {
        return [];
    }
    $out = [];
    foreach ($rows as $r) {
        $sid = (int) ($r['sid'] ?? 0);
        if ($sid > 0) {
            $out[(string) $sid] = (int) ($r['c'] ?? 0);
        }
    }

    return $out;
}

/**
 * Rename a scope; rejects duplicate names (case-insensitive).
 */
function st_scan_scopes_rename_row(PDO $db, int $scopeId, string $newName): void
{
    if ($scopeId <= 0) {
        throw new InvalidArgumentException('scope_id is required');
    }
    if (! st_sqlite_table_exists($db, 'scan_scopes')) {
        throw new RuntimeException('scan_scopes table missing');
    }
    $chk = $db->prepare('SELECT 1 FROM scan_scopes WHERE id = ? LIMIT 1');
    $chk->execute([$scopeId]);
    if ((int) $chk->fetchColumn() !== 1) {
        throw new InvalidArgumentException('scope not found');
    }
    $nameTrim = trim($newName);
    if ($nameTrim === '') {
        throw new InvalidArgumentException('name is required');
    }
    $dup = $db->prepare(
        'SELECT 1 FROM scan_scopes WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) AND id != ? LIMIT 1'
    );
    $dup->execute([$nameTrim, $scopeId]);
    if ((int) $dup->fetchColumn() === 1) {
        throw new InvalidArgumentException('A scope with this name already exists');
    }
    $db->prepare('UPDATE scan_scopes SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')->execute([
        substr($nameTrim, 0, 200),
        $scopeId,
    ]);
}

/**
 * Remove a scope: clears asset and job schedule references, removes Zabbix map rules for this id, deletes row.
 * scan_scope_baselines CASCADE with parent delete when supported.
 */
function st_scan_scopes_delete_row(PDO $db, int $scopeId): void
{
    if ($scopeId <= 0) {
        throw new InvalidArgumentException('scope_id is required');
    }
    if (! st_sqlite_table_exists($db, 'scan_scopes')) {
        throw new RuntimeException('scan_scopes table missing');
    }
    $chk = $db->prepare('SELECT 1 FROM scan_scopes WHERE id = ? LIMIT 1');
    $chk->execute([$scopeId]);
    if ((int) $chk->fetchColumn() !== 1) {
        throw new InvalidArgumentException('scope not found');
    }
    $db->beginTransaction();
    try {
        if (st_assets_has_scope_id($db)) {
            $db->prepare('UPDATE assets SET scope_id = NULL WHERE scope_id = ?')->execute([$scopeId]);
        }
        if (st_scan_scopes_table_scan_jobs_has_scope_id($db)) {
            $db->prepare('UPDATE scan_jobs SET scope_id = NULL WHERE scope_id = ?')->execute([$scopeId]);
        }
        if (st_sqlite_table_exists($db, 'scan_schedules')) {
            $schedCols = $db->query('PRAGMA table_info(scan_schedules)')->fetchAll(PDO::FETCH_ASSOC);
            $schedNames = array_column($schedCols ?: [], 'name');
            if (in_array('scope_id', $schedNames, true)) {
                $db->prepare('UPDATE scan_schedules SET scope_id = NULL WHERE scope_id = ?')->execute([$scopeId]);
            }
        }
        if (st_sqlite_table_exists($db, 'zabbix_scope_map_rules')) {
            $db->prepare('DELETE FROM zabbix_scope_map_rules WHERE scope_id = ?')->execute([$scopeId]);
        }
        $db->prepare('DELETE FROM scan_scopes WHERE id = ?')->execute([$scopeId]);
        $db->commit();
    } catch (Throwable $e) {
        $db->rollBack();
        throw $e;
    }
}
