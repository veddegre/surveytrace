<?php
/**
 * CLI selftest for quick asset search semantics used by Credentialed Checks pickers.
 *
 * Validates:
 * - partial IP search
 * - partial hostname search
 * - numeric id search (CAST(id AS TEXT) LIKE)
 * - bounded limit
 * - response-row shape mapping fields
 */
declare(strict_types=1);

$db = new PDO('sqlite::memory:', null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

$db->exec("CREATE TABLE assets (
    id INTEGER PRIMARY KEY,
    hostname TEXT,
    ip TEXT,
    category TEXT,
    scope_id INTEGER
)");
$db->exec("CREATE TABLE scan_scopes (
    id INTEGER PRIMARY KEY,
    name TEXT
)");
$db->exec("CREATE TABLE asset_assertions (
    id INTEGER PRIMARY KEY,
    asset_id INTEGER,
    assertion_type TEXT,
    asserted_value TEXT,
    confidence_level TEXT
)");

$db->exec("INSERT INTO scan_scopes (id, name) VALUES (1, 'Scope A'), (2, 'Scope B')");
$db->exec("INSERT INTO assets (id, hostname, ip, category, scope_id) VALUES
    (11, 'web-01', '192.168.23.10', 'srv', 1),
    (12, 'db-01', '192.168.23.20', 'srv', 2),
    (19, 'edge-gw', '10.0.0.19', 'net', NULL)");
$db->exec("INSERT INTO asset_assertions (asset_id, assertion_type, asserted_value, confidence_level) VALUES
    (11, 'canonical_hostname', 'web-01.example', 'high'),
    (12, 'os_platform', 'linux', 'medium')");

/**
 * @return list<array{id:int,hostname:string,ip:string,category:string,scope_name:?string,label:string}>
 */
function st_assets_quick_search_fixture(PDO $db, string $q, int $limit): array {
    $qLike = '%' . trim($q) . '%';
    $sql = "SELECT
                a.id, a.hostname, a.ip, a.category, sc.name AS scope_name
            FROM assets a
            LEFT JOIN (
              SELECT asset_id, asserted_value FROM asset_assertions
              WHERE assertion_type='canonical_hostname' AND LOWER(confidence_level) IN ('medium','high','authoritative')
            ) ah ON ah.asset_id=a.id
            LEFT JOIN (
              SELECT asset_id, asserted_value FROM asset_assertions
              WHERE assertion_type='os_platform' AND LOWER(confidence_level) IN ('medium','high','authoritative')
            ) ao ON ao.asset_id=a.id
            LEFT JOIN scan_scopes sc ON sc.id = a.scope_id
            WHERE (a.ip LIKE :q OR a.hostname LIKE :q OR CAST(a.id AS TEXT) LIKE :q
                   OR ah.asserted_value LIKE :q OR ao.asserted_value LIKE :q)
            ORDER BY a.id ASC
            LIMIT :lim";
    $st = $db->prepare($sql);
    $st->bindValue(':q', $qLike, PDO::PARAM_STR);
    $st->bindValue(':lim', max(1, min(50, $limit)), PDO::PARAM_INT);
    $st->execute();
    $rows = [];
    foreach ($st->fetchAll() as $r) {
        $id = (int) ($r['id'] ?? 0);
        $hostname = (string) ($r['hostname'] ?? '');
        $ip = (string) ($r['ip'] ?? '');
        $category = (string) ($r['category'] ?? '');
        $scopeName = isset($r['scope_name']) && $r['scope_name'] !== '' ? (string) $r['scope_name'] : null;
        $rows[] = [
            'id' => $id,
            'hostname' => $hostname,
            'ip' => $ip,
            'category' => $category,
            'scope_name' => $scopeName,
            'label' => ($hostname !== '' ? $hostname : '—') . ' (' . ($ip !== '' ? $ip : '—') . ') [' . $id . ']',
        ];
    }
    return $rows;
}

$ipRows = st_assets_quick_search_fixture($db, '192.168.23', 20);
if (count($ipRows) !== 2) {
    fwrite(STDERR, "FAIL: expected 2 rows for partial IP search\n");
    exit(1);
}

$hnRows = st_assets_quick_search_fixture($db, 'web-01', 20);
if (count($hnRows) < 1 || (int) $hnRows[0]['id'] !== 11) {
    fwrite(STDERR, "FAIL: hostname partial search mismatch\n");
    exit(1);
}

$idRows = st_assets_quick_search_fixture($db, '19', 20);
$hit19 = false;
foreach ($idRows as $r) {
    if ((int) $r['id'] === 19) {
        $hit19 = true;
        break;
    }
}
if (! $hit19) {
    fwrite(STDERR, "FAIL: numeric id search did not include id=19\n");
    exit(1);
}

$bounded = st_assets_quick_search_fixture($db, '1', 1);
if (count($bounded) !== 1) {
    fwrite(STDERR, "FAIL: limit bound not respected\n");
    exit(1);
}
$shape = $bounded[0] ?? [];
foreach (['id', 'hostname', 'ip', 'category', 'scope_name', 'label'] as $k) {
    if (! array_key_exists($k, $shape)) {
        fwrite(STDERR, "FAIL: missing response field {$k}\n");
        exit(1);
    }
}

echo "OK st_assets_quick_search_selftest\n";
