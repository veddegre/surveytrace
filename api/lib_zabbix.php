<?php
/**
 * SurveyTrace — Zabbix source connector (Phase 16.1).
 *
 * JSON-RPC client, local cache tables, asset matching, read-only enrichment.
 * Does not modify SurveyTrace asset fields (owner/hostname/etc.); scope rules are preview/save only.
 */

declare(strict_types=1);

/** Max hosts pulled per sync (bounded). */
const ST_ZABBIX_SYNC_HOST_LIMIT = 500;

/** Max problem rows per problem.get (bounded). */
const ST_ZABBIX_SYNC_PROBLEM_LIMIT = 4000;

/** HTTP timeout for each Zabbix JSON-RPC call (seconds). */
const ST_ZABBIX_HTTP_TIMEOUT_SEC = 12;

/**
 * Create Zabbix tables if missing (idempotent). Single connector row id=1.
 */
function st_zabbix_ensure_schema(PDO $pdo): void
{
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS zabbix_connector (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            name TEXT NOT NULL DEFAULT \'Zabbix\',
            api_url TEXT NOT NULL DEFAULT \'\',
            api_token TEXT NOT NULL DEFAULT \'\',
            enabled INTEGER NOT NULL DEFAULT 0,
            last_sync_at TEXT,
            last_sync_status TEXT,
            last_error TEXT,
            updated_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );
    $pdo->exec('INSERT OR IGNORE INTO zabbix_connector (id) VALUES (1)');

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS zabbix_hosts (
            hostid TEXT PRIMARY KEY,
            tech_name TEXT NOT NULL DEFAULT \'\',
            visible_name TEXT NOT NULL DEFAULT \'\',
            monitored INTEGER NOT NULL DEFAULT 0,
            available TEXT NOT NULL DEFAULT \'\',
            status_raw_json TEXT,
            inventory_json TEXT,
            groups_json TEXT,
            tags_json TEXT,
            templates_json TEXT,
            interfaces_json TEXT,
            synced_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS zabbix_host_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostid TEXT NOT NULL REFERENCES zabbix_hosts(hostid) ON DELETE CASCADE,
            interfaceid TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT \'\',
            dns TEXT NOT NULL DEFAULT \'\',
            port INTEGER NOT NULL DEFAULT 10050,
            iface_type TEXT NOT NULL DEFAULT \'\',
            main INTEGER NOT NULL DEFAULT 0,
            useip INTEGER NOT NULL DEFAULT 1,
            mac TEXT NOT NULL DEFAULT \'\',
            raw_json TEXT,
            UNIQUE(hostid, interfaceid)
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_zabbix_iface_host ON zabbix_host_interfaces(hostid)');

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS zabbix_host_groups (
            hostid TEXT NOT NULL REFERENCES zabbix_hosts(hostid) ON DELETE CASCADE,
            groupid TEXT NOT NULL,
            group_name TEXT NOT NULL DEFAULT \'\',
            PRIMARY KEY (hostid, groupid)
        )'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS zabbix_host_tags (
            hostid TEXT NOT NULL REFERENCES zabbix_hosts(hostid) ON DELETE CASCADE,
            tag TEXT NOT NULL,
            value TEXT NOT NULL DEFAULT \'\',
            PRIMARY KEY (hostid, tag, value)
        )'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS zabbix_host_problems_summary (
            hostid TEXT PRIMARY KEY REFERENCES zabbix_hosts(hostid) ON DELETE CASCADE,
            open_count INTEGER NOT NULL DEFAULT 0,
            summary_json TEXT
        )'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS zabbix_asset_links (
            asset_id INTEGER NOT NULL PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
            zabbix_hostid TEXT NOT NULL UNIQUE REFERENCES zabbix_hosts(hostid) ON DELETE CASCADE,
            match_method TEXT NOT NULL,
            confidence REAL NOT NULL,
            last_matched_at TEXT NOT NULL DEFAULT (datetime(\'now\')),
            is_manual INTEGER NOT NULL DEFAULT 0
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_zabbix_links_host ON zabbix_asset_links(zabbix_hostid)');

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS zabbix_scope_map_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type TEXT NOT NULL,
            pattern TEXT NOT NULL,
            scope_id INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime(\'now\'))
        )'
    );
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_zabbix_scope_rules ON zabbix_scope_map_rules(scope_id, enabled)');
}

function st_zabbix_table_ready(PDO $pdo): bool
{
    $n = $pdo->query(
        "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='zabbix_hosts'"
    )->fetchColumn();

    return (int) $n === 1;
}

function st_zabbix_normalize_api_url(string $url): string
{
    $url = trim($url);
    if ($url === '') {
        return '';
    }
    if (! preg_match('#^https?://#i', $url)) {
        return '';
    }
    $url = rtrim($url, '/');
    if (preg_match('#/api_jsonrpc\\.php$#i', $url)) {
        return $url;
    }

    return $url . '/api_jsonrpc.php';
}

/**
 * Strip bearer tokens and similar from messages before logs or JSON (defense in depth).
 */
function st_zabbix_redact_secrets(string $msg): string
{
    $m = preg_replace('/Authorization:\\s*Bearer\\s+\\S+/i', 'Authorization: Bearer [REDACTED]', $msg) ?? $msg;
    $m = preg_replace('/Bearer\\s+[A-Za-z0-9._+-]{12,}/i', 'Bearer [REDACTED]', $m) ?? $m;

    return $m;
}

/** Higher rank wins when two signals have equal confidence (ip > mac > dns > hostname > visible_name). */
function st_zabbix_match_method_rank(string $t): int
{
    return match ($t) {
        'ip' => 50,
        'mac' => 40,
        'dns' => 30,
        'hostname' => 20,
        'visible_name' => 10,
        default => 0,
    };
}

/**
 * @return array<string,mixed>
 */
function st_zabbix_connector_get(PDO $pdo): array
{
    $st = $pdo->query('SELECT * FROM zabbix_connector WHERE id = 1 LIMIT 1');
    $row = $st ? $st->fetch(PDO::FETCH_ASSOC) : false;
    if (! is_array($row)) {
        return [
            'id' => 1,
            'name' => 'Zabbix',
            'api_url' => '',
            'api_token' => '',
            'enabled' => 0,
            'last_sync_at' => null,
            'last_sync_status' => null,
            'last_error' => null,
            'updated_at' => null,
        ];
    }

    return $row;
}

/**
 * Public connector fields (token never returned).
 *
 * @param array<string,mixed> $row
 * @return array<string,mixed>
 */
function st_zabbix_connector_public(array $row): array
{
    $tok = (string) ($row['api_token'] ?? '');

    $lastErr = $row['last_error'] ?? null;
    if (is_string($lastErr) && $lastErr !== '') {
        $lastErr = st_zabbix_redact_secrets($lastErr);
    }

    return [
        'id' => (int) ($row['id'] ?? 1),
        'name' => (string) ($row['name'] ?? 'Zabbix'),
        'api_url' => (string) ($row['api_url'] ?? ''),
        'api_token_set' => $tok !== '',
        'enabled' => (int) ($row['enabled'] ?? 0) === 1,
        'last_sync_at' => $row['last_sync_at'] ?? null,
        'last_sync_status' => $row['last_sync_status'] ?? null,
        'last_error' => $lastErr,
        'updated_at' => $row['updated_at'] ?? null,
    ];
}

/**
 * @param array<string,mixed> $in
 */
function st_zabbix_connector_save(PDO $pdo, array $in): void
{
    $cur = st_zabbix_connector_get($pdo);
    $name = trim((string) ($in['name'] ?? $cur['name'] ?? 'Zabbix'));
    if ($name === '') {
        $name = 'Zabbix';
    }
    $apiUrl = st_zabbix_normalize_api_url(trim((string) ($in['api_url'] ?? $cur['api_url'] ?? '')));
    $enabled = ! empty($in['enabled']) ? 1 : 0;
    $newTok = array_key_exists('api_token', $in) ? trim((string) $in['api_token']) : null;
    $apiToken = $cur['api_token'] ?? '';
    if ($newTok !== null && $newTok !== '') {
        $apiToken = $newTok;
    }
    $st = $pdo->prepare(
        'UPDATE zabbix_connector SET name = ?, api_url = ?, api_token = ?, enabled = ?, updated_at = datetime(\'now\') WHERE id = 1'
    );
    $st->execute([$name, $apiUrl, $apiToken, $enabled]);
}

function st_zabbix_php_cli(): string
{
    $env = getenv('SURVEYTRACE_PHP_CLI');
    if (is_string($env) && $env !== '' && is_executable($env)) {
        return $env;
    }
    if (PHP_OS_FAMILY === 'Windows') {
        $b = PHP_BINARY;
        if (is_string($b) && str_ends_with(strtolower($b), 'php.exe')) {
            return $b;
        }

        return 'php';
    }
    $b = PHP_BINARY;
    if (is_string($b) && str_contains(strtolower($b), 'php-fpm')) {
        $which = trim((string) @shell_exec('command -v php 2>/dev/null'));
        if ($which !== '' && is_executable($which)) {
            return $which;
        }

        return 'php';
    }

    return $b !== '' && is_executable($b) ? $b : 'php';
}

function st_zabbix_exec_available(): bool
{
    if (! function_exists('exec')) {
        return false;
    }
    $df = ini_get('disable_functions');
    if (! is_string($df) || $df === '') {
        return true;
    }
    $parts = array_map('trim', explode(',', strtolower($df)));

    return ! in_array('exec', $parts, true);
}

/**
 * @return array{ok:bool,error?:string,version?:string}
 */
function st_zabbix_api_test(string $apiUrl, string $token): array
{
    $apiUrl = st_zabbix_normalize_api_url($apiUrl);
    if ($apiUrl === '') {
        return ['ok' => false, 'error' => 'invalid api_url'];
    }
    try {
        $ver = st_zabbix_jsonrpc($apiUrl, $token, 'apiinfo.version', [], 8);
        if (is_string($ver) && $ver !== '') {
            return ['ok' => true, 'version' => $ver];
        }
    } catch (Throwable $e) {
        // apiinfo may be restricted; fall through to host.get
    }
    try {
        st_zabbix_jsonrpc($apiUrl, $token, 'host.get', [
            'output' => ['hostid'],
            'limit' => 1,
        ], ST_ZABBIX_HTTP_TIMEOUT_SEC);

        return ['ok' => true, 'version' => 'authenticated'];
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

/**
 * @param array<string,mixed> $params
 * @return mixed
 */
function st_zabbix_jsonrpc(string $apiUrl, string $token, string $method, array $params, int $timeoutSec)
{
    $id = random_int(1, 1_000_000_000);
    $payload = json_encode([
        'jsonrpc' => '2.0',
        'method' => $method,
        'params' => $params,
        'id' => $id,
    ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($payload === false) {
        throw new RuntimeException('json_encode failed');
    }
    $ch = curl_init($apiUrl);
    if ($ch === false) {
        throw new RuntimeException('curl_init failed');
    }
    $headers = [
        'Content-Type: application/json-rpc',
    ];
    if ($token !== '') {
        $headers[] = 'Authorization: Bearer ' . $token;
    }
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeoutSec,
        CURLOPT_CONNECTTIMEOUT => min(8, $timeoutSec),
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    ]);
    $raw = curl_exec($ch);
    $errno = curl_errno($ch);
    $err = $errno ? curl_error($ch) : '';
    curl_close($ch);
    if ($raw === false) {
        throw new RuntimeException('Zabbix HTTP error: ' . ($err !== '' ? $err : 'empty response'));
    }
    $decoded = json_decode($raw, true);
    if (! is_array($decoded)) {
        throw new RuntimeException('Zabbix invalid JSON response');
    }
    if (isset($decoded['error']) && is_array($decoded['error'])) {
        $msg = (string) ($decoded['error']['data'] ?? $decoded['error']['message'] ?? 'Zabbix API error');

        throw new RuntimeException($msg);
    }

    return $decoded['result'] ?? null;
}

function st_zabbix_availability_label(mixed $code): string
{
    $i = (int) $code;

    return match ($i) {
        1 => 'available',
        2 => 'unavailable',
        default => 'unknown',
    };
}

/**
 * Normalize MAC for comparison (12 hex) or empty string.
 */
function st_zabbix_norm_mac(string $m): string
{
    $m = strtolower(preg_replace('/[^a-f0-9]/', '', $m) ?? '');

    return strlen($m) === 12 ? $m : '';
}

/**
 * @param array<int,array<string,mixed>> $hosts
 * @return array<string,int>
 */
function st_zabbix_fetch_problem_counts(string $apiUrl, string $token, array $hosts): array
{
    if ($hosts === []) {
        return [];
    }
    $hostids = array_values(array_filter(array_map(static fn ($h) => (string) ($h['hostid'] ?? ''), $hosts)));
    $counts = array_fill_keys($hostids, 0);
    if ($hostids === []) {
        return $counts;
    }
    $chunks = array_chunk($hostids, 200);
    $remaining = ST_ZABBIX_SYNC_PROBLEM_LIMIT;
    try {
        foreach ($chunks as $chunk) {
            if ($remaining <= 0) {
                break;
            }
            $res = st_zabbix_jsonrpc($apiUrl, $token, 'problem.get', [
                'output' => ['eventid', 'severity'],
                'selectHosts' => ['hostid'],
                'hostids' => $chunk,
                'recent' => true,
                'limit' => min(2000, $remaining),
            ], ST_ZABBIX_HTTP_TIMEOUT_SEC);
            if (! is_array($res)) {
                continue;
            }
            foreach ($res as $pr) {
                if (! is_array($pr)) {
                    continue;
                }
                $hlist = $pr['hosts'] ?? [];
                if (! is_array($hlist)) {
                    continue;
                }
                foreach ($hlist as $hh) {
                    if (! is_array($hh)) {
                        continue;
                    }
                    $hid = (string) ($hh['hostid'] ?? '');
                    if ($hid !== '' && array_key_exists($hid, $counts)) {
                        $counts[$hid]++;
                    }
                }
            }
            $remaining -= 2000;
        }
    } catch (Throwable $e) {
        $em = st_zabbix_redact_secrets(preg_replace('/[\x00-\x1F\x7F]/u', ' ', $e->getMessage()) ?? '');
        @error_log('SurveyTrace Zabbix problem.get: ' . $em);
    }

    return $counts;
}

/**
 * Run full replace sync + rematch. Updates zabbix_connector last_sync_*.
 *
 * @return array<string,mixed>
 */
function st_zabbix_run_full_sync(PDO $pdo): array
{
    $c = st_zabbix_connector_get($pdo);
    $url = (string) ($c['api_url'] ?? '');
    $tok = (string) ($c['api_token'] ?? '');
    if ($url === '' || $tok === '') {
        throw new RuntimeException('Zabbix connector is not configured (api_url / api_token)');
    }
    if ((int) ($c['enabled'] ?? 0) !== 1) {
        throw new RuntimeException('Zabbix connector is disabled');
    }
    $apiUrl = st_zabbix_normalize_api_url($url);
    try {
        $hosts = st_zabbix_jsonrpc($apiUrl, $tok, 'host.get', [
            'output' => ['hostid', 'host', 'name', 'status', 'available'],
            'selectInterfaces' => ['interfaceid', 'ip', 'dns', 'port', 'type', 'main', 'useip', 'macaddress'],
            'selectGroups' => ['groupid', 'name'],
            'selectParentTemplates' => ['templateid', 'name'],
            'selectTags' => ['tag', 'value'],
            'selectInventory' => 'extend',
            'limit' => ST_ZABBIX_SYNC_HOST_LIMIT,
            'sortfield' => 'hostid',
        ], ST_ZABBIX_HTTP_TIMEOUT_SEC);
        if (! is_array($hosts)) {
            $hosts = [];
        }
        $problemCounts = st_zabbix_fetch_problem_counts($apiUrl, $tok, $hosts);

        $pdo->exec('BEGIN IMMEDIATE');
        try {
            $pdo->exec('DELETE FROM zabbix_hosts');
            $insHost = $pdo->prepare(
                'INSERT INTO zabbix_hosts (
                hostid, tech_name, visible_name, monitored, available, status_raw_json,
                inventory_json, groups_json, tags_json, templates_json, interfaces_json, synced_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?, datetime(\'now\'))'
            );
            $insIface = $pdo->prepare(
                'INSERT INTO zabbix_host_interfaces (hostid, interfaceid, ip, dns, port, iface_type, main, useip, mac, raw_json)
             VALUES (?,?,?,?,?,?,?,?,?,?)'
            );
            $insGrp = $pdo->prepare(
                'INSERT INTO zabbix_host_groups (hostid, groupid, group_name) VALUES (?,?,?)'
            );
            $insTag = $pdo->prepare(
                'INSERT INTO zabbix_host_tags (hostid, tag, value) VALUES (?,?,?)'
            );
            $insProb = $pdo->prepare(
                'INSERT INTO zabbix_host_problems_summary (hostid, open_count, summary_json) VALUES (?,?,?)'
            );

            foreach ($hosts as $h) {
                if (! is_array($h)) {
                    continue;
                }
                $hostid = (string) ($h['hostid'] ?? '');
                if ($hostid === '') {
                    continue;
                }
                $tech = (string) ($h['host'] ?? '');
                $vis = (string) ($h['name'] ?? '');
                if ($vis === '') {
                    $vis = $tech;
                }
                $monitored = ((int) ($h['status'] ?? 1)) === 0 ? 1 : 0;
                $avail = st_zabbix_availability_label($h['available'] ?? 0);
                $statusJson = json_encode([
                    'status' => $h['status'] ?? null,
                    'available' => $h['available'] ?? null,
                ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?: '{}';
                $inv = $h['inventory'] ?? [];
                if (! is_array($inv)) {
                    $inv = [];
                }
                $invJson = json_encode($inv, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?: '{}';
                $groups = $h['groups'] ?? [];
                if (! is_array($groups)) {
                    $groups = [];
                }
                $tags = $h['tags'] ?? [];
                if (! is_array($tags)) {
                    $tags = [];
                }
                $tmpls = $h['parentTemplates'] ?? [];
                if (! is_array($tmpls)) {
                    $tmpls = [];
                }
                $ifaces = $h['interfaces'] ?? [];
                if (! is_array($ifaces)) {
                    $ifaces = [];
                }
                $insHost->execute([
                    $hostid,
                    $tech,
                    $vis,
                    $monitored,
                    $avail,
                    $statusJson,
                    $invJson,
                    json_encode($groups, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?: '[]',
                    json_encode($tags, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?: '[]',
                    json_encode($tmpls, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?: '[]',
                    json_encode($ifaces, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?: '[]',
                ]);
                foreach ($groups as $g) {
                    if (! is_array($g)) {
                        continue;
                    }
                    $gid = (string) ($g['groupid'] ?? '');
                    if ($gid === '') {
                        continue;
                    }
                    $insGrp->execute([$hostid, $gid, (string) ($g['name'] ?? '')]);
                }
                foreach ($tags as $t) {
                    if (! is_array($t)) {
                        continue;
                    }
                    $insTag->execute([$hostid, (string) ($t['tag'] ?? ''), (string) ($t['value'] ?? '')]);
                }
                $invMac = st_zabbix_norm_mac((string) ($inv['macaddress_a'] ?? ''));
                foreach ($ifaces as $iface) {
                    if (! is_array($iface)) {
                        continue;
                    }
                    $iid = (string) ($iface['interfaceid'] ?? '');
                    if ($iid === '') {
                        continue;
                    }
                    $mac = st_zabbix_norm_mac((string) ($iface['macaddress'] ?? ''));
                    if ($mac === '' && $invMac !== '') {
                        $mac = $invMac;
                    }
                    $rawIf = json_encode($iface, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) ?: '{}';
                    $insIface->execute([
                        $hostid,
                        $iid,
                        (string) ($iface['ip'] ?? ''),
                        (string) ($iface['dns'] ?? ''),
                        (int) ($iface['port'] ?? 10050),
                        (string) ($iface['type'] ?? ''),
                        (int) ($iface['main'] ?? 0),
                        (int) ($iface['useip'] ?? 1),
                        $mac,
                        $rawIf,
                    ]);
                }
                $pc = (int) ($problemCounts[$hostid] ?? 0);
                $insProb->execute([
                    $hostid,
                    $pc,
                    json_encode(['open_count' => $pc, 'note' => 'counts from problem.get capped at ' . ST_ZABBIX_SYNC_PROBLEM_LIMIT], JSON_UNESCAPED_SLASHES) ?: '{}',
                ]);
            }
            $pdo->exec('COMMIT');
        } catch (Throwable $e) {
            $pdo->exec('ROLLBACK');
            throw $e;
        }

        $matchStats = st_zabbix_rematch_assets($pdo);
        st_zabbix_refresh_asset_zabbix_denorm_all($pdo);

        $upd = $pdo->prepare(
            'UPDATE zabbix_connector SET last_sync_at = datetime(\'now\'), last_sync_status = ?, last_error = ?, updated_at = datetime(\'now\') WHERE id = 1'
        );
        $upd->execute(['ok', null]);

        return [
            'hosts_synced' => count($hosts),
            'match' => $matchStats,
        ];
    } catch (Throwable $e) {
        try {
            $safeErr = st_zabbix_redact_secrets(substr($e->getMessage(), 0, 2000));
            $pdo->prepare(
                'UPDATE zabbix_connector SET last_sync_at = datetime(\'now\'), last_sync_status = ?, last_error = ?, updated_at = datetime(\'now\') WHERE id = 1'
            )->execute(['error', $safeErr]);
        } catch (Throwable $e2) {
        }
        throw $e;
    }
}

/**
 * @return array<string,int|float>
 */
function st_zabbix_rematch_assets(PDO $pdo): array
{
    if (! st_zabbix_table_ready($pdo)) {
        return ['pairs' => 0, 'assets_unmatched' => 0, 'hosts_unmatched' => 0];
    }
    $assets = $pdo->query('SELECT id, ip, hostname, mac FROM assets')->fetchAll(PDO::FETCH_ASSOC);
    $byIp = [];
    $byHost = [];
    $byMac = [];
    foreach ($assets as $a) {
        if (! is_array($a)) {
            continue;
        }
        $aid = (int) ($a['id'] ?? 0);
        if ($aid <= 0) {
            continue;
        }
        $ip = strtolower(trim((string) ($a['ip'] ?? '')));
        if ($ip !== '') {
            $byIp[$ip] = $aid;
        }
        $hn = strtolower(trim((string) ($a['hostname'] ?? '')));
        if ($hn !== '') {
            $byHost[$hn] = $aid;
        }
        $mac = st_zabbix_norm_mac((string) ($a['mac'] ?? ''));
        if ($mac !== '') {
            $byMac[$mac] = $aid;
        }
    }

    $zrows = $pdo->query(
        'SELECT h.hostid, h.tech_name, h.visible_name, h.inventory_json FROM zabbix_hosts h'
    )->fetchAll(PDO::FETCH_ASSOC);

    $candidates = [];
    foreach ($zrows as $zr) {
        if (! is_array($zr)) {
            continue;
        }
        $hostid = (string) ($zr['hostid'] ?? '');
        if ($hostid === '') {
            continue;
        }
        $tech = strtolower(trim((string) ($zr['tech_name'] ?? '')));
        $vis = strtolower(trim((string) ($zr['visible_name'] ?? '')));
        $inv = json_decode((string) ($zr['inventory_json'] ?? '{}'), true);
        if (! is_array($inv)) {
            $inv = [];
        }
        $invMac = st_zabbix_norm_mac((string) ($inv['macaddress_a'] ?? ''));
        $pairs = [];
        $stIf = $pdo->prepare(
            'SELECT ip, dns, mac FROM zabbix_host_interfaces WHERE hostid = ? ORDER BY main DESC, interfaceid'
        );
        $stIf->execute([$hostid]);
        foreach ($stIf->fetchAll(PDO::FETCH_ASSOC) as $iface) {
            if (! is_array($iface)) {
                continue;
            }
            $ip = strtolower(trim((string) ($iface['ip'] ?? '')));
            $dns = strtolower(trim((string) ($iface['dns'] ?? '')));
            $mac = st_zabbix_norm_mac((string) ($iface['mac'] ?? ''));
            if ($ip !== '') {
                $pairs[] = ['t' => 'ip', 'v' => $ip, 'c' => 1.0];
            }
            if ($dns !== '') {
                $pairs[] = ['t' => 'dns', 'v' => $dns, 'c' => 0.93];
            }
            if ($mac !== '') {
                $pairs[] = ['t' => 'mac', 'v' => $mac, 'c' => 0.98];
            }
        }
        if ($invMac !== '') {
            $pairs[] = ['t' => 'mac', 'v' => $invMac, 'c' => 0.97];
        }
        if ($tech !== '') {
            $pairs[] = ['t' => 'hostname', 'v' => $tech, 'c' => 0.95];
        }
        if ($vis !== '' && $vis !== $tech) {
            $pairs[] = ['t' => 'visible_name', 'v' => $vis, 'c' => 0.88];
        }

        $bestConf = 0.0;
        $bestAid = 0;
        $bestMethod = '';
        foreach ($pairs as $p) {
            $t = (string) $p['t'];
            $v = (string) $p['v'];
            $baseC = (float) $p['c'];
            $aid = 0;
            if ($t === 'ip' && isset($byIp[$v])) {
                $aid = $byIp[$v];
            } elseif ($t === 'dns' && isset($byHost[$v])) {
                $aid = $byHost[$v];
            } elseif ($t === 'hostname' && isset($byHost[$v])) {
                $aid = $byHost[$v];
            } elseif ($t === 'visible_name' && isset($byHost[$v])) {
                $aid = $byHost[$v];
            } elseif ($t === 'mac' && isset($byMac[$v])) {
                $aid = $byMac[$v];
            }
            if ($aid <= 0) {
                continue;
            }
            $rank = st_zabbix_match_method_rank($t);
            $bestRank = st_zabbix_match_method_rank($bestMethod);
            $tie = abs($baseC - $bestConf) < 1e-9;
            if ($baseC > $bestConf || ($tie && $rank > $bestRank)) {
                $bestConf = $baseC;
                $bestAid = $aid;
                $bestMethod = $t;
            }
        }
        if ($bestAid > 0 && $bestConf >= 0.75) {
            $candidates[] = [
                'hostid' => $hostid,
                'asset_id' => $bestAid,
                'confidence' => $bestConf,
                'match_method' => $bestMethod,
            ];
        }
    }

    usort($candidates, static fn ($a, $b) => ($b['confidence'] <=> $a['confidence']));
    $pdo->exec('DELETE FROM zabbix_asset_links WHERE COALESCE(is_manual, 0) != 1');
    $usedA = [];
    $usedH = [];
    $stKeep = $pdo->query('SELECT asset_id, zabbix_hostid FROM zabbix_asset_links WHERE COALESCE(is_manual, 0) = 1');
    if ($stKeep) {
        foreach ($stKeep->fetchAll(PDO::FETCH_ASSOC) as $kr) {
            if (! is_array($kr)) {
                continue;
            }
            $usedA[(int) ($kr['asset_id'] ?? 0)] = 1;
            $usedH[(string) ($kr['zabbix_hostid'] ?? '')] = 1;
        }
    }
    $ins = $pdo->prepare(
        'INSERT INTO zabbix_asset_links (asset_id, zabbix_hostid, match_method, confidence, last_matched_at, is_manual)
         VALUES (?,?,?,?, datetime(\'now\'), 0)'
    );
    foreach ($candidates as $c) {
        $aid = (int) $c['asset_id'];
        $hid = (string) $c['hostid'];
        if (isset($usedA[$aid]) || isset($usedH[$hid])) {
            continue;
        }
        $usedA[$aid] = 1;
        $usedH[$hid] = 1;
        $ins->execute([$aid, $hid, (string) $c['match_method'], (float) $c['confidence']]);
    }

    $totalLinks = (int) $pdo->query('SELECT COUNT(1) FROM zabbix_asset_links')->fetchColumn();
    $totalHosts = (int) $pdo->query('SELECT COUNT(1) FROM zabbix_hosts')->fetchColumn();
    $totalAssets = (int) $pdo->query('SELECT COUNT(1) FROM assets')->fetchColumn();

    return [
        'pairs' => $totalLinks,
        'hosts_unmatched' => max(0, $totalHosts - $totalLinks),
        'assets_unmatched' => max(0, $totalAssets - $totalLinks),
    ];
}

/**
 * Read-only enrichment for a single asset (API payload).
 *
 * @return array<string,mixed>|null
 */
function st_zabbix_enrichment_for_asset(PDO $pdo, int $assetId): ?array
{
    if (! st_zabbix_table_ready($pdo) || $assetId <= 0) {
        return null;
    }
    $st = $pdo->prepare(
        'SELECT l.zabbix_hostid, l.match_method, l.confidence, l.last_matched_at, COALESCE(l.is_manual, 0) AS is_manual,
                h.monitored, h.available, h.inventory_json, h.templates_json
         FROM zabbix_asset_links l
         JOIN zabbix_hosts h ON h.hostid = l.zabbix_hostid
         WHERE l.asset_id = ? LIMIT 1'
    );
    $st->execute([$assetId]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (! is_array($row)) {
        return [
            'linked' => false,
            'monitored' => null,
            'availability' => null,
            'host_groups' => [],
            'templates' => [],
            'tags' => [],
            'inventory' => null,
            'open_problem_count' => null,
            'match' => null,
        ];
    }
    $hid = (string) $row['zabbix_hostid'];
    $gst = $pdo->prepare('SELECT group_name FROM zabbix_host_groups WHERE hostid = ? ORDER BY group_name');
    $gst->execute([$hid]);
    $groups = array_values(array_filter(array_map(static fn ($g) => (string) ($g['group_name'] ?? ''), $gst->fetchAll(PDO::FETCH_ASSOC))));
    if (count($groups) > 100) {
        $groups = array_slice($groups, 0, 100);
    }

    $tst = $pdo->prepare('SELECT tag, value FROM zabbix_host_tags WHERE hostid = ? ORDER BY tag, value');
    $tst->execute([$hid]);
    $tagRows = $tst->fetchAll(PDO::FETCH_ASSOC);
    $tags = [];
    foreach ($tagRows as $tr) {
        if (! is_array($tr)) {
            continue;
        }
        $tags[] = [
            'tag' => (string) ($tr['tag'] ?? ''),
            'value' => (string) ($tr['value'] ?? ''),
        ];
    }
    if (count($tags) > 80) {
        $tags = array_slice($tags, 0, 80);
    }

    $tmpls = [];
    $tj = json_decode((string) ($row['templates_json'] ?? '[]'), true);
    if (is_array($tj)) {
        foreach ($tj as $t) {
            if (is_array($t)) {
                $tmpls[] = (string) ($t['name'] ?? '');
            }
        }
        $tmpls = array_values(array_filter($tmpls));
    }
    if (count($tmpls) > 60) {
        $tmpls = array_slice($tmpls, 0, 60);
    }

    $inv = json_decode((string) ($row['inventory_json'] ?? '{}'), true);
    if (! is_array($inv)) {
        $inv = [];
    }
    $owner = trim((string) ($inv['contact'] ?? ''));
    if ($owner === '') {
        $owner = trim((string) ($inv['alias'] ?? ''));
    }
    $loc = trim((string) ($inv['location'] ?? ''));
    $env = trim((string) ($inv['deployment'] ?? ''));
    if ($env === '') {
        $env = trim((string) ($inv['type'] ?? ''));
    }

    $pst = $pdo->prepare('SELECT open_count FROM zabbix_host_problems_summary WHERE hostid = ?');
    $pst->execute([$hid]);
    $pc = (int) ($pst->fetchColumn() ?: 0);

    return [
        'linked' => true,
        'zabbix_hostid' => $hid,
        'match' => [
            'method' => (string) $row['match_method'],
            'confidence' => (float) $row['confidence'],
            'last_matched_at' => $row['last_matched_at'] ?? null,
            'manual' => ((int) ($row['is_manual'] ?? 0)) === 1,
        ],
        'monitored' => ((int) $row['monitored']) === 1,
        'availability' => (string) ($row['available'] ?? 'unknown'),
        'host_groups' => $groups,
        'templates' => $tmpls,
        'tags' => $tags,
        'inventory' => [
            'owner' => $owner !== '' ? $owner : null,
            'location' => $loc !== '' ? $loc : null,
            'environment' => $env !== '' ? $env : null,
        ],
        'open_problem_count' => $pc,
    ];
}

/**
 * @return array<int,array<string,mixed>>
 */
function st_zabbix_scope_rules_all(PDO $pdo): array
{
    if (! st_zabbix_table_ready($pdo)) {
        return [];
    }
    if (! st_zabbix_scan_scopes_table_exists($pdo)) {
        return $pdo->query('SELECT id, rule_type, pattern, scope_id, enabled, created_at, 1 AS scope_missing, NULL AS scope_name FROM zabbix_scope_map_rules ORDER BY id')->fetchAll(PDO::FETCH_ASSOC)
            ?: [];
    }

    $sql = 'SELECT r.id, r.rule_type, r.pattern, r.scope_id, r.enabled, r.created_at,
                   s.name AS scope_name,
                   CASE WHEN s.id IS NULL THEN 1 ELSE 0 END AS scope_missing
            FROM zabbix_scope_map_rules r
            LEFT JOIN scan_scopes s ON s.id = r.scope_id
            ORDER BY r.id';

    return $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC) ?: [];
}

/**
 * Valid scan_scopes.id values, or empty set if table missing.
 *
 * @return array<int, true>
 */
function st_zabbix_scope_id_set(PDO $pdo): array
{
    if (! st_zabbix_scan_scopes_table_exists($pdo)) {
        return [];
    }
    $st = $pdo->query('SELECT id FROM scan_scopes');
    $out = [];
    foreach ($st ? $st->fetchAll(PDO::FETCH_ASSOC) : [] as $row) {
        if (! is_array($row)) {
            continue;
        }
        $id = (int) ($row['id'] ?? 0);
        if ($id > 0) {
            $out[$id] = true;
        }
    }

    return $out;
}

/**
 * Validate Zabbix scope-map rules from API/UI. Empty array clears all rules (allowed).
 *
 * @param array<int, array<string, mixed>> $rules
 * @return array{ok: bool, errors: array<int, string>, valid_count: int}
 */
function st_zabbix_scope_rules_validate(PDO $pdo, array $rules): array
{
    $errors = [];
    $valid = 0;
    if ($rules === []) {
        return ['ok' => true, 'errors' => [], 'valid_count' => 0];
    }
    if (! st_zabbix_scan_scopes_table_exists($pdo)) {
        return ['ok' => false, 'errors' => ['scan_scopes table is missing — run migrations'], 'valid_count' => 0];
    }
    $scopeSet = st_zabbix_scope_id_set($pdo);
    if ($scopeSet === []) {
        return ['ok' => false, 'errors' => ['No scan scopes exist — create a scope before saving Zabbix mapping rules'], 'valid_count' => 0];
    }
    $rowNum = 0;
    foreach ($rules as $r) {
        ++$rowNum;
        if (! is_array($r)) {
            $errors[] = 'Row ' . $rowNum . ': invalid rule object';
            continue;
        }
        $type = strtolower(trim((string) ($r['rule_type'] ?? '')));
        $pattern = trim((string) ($r['pattern'] ?? ''));
        $sid = (int) ($r['scope_id'] ?? 0);
        $label = isset($r['_row']) ? ('Row ' . (int) $r['_row']) : ('Rule ' . $rowNum);
        if ($type === '' && $pattern === '' && $sid <= 0) {
            $errors[] = $label . ': empty rule — remove the row or complete type, pattern, and scope';
            continue;
        }
        if (! in_array($type, ['group', 'tag'], true)) {
            $errors[] = $label . ': rule_type must be group or tag';
            continue;
        }
        if ($pattern === '') {
            $errors[] = $label . ': pattern is required';
            continue;
        }
        if ($sid <= 0) {
            $errors[] = $label . ': scope is required (select a scan scope)';
            continue;
        }
        if (! isset($scopeSet[$sid])) {
            $errors[] = $label . ': scope_id ' . $sid . ' does not exist in scan_scopes';
            continue;
        }
        ++$valid;
    }

    return ['ok' => $errors === [], 'errors' => $errors, 'valid_count' => $valid];
}

/**
 * Replace all scope map rules with the given set (transactional). Validates first — does not silently drop rows.
 *
 * @param array<int, array<string, mixed>> $rules
 *
 * @throws InvalidArgumentException on validation failure
 */
function st_zabbix_scope_rules_replace(PDO $pdo, array $rules): void
{
    $v = st_zabbix_scope_rules_validate($pdo, $rules);
    if (! $v['ok']) {
        throw new InvalidArgumentException(implode(' ', $v['errors']));
    }
    $pdo->exec('BEGIN IMMEDIATE');
    try {
        $pdo->exec('DELETE FROM zabbix_scope_map_rules');
        $ins = $pdo->prepare(
            'INSERT INTO zabbix_scope_map_rules (rule_type, pattern, scope_id, enabled) VALUES (?,?,?,?)'
        );
        foreach ($rules as $r) {
            if (! is_array($r)) {
                continue;
            }
            $type = strtolower(trim((string) ($r['rule_type'] ?? '')));
            $pattern = trim((string) ($r['pattern'] ?? ''));
            $sid = (int) ($r['scope_id'] ?? 0);
            $en = ! empty($r['enabled']) ? 1 : 0;
            $ins->execute([$type, $pattern, $sid, $en]);
        }
        $pdo->exec('COMMIT');
    } catch (Throwable $e) {
        $pdo->exec('ROLLBACK');
        throw $e;
    }
}

/**
 * @throws InvalidArgumentException when enabled rules reference a missing scan_scopes row
 */
function st_zabbix_assert_no_enabled_stale_scope_rules(PDO $pdo): void
{
    if (! st_zabbix_table_ready($pdo) || ! st_zabbix_scan_scopes_table_exists($pdo)) {
        return;
    }
    $n = (int) $pdo->query(
        'SELECT COUNT(1) FROM zabbix_scope_map_rules r
         LEFT JOIN scan_scopes s ON s.id = r.scope_id
         WHERE r.enabled = 1 AND s.id IS NULL'
    )->fetchColumn();
    if ($n > 0) {
        throw new InvalidArgumentException(
            'Enabled rules reference a deleted scan scope. Edit or remove those rules under Enrichment → Zabbix before previewing or applying.'
        );
    }
}

/**
 * Preview which assets would match scope rules (no writes, no asset scope changes).
 *
 * @param array<int,array<string,mixed>> $rules
 * @return array<int,array<string,mixed>>
 */
function st_zabbix_preview_scope_map(PDO $pdo, array $rules): array
{
    $v = st_zabbix_scope_rules_validate($pdo, $rules);
    if (! $v['ok']) {
        throw new InvalidArgumentException(implode(' ', $v['errors']));
    }
    if ($rules === []) {
        return [];
    }
    $st = $pdo->query(
        'SELECT l.asset_id, a.ip, a.hostname, a.scope_id AS current_scope_id, l.zabbix_hostid
         FROM zabbix_asset_links l JOIN assets a ON a.id = l.asset_id'
    );
    $rows = $st ? $st->fetchAll(PDO::FETCH_ASSOC) : [];
    $out = [];
    foreach ($rows as $row) {
        if (! is_array($row)) {
            continue;
        }
        $aid = (int) ($row['asset_id'] ?? 0);
        $zh = (string) ($row['zabbix_hostid'] ?? '');
        if ($aid <= 0 || $zh === '') {
            continue;
        }
        $gst = $pdo->prepare('SELECT group_name FROM zabbix_host_groups WHERE hostid = ?');
        $gst->execute([$zh]);
        $groupNames = [];
        foreach ($gst->fetchAll(PDO::FETCH_ASSOC) as $g) {
            if (is_array($g) && (string) ($g['group_name'] ?? '') !== '') {
                $groupNames[] = (string) $g['group_name'];
            }
        }
        $tst = $pdo->prepare('SELECT tag, value FROM zabbix_host_tags WHERE hostid = ?');
        $tst->execute([$zh]);
        $tagPairs = [];
        foreach ($tst->fetchAll(PDO::FETCH_ASSOC) as $t) {
            if (! is_array($t)) {
                continue;
            }
            $tagPairs[] = [(string) ($t['tag'] ?? ''), (string) ($t['value'] ?? '')];
        }
        foreach ($rules as $rule) {
            if (! is_array($rule)) {
                continue;
            }
            if ((int) ($rule['enabled'] ?? 0) !== 1) {
                continue;
            }
            $type = strtolower(trim((string) ($rule['rule_type'] ?? '')));
            $pattern = trim((string) ($rule['pattern'] ?? ''));
            $sid = (int) ($rule['scope_id'] ?? 0);
            if ($pattern === '' || $sid <= 0) {
                continue;
            }
            $hit = false;
            $detail = '';
            if ($type === 'group') {
                foreach ($groupNames as $gn) {
                    if (strcasecmp($gn, $pattern) === 0) {
                        $hit = true;
                        $detail = 'host_group:' . $gn;
                        break;
                    }
                }
            } elseif ($type === 'tag') {
                if (str_contains($pattern, '=')) {
                    [$tk, $tv] = array_map('trim', explode('=', $pattern, 2));
                    foreach ($tagPairs as [$kt, $kv]) {
                        if (strcasecmp($kt, $tk) === 0 && (string) $kv === $tv) {
                            $hit = true;
                            $detail = 'tag:' . $kt . '=' . $kv;
                            break;
                        }
                    }
                } else {
                    foreach ($tagPairs as [$kt, $kv]) {
                        if (strcasecmp($kt, $pattern) === 0) {
                            $hit = true;
                            $detail = 'tag:' . $kt . '=' . $kv;
                            break;
                        }
                    }
                }
            }
            if ($hit) {
                $curScope = $row['current_scope_id'] ?? null;
                $out[] = [
                    'asset_id' => $aid,
                    'ip' => (string) ($row['ip'] ?? ''),
                    'hostname' => (string) ($row['hostname'] ?? ''),
                    'zabbix_hostid' => $zh,
                    'current_scope_id' => $curScope !== null && $curScope !== '' ? (int) $curScope : null,
                    'suggested_scope_id' => $sid,
                    'rule_type' => $type,
                    'pattern' => $pattern,
                    'detail' => $detail,
                ];
                break;
            }
        }
    }

    return $out;
}

/**
 * @return array<string,mixed>
 */
function st_zabbix_stats(PDO $pdo): array
{
    if (! st_zabbix_table_ready($pdo)) {
        return [
            'hosts' => 0,
            'matched_pairs' => 0,
            'hosts_unmatched' => 0,
            'assets_unmatched' => 0,
        ];
    }
    $hosts = (int) $pdo->query('SELECT COUNT(1) FROM zabbix_hosts')->fetchColumn();
    $matched = (int) $pdo->query('SELECT COUNT(1) FROM zabbix_asset_links')->fetchColumn();
    $assetsTotal = (int) $pdo->query('SELECT COUNT(1) FROM assets')->fetchColumn();

    return [
        'hosts' => $hosts,
        'matched_pairs' => $matched,
        'hosts_unmatched' => max(0, $hosts - $matched),
        'assets_unmatched' => max(0, $assetsTotal - $matched),
    ];
}

/**
 * @return array<int,array<string,mixed>>
 */
function st_zabbix_sample_matches(PDO $pdo, int $limit = 8): array
{
    if (! st_zabbix_table_ready($pdo)) {
        return [];
    }
    $lim = max(1, min(25, $limit));
    $sql = "SELECT a.ip, a.hostname, h.visible_name AS zabbix_visible, h.tech_name AS zabbix_tech,
                   l.zabbix_hostid, l.match_method, l.confidence
            FROM zabbix_asset_links l
            JOIN assets a ON a.id = l.asset_id
            JOIN zabbix_hosts h ON h.hostid = l.zabbix_hostid
            ORDER BY l.confidence DESC, a.ip
            LIMIT {$lim}";
    $st = $pdo->query($sql);

    return $st ? $st->fetchAll(PDO::FETCH_ASSOC) : [];
}

/**
 * Spawn CLI worker; returns false if spawn failed.
 */
function st_zabbix_spawn_worker(): bool
{
    $worker = realpath(__DIR__ . '/zabbix_sync_worker.php');
    if ($worker === false || ! is_file($worker)) {
        return false;
    }
    $root = realpath(__DIR__ . '/..');
    if ($root === false) {
        return false;
    }
    if (PHP_OS_FAMILY === 'Windows') {
        if (! function_exists('popen') || in_array('popen', explode(',', (string) ini_get('disable_functions')), true)) {
            return false;
        }
        $cmd = sprintf(
            'start /B "" %s %s',
            escapeshellarg(st_zabbix_php_cli()),
            escapeshellarg($worker)
        );
        pclose(popen($cmd, 'r'));

        return true;
    }
    if (! st_zabbix_exec_available()) {
        return false;
    }
    $log = ST_DATA_DIR . '/zabbix_sync_worker.log';
    $cmd = sprintf(
        'cd %s && nohup %s %s >> %s 2>&1 &',
        escapeshellarg($root),
        escapeshellarg(st_zabbix_php_cli()),
        escapeshellarg($worker),
        escapeshellarg($log)
    );
    @exec($cmd);

    return true;
}

function st_zabbix_asset_workflow_columns_ready(PDO $pdo): bool
{
    static $cache = null;
    if ($cache !== null) {
        return $cache;
    }
    $cols = $pdo->query('PRAGMA table_info(assets)')->fetchAll(PDO::FETCH_COLUMN, 1);
    $cache = is_array($cols) && in_array('monitored_by_zabbix', $cols, true);

    return $cache;
}

function st_zabbix_scan_scopes_table_exists(PDO $pdo): bool
{
    $n = (int) $pdo->query(
        "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='scan_scopes'"
    )->fetchColumn();

    return $n === 1;
}

/**
 * Denormalize Zabbix trust fields onto assets (clears then sets for linked rows).
 */
function st_zabbix_refresh_asset_zabbix_denorm_all(PDO $pdo): void
{
    if (! st_zabbix_table_ready($pdo) || ! st_zabbix_asset_workflow_columns_ready($pdo)) {
        return;
    }
    $pdo->exec(
        "UPDATE assets SET monitored_by_zabbix = 0, zabbix_availability = '', zabbix_problem_count = 0"
    );
    $q = $pdo->query(
        'SELECT l.asset_id, h.monitored, h.available, COALESCE(p.open_count, 0) AS oc
         FROM zabbix_asset_links l
         JOIN zabbix_hosts h ON h.hostid = l.zabbix_hostid
         LEFT JOIN zabbix_host_problems_summary p ON p.hostid = l.zabbix_hostid'
    );
    if (! $q) {
        return;
    }
    $upd = $pdo->prepare(
        'UPDATE assets SET monitored_by_zabbix = ?, zabbix_availability = ?, zabbix_problem_count = ? WHERE id = ?'
    );
    foreach ($q->fetchAll(PDO::FETCH_ASSOC) as $row) {
        if (! is_array($row)) {
            continue;
        }
        $upd->execute([
            (int) ($row['monitored'] ?? 0),
            (string) ($row['available'] ?? ''),
            (int) ($row['oc'] ?? 0),
            (int) ($row['asset_id'] ?? 0),
        ]);
    }
}

/**
 * @return array{groups: array<int, string>, tags: array<int, array{0:string,1:string}>}
 */
function st_zabbix_host_groups_and_tags(PDO $pdo, string $hostid): array
{
    $groups = [];
    $gst = $pdo->prepare('SELECT group_name FROM zabbix_host_groups WHERE hostid = ?');
    $gst->execute([$hostid]);
    foreach ($gst->fetchAll(PDO::FETCH_ASSOC) as $g) {
        if (is_array($g) && (string) ($g['group_name'] ?? '') !== '') {
            $groups[] = (string) $g['group_name'];
        }
    }
    $tags = [];
    $tst = $pdo->prepare('SELECT tag, value FROM zabbix_host_tags WHERE hostid = ?');
    $tst->execute([$hostid]);
    foreach ($tst->fetchAll(PDO::FETCH_ASSOC) as $t) {
        if (is_array($t)) {
            $tags[] = [(string) ($t['tag'] ?? ''), (string) ($t['value'] ?? '')];
        }
    }

    return ['groups' => $groups, 'tags' => $tags];
}

/**
 * @param array<int, array<string,mixed>> $rules rows with rule_type, pattern, scope_id
 */
function st_zabbix_first_matching_scope_id(array $rules, array $groupNames, array $tagPairs): ?int
{
    foreach ($rules as $rule) {
        if (! is_array($rule)) {
            continue;
        }
        $type = strtolower(trim((string) ($rule['rule_type'] ?? '')));
        $pattern = trim((string) ($rule['pattern'] ?? ''));
        $sid = (int) ($rule['scope_id'] ?? 0);
        if ($pattern === '' || $sid <= 0) {
            continue;
        }
        if ($type === 'group') {
            foreach ($groupNames as $gn) {
                if (strcasecmp($gn, $pattern) === 0) {
                    return $sid;
                }
            }
        } elseif ($type === 'tag') {
            if (str_contains($pattern, '=')) {
                [$tk, $tv] = array_map('trim', explode('=', $pattern, 2));
                foreach ($tagPairs as [$kt, $kv]) {
                    if (strcasecmp($kt, $tk) === 0 && (string) $kv === $tv) {
                        return $sid;
                    }
                }
            } else {
                foreach ($tagPairs as [$kt, $kv]) {
                    if (strcasecmp($kt, $pattern) === 0) {
                        return $sid;
                    }
                }
            }
        }
    }

    return null;
}

function st_zabbix_norm_scope_id(mixed $v): ?int
{
    if ($v === null || $v === '') {
        return null;
    }
    $i = (int) $v;

    return $i > 0 ? $i : null;
}

/**
 * Suggested scan_scopes.id from enabled DB rules for a linked asset, or null.
 */
function st_zabbix_suggest_scope_for_asset(PDO $pdo, int $assetId): ?int
{
    if (! st_zabbix_table_ready($pdo) || $assetId <= 0) {
        return null;
    }
    $st = $pdo->prepare('SELECT zabbix_hostid FROM zabbix_asset_links WHERE asset_id = ? LIMIT 1');
    $st->execute([$assetId]);
    $hid = $st->fetchColumn();
    if (! is_string($hid) || $hid === '') {
        return null;
    }
    $rules = $pdo->query(
        'SELECT r.rule_type, r.pattern, r.scope_id
         FROM zabbix_scope_map_rules r
         INNER JOIN scan_scopes s ON s.id = r.scope_id
         WHERE r.enabled = 1 ORDER BY r.id'
    )->fetchAll(PDO::FETCH_ASSOC);
    if (! is_array($rules) || $rules === []) {
        return null;
    }
    $gt = st_zabbix_host_groups_and_tags($pdo, $hid);

    return st_zabbix_first_matching_scope_id($rules, $gt['groups'], $gt['tags']);
}

/**
 * Apply scope mapping after explicit confirmation. Each row must match current DB scope and server suggestion.
 *
 * @param array<int, array<string,mixed>> $rows
 * @return array{applied: int, skipped: int, errors: array<int, string>, changes: array<int, array<string,int|null>>}
 */
function st_zabbix_apply_scope_map(PDO $pdo, bool $confirm, array $rows): array
{
    if (! $confirm) {
        throw new InvalidArgumentException('confirm is required to apply scope mapping');
    }
    if (! st_zabbix_scan_scopes_table_exists($pdo) || ! st_zabbix_asset_workflow_columns_ready($pdo)) {
        throw new RuntimeException('scan_scopes or asset workflow columns unavailable');
    }
    $applied = 0;
    $skipped = 0;
    $errors = [];
    $changes = [];
    $chkScope = $pdo->prepare('SELECT 1 FROM scan_scopes WHERE id = ? LIMIT 1');
    $selAsset = $pdo->prepare('SELECT COALESCE(scope_id, 0) AS sid FROM assets WHERE id = ? LIMIT 1');
    $upd = $pdo->prepare('UPDATE assets SET scope_id = ? WHERE id = ?');
    foreach ($rows as $idx => $r) {
        if (! is_array($r)) {
            $skipped++;
            continue;
        }
        $aid = (int) ($r['asset_id'] ?? 0);
        $newScope = (int) ($r['new_scope_id'] ?? 0);
        if ($aid <= 0 || $newScope <= 0) {
            $skipped++;
            continue;
        }
        $chkScope->execute([$newScope]);
        if ((int) $chkScope->fetchColumn() !== 1) {
            $errors[] = 'asset ' . $aid . ': invalid new_scope_id';
            $skipped++;
            continue;
        }
        $selAsset->execute([$aid]);
        $curRow = $selAsset->fetch(PDO::FETCH_ASSOC);
        if (! is_array($curRow)) {
            $errors[] = 'asset ' . $aid . ': not found';
            $skipped++;
            continue;
        }
        $cur = st_zabbix_norm_scope_id($curRow['sid'] ?? null);
        $oldExpect = st_zabbix_norm_scope_id($r['old_scope_id'] ?? null);
        if ($cur !== $oldExpect) {
            $errors[] = 'asset ' . $aid . ': old_scope_id mismatch (refresh preview)';
            $skipped++;
            continue;
        }
        $suggested = st_zabbix_suggest_scope_for_asset($pdo, $aid);
        if ($suggested !== $newScope) {
            $errors[] = 'asset ' . $aid . ': new_scope_id does not match current rules';
            $skipped++;
            continue;
        }
        if ($cur === $newScope) {
            $skipped++;
            continue;
        }
        $upd->execute([$newScope, $aid]);
        $changes[] = ['asset_id' => $aid, 'old_scope_id' => $cur, 'new_scope_id' => $newScope];
        $applied++;
    }

    return ['applied' => $applied, 'skipped' => $skipped, 'errors' => $errors, 'changes' => $changes];
}

/**
 * Match review payload for admin UI (capped lists).
 *
 * @return array<string, mixed>
 */
function st_zabbix_match_review(PDO $pdo): array
{
    if (! st_zabbix_table_ready($pdo)) {
        return [
            'high_confidence' => [],
            'near_threshold' => [],
            'unmatched_zabbix_hosts' => [],
            'unmatched_assets' => [],
        ];
    }
    $lim = 200;
    $high = $pdo->query(
        "SELECT a.id AS asset_id, a.ip, a.hostname, l.zabbix_hostid, l.confidence, l.match_method, COALESCE(l.is_manual,0) AS is_manual
         FROM zabbix_asset_links l
         JOIN assets a ON a.id = l.asset_id
         WHERE l.confidence >= 0.9
         ORDER BY l.confidence DESC, a.ip
         LIMIT {$lim}"
    )->fetchAll(PDO::FETCH_ASSOC);
    $near = $pdo->query(
        "SELECT a.id AS asset_id, a.ip, a.hostname, l.zabbix_hostid, l.confidence, l.match_method, COALESCE(l.is_manual,0) AS is_manual
         FROM zabbix_asset_links l
         JOIN assets a ON a.id = l.asset_id
         WHERE l.confidence >= 0.75 AND l.confidence < 0.9
         ORDER BY l.confidence ASC, a.ip
         LIMIT {$lim}"
    )->fetchAll(PDO::FETCH_ASSOC);
    $unHosts = $pdo->query(
        "SELECT h.hostid, h.visible_name, h.tech_name, h.monitored, h.available
         FROM zabbix_hosts h
         LEFT JOIN zabbix_asset_links l ON l.zabbix_hostid = h.hostid
         WHERE l.asset_id IS NULL
         ORDER BY h.tech_name
         LIMIT {$lim}"
    )->fetchAll(PDO::FETCH_ASSOC);
    $unAssets = $pdo->query(
        "SELECT a.id AS asset_id, a.ip, a.hostname
         FROM assets a
         LEFT JOIN zabbix_asset_links l ON l.asset_id = a.id
         WHERE l.asset_id IS NULL
         ORDER BY a.ip
         LIMIT {$lim}"
    )->fetchAll(PDO::FETCH_ASSOC);

    return [
        'high_confidence' => is_array($high) ? $high : [],
        'near_threshold' => is_array($near) ? $near : [],
        'unmatched_zabbix_hosts' => is_array($unHosts) ? $unHosts : [],
        'unmatched_assets' => is_array($unAssets) ? $unAssets : [],
    ];
}

/**
 * Manual link / override (audited by caller).
 */
function st_zabbix_link_manual(PDO $pdo, int $assetId, string $zabbixHostid, string $matchMethod, float $confidence): void
{
    if (! st_zabbix_table_ready($pdo) || $assetId <= 0 || $zabbixHostid === '') {
        throw new InvalidArgumentException('invalid link parameters');
    }
    $h = $pdo->prepare('SELECT 1 FROM zabbix_hosts WHERE hostid = ? LIMIT 1');
    $h->execute([$zabbixHostid]);
    if ((int) $h->fetchColumn() !== 1) {
        throw new RuntimeException('Zabbix host not found in local cache (run sync)');
    }
    $a = $pdo->prepare('SELECT 1 FROM assets WHERE id = ? LIMIT 1');
    $a->execute([$assetId]);
    if ((int) $a->fetchColumn() !== 1) {
        throw new RuntimeException('asset not found');
    }
    $pdo->exec('BEGIN IMMEDIATE');
    try {
        $pdo->prepare('DELETE FROM zabbix_asset_links WHERE asset_id = ? OR zabbix_hostid = ?')->execute([$assetId, $zabbixHostid]);
        $ins = $pdo->prepare(
            'INSERT INTO zabbix_asset_links (asset_id, zabbix_hostid, match_method, confidence, last_matched_at, is_manual)
             VALUES (?, ?, ?, ?, datetime(\'now\'), 1)'
        );
        $mm = $matchMethod !== '' ? $matchMethod : 'manual';
        $ins->execute([$assetId, $zabbixHostid, $mm, max(0.0, min(1.0, $confidence))]);
        $pdo->exec('COMMIT');
    } catch (Throwable $e) {
        $pdo->exec('ROLLBACK');
        throw $e;
    }
    st_zabbix_refresh_asset_zabbix_denorm_all($pdo);
}

function st_zabbix_unlink_asset(PDO $pdo, int $assetId): void
{
    if (! st_zabbix_table_ready($pdo) || $assetId <= 0) {
        return;
    }
    $pdo->prepare('DELETE FROM zabbix_asset_links WHERE asset_id = ?')->execute([$assetId]);
    st_zabbix_refresh_asset_zabbix_denorm_all($pdo);
}
