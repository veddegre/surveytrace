<?php
/**
 * SurveyTrace — GET /api/scan_history.php
 *
 * Query params:
 *   - id: optional scan job id for full detail
 *   - limit: list size when id is omitted (default 50, max 200)
 *   - q: optional filter on label, target_cidr, or job id (substring match, max 120 chars)
 */

require_once __DIR__ . '/db.php';
st_auth();
st_require_role(['viewer', 'scan_editor', 'admin']);
st_method('GET');

$db = st_db();
$id = st_int('id', 0, 0);
$compareToId = st_int('compare_to', 0, 0);
$compareScope = st_str('compare_scope', 'any', ['any', 'target', 'profile', 'both']);
$view = st_str('view', 'active', ['active', 'trash', 'all']);
$limit = st_int('limit', 50, 1, 200);

// Ensure history columns exist for older DBs
$scanJobCols = array_column($db->query("PRAGMA table_info(scan_jobs)")->fetchAll(), 'name');
$scanJobMigrations = [
    'scan_mode'   => "TEXT DEFAULT 'auto'",
    'profile'     => "TEXT DEFAULT 'standard_inventory'",
    'priority'    => "INTEGER DEFAULT 10",
    'retry_count' => "INTEGER DEFAULT 0",
    'summary_json'=> "TEXT",
    'enrichment_source_ids' => "TEXT",
    'deleted_at'  => "DATETIME",
];
foreach ($scanJobMigrations as $col => $defn) {
    if (!in_array($col, $scanJobCols, true)) {
        $db->exec("ALTER TABLE scan_jobs ADD COLUMN $col $defn");
    }
}

if ($id > 0) {
    $stmt = $db->prepare("
        SELECT id, status, target_cidr, label, exclusions, phases, rate_pps, inter_delay,
               created_at, started_at, finished_at, hosts_found, hosts_scanned,
               error_msg, COALESCE(profile, 'standard_inventory') AS profile,
               COALESCE(scan_mode, 'auto') AS scan_mode,
               COALESCE(priority, 10) AS priority,
               COALESCE(retry_count, 0) AS retry_count,
               summary_json, deleted_at,
               CAST((julianday(COALESCE(finished_at,'now')) - julianday(COALESCE(started_at, created_at))) * 86400 AS INTEGER) AS duration_secs
        FROM scan_jobs
        WHERE id = ?
        LIMIT 1
    ");
    $stmt->execute([$id]);
    $job = $stmt->fetch();
    if (!$job) {
        st_json(['error' => "Job #$id not found"], 404);
    }

    $job['phases'] = json_decode((string)($job['phases'] ?? '[]'), true) ?: [];
    $job['summary'] = json_decode((string)($job['summary_json'] ?? ''), true) ?: null;
    unset($job['summary_json']);

    $snapStmt = $db->prepare("
        SELECT
            COALESCE(asset_id, 0) AS id,
            ip, hostname, category, vendor, top_cve, top_cvss, open_ports, device_id
        FROM scan_asset_snapshots
        WHERE job_id = ?
        ORDER BY ip ASC, id ASC
        LIMIT 300
    ");
    $snapStmt->execute([$id]);
    $assets = $snapStmt->fetchAll();

    // Fallback for older runs created before scan_asset_snapshots existed.
    if (!$assets) {
        $assetsStmt = $db->prepare("
            SELECT id, ip, hostname, category, vendor, top_cve, top_cvss, open_ports, device_id
            FROM assets
            WHERE last_scan_id = ?
            ORDER BY ip ASC
            LIMIT 200
        ");
        $assetsStmt->execute([$id]);
        $assets = $assetsStmt->fetchAll();
    }

    // Second fallback: reconstruct run evidence from port_history snapshots
    // for this scan id, joined to current asset metadata when available.
    if (!$assets) {
        $phStmt = $db->prepare("
            SELECT
                COALESCE(a.id, ph.asset_id, 0) AS id,
                COALESCE(a.ip, '') AS ip,
                COALESCE(a.hostname, '') AS hostname,
                COALESCE(a.category, 'unk') AS category,
                COALESCE(a.vendor, '') AS vendor,
                COALESCE(a.top_cve, '') AS top_cve,
                a.top_cvss AS top_cvss,
                ph.ports AS open_ports,
                COALESCE(a.device_id, 0) AS device_id
            FROM port_history ph
            LEFT JOIN assets a ON a.id = ph.asset_id
            WHERE ph.scan_id = ?
            ORDER BY ip ASC, id ASC
            LIMIT 300
        ");
        $phStmt->execute([$id]);
        $assets = $phStmt->fetchAll();
    }

    $assets = array_map(function($a) {
        $a['open_ports'] = json_decode((string)($a['open_ports'] ?? '[]'), true) ?: [];
        return $a;
    }, $assets);

    $logStmt = $db->prepare("
        SELECT id, ts, level, ip, message
        FROM scan_log
        WHERE job_id = ?
        ORDER BY id DESC
        LIMIT 80
    ");
    $logStmt->execute([$id]);
    $logTail = array_reverse($logStmt->fetchAll());

    $compare = null;
    $compareOptions = [];
    $optStmt = $db->prepare("
        SELECT id, label, target_cidr, status, finished_at
             , COALESCE(profile, 'standard_inventory') AS profile
             , COALESCE(scan_mode, 'auto') AS scan_mode
        FROM scan_jobs
        WHERE id < ?
          AND deleted_at IS NULL
          AND status IN ('done','aborted','failed')
        ORDER BY id DESC
        LIMIT 40
    ");
    $optStmt->execute([$id]);
    $compareOptions = array_map(function($r) {
        return [
            'id' => (int)$r['id'],
            'label' => (string)($r['label'] ?? ''),
            'target_cidr' => (string)($r['target_cidr'] ?? ''),
            'status' => (string)($r['status'] ?? ''),
            'finished_at' => $r['finished_at'] ?? null,
            'profile' => (string)($r['profile'] ?? ''),
            'scan_mode' => (string)($r['scan_mode'] ?? ''),
        ];
    }, $optStmt->fetchAll());

    $cmpJob = null;
    if ($compareToId > 0) {
        $cmpStmt = $db->prepare("
            SELECT id, label, target_cidr, status, finished_at
            FROM scan_jobs
            WHERE id = ?
              AND deleted_at IS NULL
            LIMIT 1
        ");
        $cmpStmt->execute([$compareToId]);
        $cmpJob = $cmpStmt->fetch();
    } else {
        $whereExtra = '';
        $paramsCmp = [$id];
        if ($compareScope === 'target' || $compareScope === 'both') {
            $whereExtra .= " AND COALESCE(target_cidr,'') = COALESCE(?, '')";
            $paramsCmp[] = (string)($job['target_cidr'] ?? '');
        }
        if ($compareScope === 'profile' || $compareScope === 'both') {
            $whereExtra .= " AND COALESCE(profile,'standard_inventory') = COALESCE(?, 'standard_inventory')";
            $whereExtra .= " AND COALESCE(scan_mode,'auto') = COALESCE(?, 'auto')";
            $paramsCmp[] = (string)($job['profile'] ?? 'standard_inventory');
            $paramsCmp[] = (string)($job['scan_mode'] ?? 'auto');
        }
        $cmpStmt = $db->prepare("
            SELECT id, label, target_cidr, status, finished_at
            FROM scan_jobs
            WHERE id < ?
              AND deleted_at IS NULL
              AND status IN ('done','aborted','failed')
              $whereExtra
            ORDER BY id DESC
            LIMIT 1
        ");
        $cmpStmt->execute($paramsCmp);
        $cmpJob = $cmpStmt->fetch();
    }

    if ($cmpJob) {
        $loadAssetsForJob = function(int $jid) use ($db): array {
            $s = $db->prepare("
                SELECT ip, open_ports
                FROM scan_asset_snapshots
                WHERE job_id = ?
                ORDER BY ip ASC
            ");
            $s->execute([$jid]);
            $rows = $s->fetchAll();
            if (!$rows) {
                $s = $db->prepare("
                    SELECT ip, ports AS open_ports
                    FROM port_history
                    WHERE scan_id = ?
                    ORDER BY id ASC
                ");
                $s->execute([$jid]);
                $rows = $s->fetchAll();
            }
            $ips = [];
            $ipPorts = [];
            foreach ($rows as $r) {
                $ip = trim((string)($r['ip'] ?? ''));
                if ($ip === '') continue;
                $ips[$ip] = 1;
                $ports = json_decode((string)($r['open_ports'] ?? '[]'), true);
                if (!is_array($ports)) $ports = [];
                foreach ($ports as $p) {
                    $pi = (int)$p;
                    if ($pi <= 0 || $pi > 65535) continue;
                    $ipPorts[$ip . ':' . $pi] = 1;
                }
            }
            return [array_keys($ips), array_keys($ipPorts)];
        };
        $loadOpenCvesForJob = function(int $jid) use ($db): array {
            $s = $db->prepare("
                SELECT DISTINCT cve_id
                FROM scan_finding_snapshots
                WHERE job_id = ? AND COALESCE(resolved, 0) = 0
            ");
            $s->execute([$jid]);
            return array_values(array_filter(array_map('strval', $s->fetchAll(PDO::FETCH_COLUMN))));
        };

        [$curIps, $curIpPorts] = $loadAssetsForJob((int)$id);
        [$prevIps, $prevIpPorts] = $loadAssetsForJob((int)$cmpJob['id']);
        $curCves = $loadOpenCvesForJob((int)$id);
        $prevCves = $loadOpenCvesForJob((int)$cmpJob['id']);
        $addedHostPorts = array_values(array_diff($curIpPorts, $prevIpPorts));
        $removedHostPorts = array_values(array_diff($prevIpPorts, $curIpPorts));
        $extractPorts = function(array $pairs): array {
            $set = [];
            foreach ($pairs as $pair) {
                $parts = explode(':', (string)$pair);
                if (count($parts) < 2) continue;
                $p = (int)end($parts);
                if ($p > 0 && $p <= 65535) $set[$p] = 1;
            }
            $ports = array_map('intval', array_keys($set));
            sort($ports, SORT_NUMERIC);
            return $ports;
        };
        $addedPorts = $extractPorts($addedHostPorts);
        $removedPorts = $extractPorts($removedHostPorts);

        $compare = [
            'compared_job' => [
                'id' => (int)$cmpJob['id'],
                'label' => $cmpJob['label'] ?? '',
                'target_cidr' => $cmpJob['target_cidr'] ?? '',
                'status' => $cmpJob['status'] ?? '',
                'finished_at' => $cmpJob['finished_at'] ?? null,
            ],
            'hosts' => [
                'current' => count($curIps),
                'previous' => count($prevIps),
                'added' => array_slice(array_values(array_diff($curIps, $prevIps)), 0, 25),
                'removed' => array_slice(array_values(array_diff($prevIps, $curIps)), 0, 25),
            ],
            'ports' => [
                'added' => count($addedHostPorts),
                'removed' => count($removedHostPorts),
                'added_ports' => array_slice($addedPorts, 0, 30),
                'removed_ports' => array_slice($removedPorts, 0, 30),
            ],
            'cves' => [
                'open_current' => count($curCves),
                'open_previous' => count($prevCves),
                'new_open' => array_slice(array_values(array_diff($curCves, $prevCves)), 0, 25),
                'resolved' => array_slice(array_values(array_diff($prevCves, $curCves)), 0, 25),
            ],
        ];
    }

    st_json([
        'ok' => true,
        'job' => $job,
        'assets' => $assets,
        'log_tail' => $logTail,
        'compare' => $compare,
        'compare_options' => $compareOptions,
        'compare_scope' => $compareScope,
    ]);
}

$qRaw = substr(st_str('q', ''), 0, 120);
$likePat = null;
if ($qRaw !== '') {
    $likePat = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $qRaw) . '%';
}

$listWhere = 'WHERE deleted_at IS NULL';
if ($view === 'trash') {
    $listWhere = 'WHERE deleted_at IS NOT NULL';
} elseif ($view === 'all') {
    $listWhere = 'WHERE 1=1';
}

if ($likePat !== null) {
    $rows = $db->prepare("
        SELECT id, status, target_cidr, label, hosts_found, hosts_scanned, deleted_at,
               created_at, started_at, finished_at, error_msg,
               COALESCE(profile, 'standard_inventory') AS profile,
               COALESCE(scan_mode, 'auto') AS scan_mode,
               COALESCE(priority, 10) AS priority,
               COALESCE(retry_count, 0) AS retry_count,
               summary_json,
               CAST((julianday(COALESCE(finished_at,'now')) - julianday(COALESCE(started_at, created_at))) * 86400 AS INTEGER) AS duration_secs
        FROM scan_jobs
        $listWhere
          AND (COALESCE(label, '') LIKE :qp1 ESCAPE '\\'
            OR COALESCE(target_cidr, '') LIKE :qp2 ESCAPE '\\'
            OR CAST(id AS TEXT) LIKE :qp3 ESCAPE '\\')
        ORDER BY id DESC
        LIMIT :lim
    ");
    $rows->bindValue(':qp1', $likePat);
    $rows->bindValue(':qp2', $likePat);
    $rows->bindValue(':qp3', $likePat);
    $rows->bindValue(':lim', $limit, PDO::PARAM_INT);
    $rows->execute();
} else {
    $rows = $db->prepare("
        SELECT id, status, target_cidr, label, hosts_found, hosts_scanned, deleted_at,
               created_at, started_at, finished_at, error_msg,
               COALESCE(profile, 'standard_inventory') AS profile,
               COALESCE(scan_mode, 'auto') AS scan_mode,
               COALESCE(priority, 10) AS priority,
               COALESCE(retry_count, 0) AS retry_count,
               summary_json,
               CAST((julianday(COALESCE(finished_at,'now')) - julianday(COALESCE(started_at, created_at))) * 86400 AS INTEGER) AS duration_secs
        FROM scan_jobs
        $listWhere
        ORDER BY id DESC
        LIMIT ?
    ");
    $rows->bindValue(1, $limit, PDO::PARAM_INT);
    $rows->execute();
}

$history = array_map(function($r) {
    $r['summary'] = json_decode((string)($r['summary_json'] ?? ''), true) ?: null;
    unset($r['summary_json']);
    $r['priority'] = (int)($r['priority'] ?? 10);
    $r['retry_count'] = (int)($r['retry_count'] ?? 0);
    return $r;
}, $rows->fetchAll());

st_json([
    'ok' => true,
    'history' => $history,
    'view' => $view,
]);
