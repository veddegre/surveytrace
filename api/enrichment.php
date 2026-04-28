<?php
/**
 * SurveyTrace — /api/enrichment.php
 *
 * Manage enrichment sources (SNMP, controllers, DHCP/DNS/firewall logs, etc.)
 *
 * GET  /api/enrichment.php           — list all sources
 * POST /api/enrichment.php           — create or update a source
 * POST /api/enrichment.php?test=1    — test connection to a source
 * DELETE /api/enrichment.php?id=N   — delete a source
 */

require_once __DIR__ . '/db.php';
st_auth();
st_require_role(['admin']);

$db = st_db();

// Auto-create table if missing (schema migration)
$db->exec("
    CREATE TABLE IF NOT EXISTS enrichment_sources (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        source_type  TEXT NOT NULL,
        label        TEXT NOT NULL,
        enabled      INTEGER DEFAULT 0,
        priority     INTEGER DEFAULT 10,
        config_json  TEXT DEFAULT '{}',
        last_tested  DATETIME,
        last_test_ok INTEGER DEFAULT 0,
        last_test_msg TEXT,
        created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
    )
");

$method = $_SERVER['REQUEST_METHOD'];

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------
if ($method === 'DELETE') {
    $id = (int)($_GET['id'] ?? 0);
    if (!$id) st_json(['error' => 'id required'], 400);
    $db->prepare("DELETE FROM enrichment_sources WHERE id = ?")->execute([$id]);
    st_json(['ok' => true]);
}

// ---------------------------------------------------------------------------
// GET — list sources
// ---------------------------------------------------------------------------
if ($method === 'GET') {
    $rows = $db->query("SELECT * FROM enrichment_sources ORDER BY priority ASC, id ASC")->fetchAll();
    // Mask passwords in config before returning
    foreach ($rows as &$r) {
        $cfg = json_decode($r['config_json'] ?? '{}', true) ?: [];
        foreach (['password','api_key','auth_password','priv_password'] as $k) {
            if (isset($cfg[$k])) $cfg[$k] = '••••••••';
        }
        $r['config_json'] = json_encode($cfg);
        $r['config']      = $cfg;
    }
    unset($r);

    // Also return available source types from a static list
    $available_types = [
        ['type' => 'unifi',       'label' => 'UniFi / UDM',          'status' => 'ready'],
        ['type' => 'snmp',        'label' => 'SNMP (universal)',       'status' => 'ready'],
        ['type' => 'dhcp_leases', 'label' => 'DHCP Leases (generic)',  'status' => 'ready'],
        ['type' => 'dns_logs',    'label' => 'DNS Logs (generic)',     'status' => 'ready'],
        ['type' => 'firewall_logs','label' => 'Firewall Logs (generic)','status' => 'ready'],
        ['type' => 'ms_dns',      'label' => 'Microsoft DNS',          'status' => 'partial'],
        ['type' => 'cisco_dna',   'label' => 'Cisco DNA Center',       'status' => 'stub'],
        ['type' => 'meraki',      'label' => 'Cisco Meraki',           'status' => 'stub'],
        ['type' => 'juniper_mist','label' => 'Juniper Mist',           'status' => 'stub'],
        ['type' => 'infoblox',    'label' => 'Infoblox DDI',           'status' => 'stub'],
        ['type' => 'palo_alto',   'label' => 'Palo Alto Panorama',     'status' => 'stub'],
    ];

    st_json(['sources' => $rows, 'available_types' => $available_types]);
}

// ---------------------------------------------------------------------------
// POST — create/update or test
// ---------------------------------------------------------------------------
st_method('POST');
$body = st_input();

// Test connection
if (isset($_GET['test'])) {
    $id = (int)($body['id'] ?? 0);
    if (!$id) st_json(['error' => 'id required for test'], 400);

    $row = $db->prepare("SELECT * FROM enrichment_sources WHERE id = ?")->execute([$id])
        ? null : null;
    $stmt = $db->prepare("SELECT * FROM enrichment_sources WHERE id = ?");
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    if (!$row) st_json(['error' => 'Source not found'], 404);

    // Delegate test to Python daemon via a special scan_log entry
    // (The daemon tests the connection and writes the result back)
    // For now return a placeholder — full implementation via Python subprocess
    $config = json_decode($row['config_json'] ?? '{}', true) ?: [];
    $host   = trim($config['host'] ?? '');
    if ($row['source_type'] === 'dhcp_leases') {
        $paths = trim((string)($config['paths'] ?? ''));
        if ($paths === '') {
            st_json(['ok' => false, 'message' => 'No lease file paths configured'], 400);
        }
        $msg = "DHCP lease source configured. Validation runs in daemon at scan time.";
        $ok  = 1;
        $db->prepare("
            UPDATE enrichment_sources
            SET last_tested=CURRENT_TIMESTAMP, last_test_ok=?, last_test_msg=?
            WHERE id=?
        ")->execute([$ok, $msg, $id]);
        st_json(['ok' => true, 'message' => $msg]);
    }
    if ($row['source_type'] === 'dns_logs') {
        $paths = trim((string)($config['paths'] ?? ''));
        if ($paths === '') {
            st_json(['ok' => false, 'message' => 'No DNS log file paths configured'], 400);
        }
        $msg = "DNS log source configured. Validation runs in daemon at scan time.";
        $ok  = 1;
        $db->prepare("
            UPDATE enrichment_sources
            SET last_tested=CURRENT_TIMESTAMP, last_test_ok=?, last_test_msg=?
            WHERE id=?
        ")->execute([$ok, $msg, $id]);
        st_json(['ok' => true, 'message' => $msg]);
    }
    if ($row['source_type'] === 'firewall_logs') {
        $paths = trim((string)($config['paths'] ?? ''));
        if ($paths === '') {
            st_json(['ok' => false, 'message' => 'No firewall log file paths configured'], 400);
        }
        $msg = "Firewall log source configured. Validation runs in daemon at scan time.";
        $ok  = 1;
        $db->prepare("
            UPDATE enrichment_sources
            SET last_tested=CURRENT_TIMESTAMP, last_test_ok=?, last_test_msg=?
            WHERE id=?
        ")->execute([$ok, $msg, $id]);
        st_json(['ok' => true, 'message' => $msg]);
    }

    if (empty($host)) {
        st_json(['ok' => false, 'message' => 'No host configured for this source'], 400);
    }

    // Default ports per source type
    $default_ports = [
        'unifi'        => 443,
        'snmp'         => 161,
        'dhcp_leases'  => 0,
        'dns_logs'     => 0,
        'firewall_logs'=> 0,
        'ms_dns'       => 53,
        'cisco_dna'    => 443,
        'meraki'       => 443,
        'juniper_mist' => 443,
        'infoblox'     => 443,
        'palo_alto'    => 443,
    ];
    $port = (int)($config['port'] ?? 0);
    if ($port <= 0) {
        $port = $default_ports[$row['source_type']] ?? 443;
    }

    // SNMP uses UDP — TCP test not applicable, just report configured
    if ($row['source_type'] === 'snmp') {
        $msg = "SNMP configured for $host:$port (UDP — TCP test not applicable). Run a scan to verify.";
        $ok  = 1;
        $db->prepare("
            UPDATE enrichment_sources
            SET last_tested=CURRENT_TIMESTAMP, last_test_ok=?, last_test_msg=?
            WHERE id=?
        ")->execute([$ok, $msg, $id]);
        st_json(['ok' => true, 'message' => $msg]);
    }

    // Quick PHP-level TCP reachability check
    $fp = @fsockopen($host, $port, $errno, $errstr, 3);
    if ($fp) {
        fclose($fp);
        $msg = "TCP reachable at $host:$port — run a scan to test full authentication";
        $ok  = 1;
    } else {
        $msg = "Cannot reach $host:$port — $errstr";
        $ok  = 0;
    }

    $db->prepare("
        UPDATE enrichment_sources
        SET last_tested=CURRENT_TIMESTAMP, last_test_ok=?, last_test_msg=?
        WHERE id=?
    ")->execute([$ok, $msg, $id]);

    st_json(['ok' => (bool)$ok, 'message' => $msg]);
}

// Create or update
$id          = (int)($body['id'] ?? 0);
$source_type = trim($body['source_type'] ?? '');
$label       = substr(trim($body['label'] ?? ''), 0, 100);
$enabled     = (int)($body['enabled'] ?? 0);
$priority    = max(1, min(100, (int)($body['priority'] ?? 10)));

$allowed_types = ['unifi','snmp','dhcp_leases','dns_logs','firewall_logs','ms_dns','cisco_dna','meraki',
                  'juniper_mist','infoblox','palo_alto'];
if (!in_array($source_type, $allowed_types)) {
    st_json(['error' => "Unknown source type: $source_type"], 400);
}
if (!$label) $label = $source_type;

// Build config — merge with existing to preserve masked passwords
$new_config = (array)($body['config'] ?? []);

if ($id > 0) {
    // Fetch existing config to preserve masked fields
    $xstmt = $db->prepare("SELECT config_json FROM enrichment_sources WHERE id = ?");
    $xstmt->execute([$id]);
    $existing_cfg = json_decode($xstmt->fetchColumn() ?: '{}', true) ?: [];
    foreach (['password','api_key','auth_password','priv_password'] as $k) {
        if (($new_config[$k] ?? '') === '••••••••' && isset($existing_cfg[$k])) {
            $new_config[$k] = $existing_cfg[$k];   // restore real value
        }
    }
    $db->prepare("
        UPDATE enrichment_sources
        SET source_type=?, label=?, enabled=?, priority=?, config_json=?
        WHERE id=?
    ")->execute([$source_type, $label, $enabled, $priority,
                 json_encode($new_config), $id]);
} else {
    $db->prepare("
        INSERT INTO enrichment_sources (source_type, label, enabled, priority, config_json)
        VALUES (?, ?, ?, ?, ?)
    ")->execute([$source_type, $label, $enabled, $priority, json_encode($new_config)]);
    $id = (int)$db->lastInsertId();
}

$stmt2 = $db->prepare("SELECT * FROM enrichment_sources WHERE id = ?");
$stmt2->execute([$id]);
st_json(['ok' => true, 'source' => $stmt2->fetch()]);
