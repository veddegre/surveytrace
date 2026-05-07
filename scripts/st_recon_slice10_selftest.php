<?php
/**
 * Slice 10 — credentialed trusted-data reconciliation (no network).
 *
 *   php scripts/st_recon_slice10_selftest.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_reconciliation.php';

function assert_true(bool $cond, string $msg): void
{
    if (! $cond) {
        fwrite(STDERR, 'FAIL: ' . $msg . "\n");
        exit(1);
    }
}

function mk_os_def(string $type, string $slug, string $label, array $extra = []): array
{
    return array_merge([
        'observation_type'   => $type,
        'raw_value'          => $label,
        'normalized_slug'    => $slug,
        'normalized_label'   => $label,
        'source_id'          => 1,
        'source_object_ref'  => '',
        'confidence_level'   => 'medium',
        'provenance_json'    => '{}',
        'observed_at'        => '',
    ], $extra);
}

// --- OS resolver ---
$rScan = st_recon_resolve_os_platform([
    mk_os_def('os_fingerprint_scan', 'ubuntu_22_x', 'Ubuntu 22.x'),
]);
assert_true(($rScan['skip'] ?? true) === false && ($rScan['confidence'] ?? '') === 'medium', 'scan-only OS');

$rZbOnly = st_recon_resolve_os_platform([
    mk_os_def(
        'os_inventory_zabbix',
        'ubuntu_22_x',
        'Ubuntu 22.x',
        ['source_object_ref' => '10084']
    ),
]);
assert_true(
    ($rZbOnly['skip'] ?? true) === false
    && ($rZbOnly['confidence'] ?? '') === 'medium'
    && str_contains((string) ($rZbOnly['explanation'] ?? ''), 'Zabbix host inventory only'),
    'Zabbix-only OS unchanged'
);

$rCredOnly = st_recon_resolve_os_platform([
    mk_os_def(
        'os_version_observed',
        'rhel_9_x',
        'RHEL 9.x',
        [
            'confidence_level'  => 'high',
            'observed_at'       => date('Y-m-d H:i:s'),
            'source_object_ref' => 'run:1:target:1:ssh.linux.os_release@1.0.0',
        ]
    ),
]);
assert_true(
    ($rCredOnly['skip'] ?? true) === false
    && ($rCredOnly['confidence'] ?? '') === 'high'
    && str_contains((string) ($rCredOnly['explanation'] ?? ''), 'credentialed check'),
    'credentialed-only OS when fresh'
);

$credFresh = mk_os_def(
    'os_version_observed',
    'ubuntu_22_x',
    'Ubuntu 22.x',
    [
        'confidence_level' => 'high',
        'observed_at'      => date('Y-m-d H:i:s'),
        'source_object_ref'=> 'run:1:target:1:ssh.linux.os_release@1.0.0',
    ]
);
$rAgree = st_recon_resolve_os_platform([
    $credFresh,
    mk_os_def('os_fingerprint_scan', 'ubuntu_22_x', 'Ubuntu 22.x'),
]);
assert_true(
    ($rAgree['confidence'] ?? '') === 'high'
    && str_contains((string) ($rAgree['explanation'] ?? ''), 'Authenticated OS release agrees with SurveyTrace scan fingerprint'),
    'cred + scan agree OS'
);

$rConflict = st_recon_resolve_os_platform([
    mk_os_def(
        'os_version_observed',
        'debian_12_x',
        'Debian 12.x',
        ['observed_at' => date('Y-m-d H:i:s'), 'confidence_level' => 'high']
    ),
    mk_os_def('os_fingerprint_scan', 'ubuntu_22_x', 'Ubuntu 22.x'),
]);
assert_true(
    ($rConflict['slug'] ?? '') === 'debian_12_x'
    && ($rConflict['confidence'] ?? '') === 'medium'
    && str_contains((string) ($rConflict['explanation'] ?? ''), 'differs'),
    'cred vs scan conflict prefers authenticated slug with visible wording'
);

$old = date('Y-m-d H:i:s', time() - 120 * 86400);
$rStale = st_recon_resolve_os_platform([
    mk_os_def(
        'os_version_observed',
        'debian_12_x',
        'Debian 12.x',
        ['observed_at' => $old, 'confidence_level' => 'high']
    ),
    mk_os_def('os_fingerprint_scan', 'ubuntu_22_x', 'Ubuntu 22.x'),
]);
assert_true(
    ($rStale['slug'] ?? '') === 'ubuntu_22_x'
    && str_contains((string) ($rStale['explanation'] ?? ''), 'Older authenticated'),
    'stale cred does not override fresher scan fingerprint'
);

$rStaleAgree = st_recon_resolve_os_platform([
    mk_os_def(
        'os_version_observed',
        'ubuntu_22_x',
        'Ubuntu 22.x',
        ['observed_at' => $old, 'confidence_level' => 'high']
    ),
    mk_os_def('os_fingerprint_scan', 'ubuntu_22_x', 'Ubuntu 22.x'),
]);
assert_true(
    ($rStaleAgree['slug'] ?? '') === 'ubuntu_22_x'
    && ($rStaleAgree['confidence'] ?? '') === 'medium'
    && str_contains((string) ($rStaleAgree['explanation'] ?? ''), 'agrees but is not used to raise confidence'),
    'stale cred + scan agreement: no misleading conflict wording'
);

$rEmptyObsAt = st_recon_resolve_os_platform([
    mk_os_def(
        'os_version_observed',
        'ubuntu_22_x',
        'Ubuntu 22.x',
        ['observed_at' => '', 'confidence_level' => 'high']
    ),
    mk_os_def('os_fingerprint_scan', 'ubuntu_22_x', 'Ubuntu 22.x'),
]);
assert_true(
    ($rEmptyObsAt['slug'] ?? '') === 'ubuntu_22_x'
    && str_contains((string) ($rEmptyObsAt['explanation'] ?? ''), 'agrees but is not used'),
    'missing observed_at on cred OS treated as non-dominating vs scan'
);

$rUnknownOnly = st_recon_resolve_os_platform([
    mk_os_def(
        'os_version_observed',
        'os_unknown',
        'Weird',
        ['observed_at' => date('Y-m-d H:i:s'), 'confidence_level' => 'high']
    ),
]);
assert_true(($rUnknownOnly['skip'] ?? false) === true, 'cred OS normalized to os_unknown does not drive resolver');

// --- Identity resolver (minimal SQLite for anchor query) ---
$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec(
    'CREATE TABLE asset_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        observation_type TEXT NOT NULL,
        normalized_value TEXT,
        raw_value TEXT,
        confidence_level TEXT,
        observed_at TEXT,
        source_id INTEGER NOT NULL DEFAULT 1,
        source_object_ref TEXT NOT NULL DEFAULT \'\',
        provenance_json TEXT NOT NULL DEFAULT \'{}\'
    )'
);

$credProv = static fn (): string => json_encode(['origin' => 'credentialed_check', 'field' => 'sysName'], JSON_UNESCAPED_SLASHES) ?: '{}';
$credProvFqdnHost = static fn (bool $derived): string => json_encode(
    array_merge(
        ['origin' => 'credentialed_check', 'field' => 'sysName', 'run_id' => 1, 'target_row_id' => 2],
        $derived ? ['derived_from' => 'fqdn'] : []
    ),
    JSON_UNESCAPED_SLASHES
) ?: '{}';

$scanProv = static fn (): string => json_encode(['origin' => 'identity_snapshot', 'field' => 'assets.hostname'], JSON_UNESCAPED_SLASHES) ?: '{}';

$row = static function (int $id, string $type, string $norm, string $raw, string $prov, int $sid): array {
    return [
        'id'                 => $id,
        'observation_type'   => $type,
        'normalized_value'   => $norm,
        'raw_value'          => $raw,
        'confidence_level'   => 'medium',
        'observed_at'        => '2026-05-01 12:00:00',
        'source_id'          => $sid,
        'source_object_ref'  => 'ref:' . $id,
        'provenance_json'    => $prov,
    ];
};

$aSnmp = $row(1, 'hostname_observed', 'snmp-host', 'snmp-host', $credProv(), 10);
$bScan = $row(2, 'hostname_observed', 'scan-host', 'scan-host', $scanProv(), 11);
$resDual = st_recon_resolve_canonical_hostname_from_rows($pdo, 1, [$aSnmp, $bScan]);
assert_true(
    ($resDual['short'] ?? '') === 'scan-host'
    && str_contains((string) ($resDual['explanation'] ?? ''), 'differ'),
    'SNMP sysName-only group loses to distinct scan hostname when both exist'
);

$snSame = $row(1, 'hostname_observed', 'shared', 'sharedSNMP', $credProv(), 10);
$scSame = $row(2, 'hostname_observed', 'shared', 'sharedScan', $scanProv(), 11);
$resAgree = st_recon_resolve_canonical_hostname_from_rows($pdo, 2, [$snSame, $scSame]);
assert_true(
    ($resAgree['short'] ?? '') === 'shared'
    && str_contains((string) ($resAgree['explanation'] ?? ''), 'SNMP sysName agrees'),
    'SNMP + scan agreement raises explanation visibility'
);

$onlySnmp = [$row(1, 'hostname_observed', 'alone', 'alone', $credProv(), 10)];
$resSnmp = st_recon_resolve_canonical_hostname_from_rows($pdo, 3, $onlySnmp);
assert_true(
    ($resSnmp['short'] ?? '') === 'alone'
    && ($resSnmp['confidence'] ?? '') === 'medium'
    && str_contains((string) ($resSnmp['explanation'] ?? ''), 'SNMP sysName supports'),
    'SNMP-only hostname still resolves with explicit explanation and confidence cap'
);

$fqd = $row(1, 'fqdn_observed', 'host.example.com', 'HOST.EXAMPLE.COM', $credProvFqdnHost(false), 10);
$hShort = $row(2, 'hostname_observed', 'host', 'HOST.EXAMPLE.COM', $credProvFqdnHost(true), 10);
$resFqSnmp = st_recon_resolve_canonical_hostname_from_rows($pdo, 4, [$fqd, $hShort]);
assert_true(
    ($resFqSnmp['short'] ?? '') === 'host'
    && ($resFqSnmp['confidence'] ?? '') === 'medium'
    && ! str_contains((string) ($resFqSnmp['explanation'] ?? ''), 'FQDN observation aligns'),
    'SNMP sysName FQDN parse: internal fqdn+hostname does not count as DNS corroboration'
);

$diOnly = [
    [
        'id'                 => 1,
        'observation_type'   => 'device_identity_observed',
        'normalized_value'   => 'sha256deadbeef01',
        'raw_value'          => '{"digest":"test"}',
        'confidence_level'   => 'medium',
        'observed_at'        => '2026-05-01 12:00:00',
        'source_id'          => 10,
        'source_object_ref'  => 'run:9:target:1:snmpv3.device_identity@1.0.0',
        'provenance_json'    => '{}',
    ],
];
$resDi = st_recon_resolve_canonical_hostname_from_rows($pdo, 5, $diOnly);
assert_true(
    ($resDi['skip'] ?? false) === true && (($resDi['reason'] ?? '') === 'no_valid_hostname_groups'),
    'device_identity_observed without hostname/FQDN does not participate in canonical_hostname grouping'
);

echo "OK st_recon_slice10_selftest\n";
