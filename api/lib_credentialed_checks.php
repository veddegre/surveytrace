<?php
/**
 * SurveyTrace — credentialed checks: built-in plugin registry (read-only helpers + seed).
 *
 * No execution, no credentials, no worker enqueue. See docs/CREDENTIALED_CHECKS_MVP_PLAN.md slice 2.
 */

declare(strict_types=1);

/**
 * True when credential_check_plugins exists (cred checks slice 1 schema applied).
 */
function st_cred_tables_ready(PDO $pdo): bool
{
    try {
        $n = $pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credential_check_plugins' LIMIT 1"
        )->fetchColumn();

        return $n !== false && $n !== null;
    } catch (Throwable) {
        return false;
    }
}

/**
 * @return array<int, array<string, mixed>>
 */
function st_cred_builtin_plugin_manifests(): array
{
    $osReleaseInputs = [
        'type'       => 'object',
        'properties' => [
            'asset_id' => ['type' => 'integer', 'description' => 'Target asset (resolved to management IP at execution time; slice 5+).'],
        ],
        'required'   => [],
    ];

    $osReleaseOutput = [
        'type'       => 'object',
        'properties' => [
            'id'               => ['type' => 'string'],
            'name'             => ['type' => 'string'],
            'version_id'       => ['type' => 'string'],
            'pretty_name'      => ['type' => 'string'],
            'version_codename' => ['type' => 'string'],
        ],
        'description' => 'Subset of /etc/os-release key=value pairs (normalized keys).',
    ];

    $pkgInputs = [
        'type'       => 'object',
        'properties' => [
            'asset_id' => ['type' => 'integer'],
        ],
        'required' => [],
    ];

    $pkgOutput = [
        'type'       => 'object',
        'properties' => [
            'package_manager' => ['type' => 'string', 'enum' => ['dpkg', 'rpm', 'unknown']],
            'packages'        => [
                'type'  => 'array',
                'items' => [
                    'type'       => 'object',
                    'properties' => [
                        'name'    => ['type' => 'string'],
                        'version' => ['type' => 'string'],
                        'arch'    => ['type' => 'string'],
                    ],
                ],
            ],
        ],
        'description' => 'Inventory list; executor may truncate with metrics.reason when output exceeds cap.',
    ];

    $snmpInputs = [
        'type'       => 'object',
        'properties' => [
            'asset_id' => ['type' => 'integer'],
        ],
        'required' => [],
    ];

    $snmpOutput = [
        'type'       => 'object',
        'properties' => [
            'sys_name'     => ['type' => 'string'],
            'sys_descr'    => ['type' => 'string'],
            'sys_object_id'=> ['type' => 'string'],
        ],
    ];

    return [
        [
            'plugin_key'              => 'ssh.linux.os_release',
            'version'                 => '1.0.0',
            'transport'               => 'ssh',
            'title'                   => 'Linux os-release (read-only)',
            'description'             => 'Reads /etc/os-release via a fixed allowlisted file read path only. No arbitrary shell or user-supplied command.',
            'state'                   => 'stable',
            'privilege'               => 'none',
            'timeout_ms_default'      => 15000,
            'timeout_ms_max'          => 60000,
            'output_size_bytes_max'   => 65536,
            'inputs_schema_json'      => $osReleaseInputs,
            'output_schema_json'      => $osReleaseOutput,
            'allowlisted_operations'  => [
                ['type' => 'read_file', 'path' => '/etc/os-release', 'max_bytes' => 65536],
            ],
            'remediation'             => null,
            'notes'                   => 'MVP: executor maps plugin_key to fixed implementation only.',
        ],
        [
            'plugin_key'              => 'ssh.linux.package_inventory',
            'version'                 => '1.0.0',
            'transport'               => 'ssh',
            'title'                   => 'Linux package inventory (dpkg/rpm)',
            'description'             => 'Package list via fixed dpkg-query or rpm -qa style allowlisted commands (detection at runtime). Large output is capped; result may be partial with truncation metadata.',
            'state'                   => 'experimental',
            'privilege'               => 'none',
            'timeout_ms_default'      => 120000,
            'timeout_ms_max'          => 300000,
            'output_size_bytes_max'   => 5242880,
            'inputs_schema_json'      => $pkgInputs,
            'output_schema_json'      => $pkgOutput,
            'allowlisted_operations'  => [
                [
                    'type'        => 'exec_template',
                    'id'          => 'dpkg_query_w',
                    'argv'        => ['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n'],
                    'max_stdout'  => 5242880,
                ],
                [
                    'type'        => 'exec_template',
                    'id'          => 'rpm_qa',
                    'argv'        => ['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'],
                    'max_stdout'  => 5242880,
                ],
            ],
            'remediation'             => [
                'doc' => 'If inventory is truncated, narrow scope or raise cap in a future job policy slice.',
            ],
            'large_output_behavior'   => 'truncate_with_partial_status',
        ],
        [
            'plugin_key'              => 'snmpv3.device_identity',
            'version'                 => '1.0.0',
            'transport'               => 'snmpv3',
            'title'                   => 'SNMPv3 device identity (read-only GET)',
            'description'             => 'sysName, sysDescr, sysObjectID via OID allowlist only. SNMP SET not permitted.',
            'state'                   => 'experimental',
            'privilege'               => 'none',
            'timeout_ms_default'      => 10000,
            'timeout_ms_max'          => 60000,
            'output_size_bytes_max'   => 131072,
            'inputs_schema_json'      => $snmpInputs,
            'output_schema_json'      => $snmpOutput,
            'allowlisted_operations'  => [
                ['type' => 'snmp_get', 'oids' => ['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.2.0', '1.3.6.1.2.1.1.5.0'], 'max_varbinds' => 16],
            ],
            'remediation'             => null,
        ],
    ];
}

/**
 * @param array<string, mixed> $manifest
 */
function st_cred_manifest_json_encode(array $manifest): ?string
{
    try {
        $s = json_encode($manifest, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($s === false) {
            return null;
        }

        return $s;
    } catch (Throwable) {
        return null;
    }
}

/**
 * Idempotent upsert for each built-in (plugin_key + version). Updates manifest_json, state, transport, updated_at.
 * Does not DELETE unknown plugin rows.
 */
function st_cred_seed_builtin_plugins(PDO $pdo): void
{
    if (! st_cred_tables_ready($pdo)) {
        return;
    }

    $sql = 'INSERT INTO credential_check_plugins (plugin_key, version, transport, manifest_json, state, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime(\'now\'), datetime(\'now\'))
            ON CONFLICT(plugin_key, version) DO UPDATE SET
                transport = excluded.transport,
                manifest_json = excluded.manifest_json,
                state = excluded.state,
                updated_at = datetime(\'now\')';

    $ins = $pdo->prepare($sql);

    foreach (st_cred_builtin_plugin_manifests() as $def) {
        $pluginKey = (string) ($def['plugin_key'] ?? '');
        $version = (string) ($def['version'] ?? '');
        $transport = (string) ($def['transport'] ?? '');
        $state = (string) ($def['state'] ?? 'stable');
        if ($pluginKey === '' || $version === '' || $transport === '') {
            continue;
        }
        $manifest = $def;
        $mj = st_cred_manifest_json_encode($manifest);
        if ($mj === null) {
            continue;
        }
        try {
            $ins->execute([$pluginKey, $version, $transport, $mj, $state]);
        } catch (Throwable) {
            // best-effort seed; never break app bootstrap
        }
    }
}

/**
 * Decode manifest_json into array fields for API consumers.
 *
 * @param array<string, mixed> $row
 *
 * @return array<string, mixed>
 */
function st_cred_decode_plugin_row(array $row): array
{
    $mj = $row['manifest_json'] ?? null;
    $decoded = [];
    if (is_string($mj) && $mj !== '') {
        try {
            $tmp = json_decode($mj, true, 512, JSON_THROW_ON_ERROR);
            $decoded = is_array($tmp) ? $tmp : [];
        } catch (Throwable) {
            $decoded = [];
        }
    }
    unset($row['manifest_json']);

    return array_merge($row, $decoded);
}

/**
 * @param array<string, mixed> $filters transport?, state?, include_disabled? (bool)
 *
 * @return list<array<string, mixed>>
 */
function st_cred_list_plugins(PDO $pdo, array $filters = []): array
{
    if (! st_cred_tables_ready($pdo)) {
        return [];
    }

    $where = [];
    $params = [];
    if (isset($filters['transport']) && is_string($filters['transport']) && $filters['transport'] !== '') {
        $where[] = 'transport = ?';
        $params[] = $filters['transport'];
    }
    if (isset($filters['state']) && is_string($filters['state']) && $filters['state'] !== '') {
        $where[] = 'state = ?';
        $params[] = $filters['state'];
    } elseif (empty($filters['include_disabled'])) {
        $where[] = "lower(state) != 'disabled'";
    }

    $sql = 'SELECT id, plugin_key, version, transport, manifest_json, state, created_at, updated_at
            FROM credential_check_plugins';
    if ($where !== []) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }
    $sql .= ' ORDER BY plugin_key ASC, version ASC';

    $st = $pdo->prepare($sql);
    $st->execute($params);
    $out = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
        if (! is_array($r)) {
            continue;
        }
        $out[] = st_cred_decode_plugin_row($r);
    }

    return $out;
}

/**
 * Latest row for plugin_key when version is null (highest id); otherwise exact version match.
 *
 * @return array<string, mixed>|null
 */
function st_cred_get_plugin(PDO $pdo, string $pluginKey, ?string $version = null): ?array
{
    if (! st_cred_tables_ready($pdo) || $pluginKey === '') {
        return null;
    }
    if ($version !== null && $version !== '') {
        $st = $pdo->prepare(
            'SELECT id, plugin_key, version, transport, manifest_json, state, created_at, updated_at
             FROM credential_check_plugins WHERE plugin_key = ? AND version = ? LIMIT 1'
        );
        $st->execute([$pluginKey, $version]);
    } else {
        $st = $pdo->prepare(
            'SELECT id, plugin_key, version, transport, manifest_json, state, created_at, updated_at
             FROM credential_check_plugins WHERE plugin_key = ? ORDER BY id DESC LIMIT 1'
        );
        $st->execute([$pluginKey]);
    }
    $r = $st->fetch(PDO::FETCH_ASSOC);
    if (! is_array($r)) {
        return null;
    }

    return st_cred_decode_plugin_row($r);
}
