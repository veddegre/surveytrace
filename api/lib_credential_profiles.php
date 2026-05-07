<?php
/**
 * SurveyTrace — credential profile metadata + secret envelope helpers (slice 4+).
 *
 * @see docs/CREDENTIALED_CHECKS_MVP_PLAN.md
 */

declare(strict_types=1);

require_once __DIR__ . '/lib_secrets.php';

/** Transports allowed for credential_profiles (app-level). */
const ST_CRED_PROFILE_TRANSPORTS = ['ssh', 'snmpv3', 'winrm'];

/** Keys that must never appear in principal_json (secrets belong in secret_ciphertext via set_secret). */
const ST_CRED_PROFILE_FORBIDDEN_PRINCIPAL_KEYS = [
    'password', 'secret', 'private_key', 'privatekey', 'priv_key',
    'auth_password', 'authpassword', 'priv_password', 'privpassword',
    'priv_passphrase', 'community', 'passphrase',
];

/**
 * Internal row for transport test (includes secret_ciphertext — never expose in API).
 *
 * @return array<string, mixed>|null
 */
function st_cred_profile_internal_by_id(PDO $pdo, int $id): ?array
{
    if ($id < 1 || ! st_cred_profile_tables_ready($pdo)) {
        return null;
    }
    try {
        $st = $pdo->prepare(
            'SELECT id, transport, enabled, principal_json, secret_ciphertext
             FROM credential_profiles WHERE id = ? AND deleted_at IS NULL LIMIT 1'
        );
        $st->execute([$id]);
        $r = $st->fetch(PDO::FETCH_ASSOC);

        return is_array($r) ? $r : null;
    } catch (Throwable) {
        return null;
    }
}

function st_cred_profile_tables_ready(PDO $pdo): bool
{
    try {
        $n = $pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credential_profiles' LIMIT 1"
        )->fetchColumn();

        return $n !== false && $n !== null;
    } catch (Throwable) {
        return false;
    }
}

function st_cred_profile_job_ref_count(PDO $pdo, int $profileId): int
{
    if ($profileId < 1) {
        return 0;
    }
    try {
        $chk = $pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credential_check_jobs' LIMIT 1"
        )->fetchColumn();
        if ($chk === false || $chk === null) {
            return 0;
        }
        $st = $pdo->prepare('SELECT COUNT(*) FROM credential_check_jobs WHERE credential_profile_id = ?');
        $st->execute([$profileId]);

        return (int) $st->fetchColumn();
    } catch (Throwable) {
        return 0;
    }
}

/**
 * @param array<string, mixed>|null $obj
 *
 * @return array{0:bool,1:?string} [ok, error]
 */
function st_cred_profile_principal_allowed(?array $obj): array
{
    if ($obj === null) {
        return [true, null];
    }
    foreach (array_keys($obj) as $k) {
        $lk = strtolower((string) $k);
        foreach (ST_CRED_PROFILE_FORBIDDEN_PRINCIPAL_KEYS as $bad) {
            if ($lk === strtolower($bad)) {
                return [false, 'principal_json must not contain secret or password fields'];
            }
        }
        if (str_ends_with($lk, '_password') || str_starts_with($lk, 'password_')) {
            return [false, 'principal_json must not contain password fields'];
        }
    }

    return [true, null];
}

/**
 * @return array{0:?string,1:?string} [encoded json or null, error message]
 */
function st_cred_profile_encode_json_field(mixed $raw, string $label): array
{
    if ($raw === null || $raw === '') {
        return [null, null];
    }
    if (is_array($raw)) {
        if ($label === 'principal_json') {
            [$okP, $errP] = st_cred_profile_principal_allowed($raw);
            if (! $okP) {
                return [null, $errP ?? $label . ' rejected'];
            }
        }
        try {
            $s = json_encode($raw, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($s === false) {
                return [null, $label . ' is not valid JSON'];
            }

            return [$s, null];
        } catch (Throwable) {
            return [null, $label . ' is not valid JSON'];
        }
    }
    if (is_string($raw)) {
        $t = trim($raw);
        if ($t === '') {
            return [null, null];
        }
        try {
            $tmp = json_decode($t, true, 64, JSON_THROW_ON_ERROR);
            if (! is_array($tmp)) {
                return [null, $label . ' must be a JSON object'];
            }
            [$ok, $err] = st_cred_profile_principal_allowed($tmp);
            if (! $ok) {
                return [null, $err ?? $label . ' rejected'];
            }
            $s = json_encode($tmp, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($s === false) {
                return [null, $label . ' encode failed'];
            }

            return [$s, null];
        } catch (Throwable) {
            return [null, $label . ' must be valid JSON object'];
        }
    }

    return [null, $label . ' must be object or JSON string'];
}

/**
 * @return array<string, mixed>
 */
function st_cred_profile_decode_json(?string $json): array
{
    if ($json === null || trim($json) === '') {
        return [];
    }
    try {
        $v = json_decode($json, true, 64, JSON_THROW_ON_ERROR);

        return is_array($v) ? $v : [];
    } catch (Throwable) {
        return [];
    }
}

/**
 * Safe public row — never includes secret_ciphertext.
 *
 * @param array<string, mixed> $row
 *
 * @return array<string, mixed>
 */
function st_cred_profile_public_row(array $row): array
{
    unset($row['secret_ciphertext']);
    $cipher = '';
    $hasCipher = false;
    if (isset($row['_secret_len'])) {
        $hasCipher = (int) $row['_secret_len'] > 0;
        unset($row['_secret_len']);
    }
    $row['has_secret'] = $hasCipher;
    $row['secret_status'] = $hasCipher ? 'stored' : 'none';
    $pj = st_cred_profile_decode_json(isset($row['principal_json']) ? (string) $row['principal_json'] : null);
    $sj = st_cred_profile_decode_json(isset($row['scope_json']) ? (string) $row['scope_json'] : null);
    $row['principal_summary'] = st_cred_profile_summarize_principal($pj, (string) ($row['transport'] ?? ''));
    $row['scope_summary'] = st_cred_profile_summarize_scope($sj);
    if (isset($row['principal_json'])) {
        $row['principal_json'] = $pj;
    }
    if (isset($row['scope_json'])) {
        $row['scope_json'] = $sj;
    }
    foreach (['enabled'] as $k) {
        if (isset($row[$k])) {
            $row[$k] = (int) $row[$k] !== 0;
        }
    }
    if (isset($row['last_test_duration_ms']) && $row['last_test_duration_ms'] !== null && $row['last_test_duration_ms'] !== '') {
        $row['last_test_duration_ms'] = (int) $row['last_test_duration_ms'];
    }
    if ($hasCipher) {
        $rawEnc = '';
        if (isset($row['_secret_envelope_raw'])) {
            $rawEnc = (string) $row['_secret_envelope_raw'];
            unset($row['_secret_envelope_raw']);
        }
        $row['secret_envelope'] = st_secret_redact_summary($rawEnc !== '' ? $rawEnc : null);
    }

    return $row;
}

function st_cred_profile_summarize_principal(array $pj, string $transport): string
{
    if ($pj === []) {
        return '—';
    }
    $u = trim((string) ($pj['username'] ?? ''));
    if ($u !== '' && in_array($transport, ['ssh', 'winrm'], true)) {
        return 'user: ' . $u;
    }
    $sn = trim((string) ($pj['securityName'] ?? $pj['security_name'] ?? ''));
    if ($sn !== '') {
        return 'SNMP user: ' . $sn;
    }

    return 'keys: ' . implode(', ', array_slice(array_keys($pj), 0, 6));
}

/**
 * Normalize transport-specific secret material (allowed keys only).
 *
 * @param array<string, mixed> $material
 *
 * @return array{0:array<string, string>,1:?string}
 */
function st_cred_profile_normalize_secret_material(string $transport, array $material): array
{
    $t = strtolower($transport);
    $clip = static function (string $s, int $max): string {
        if (strlen($s) <= $max) {
            return $s;
        }

        return substr($s, 0, $max);
    };
    $rejectUnknown = static function (array $material, array $allowed): ?string {
        foreach (array_keys($material) as $k) {
            if (! in_array((string) $k, $allowed, true)) {
                return 'Unknown or disallowed secret field: ' . (string) $k;
            }
        }

        return null;
    };

    if ($t === 'ssh') {
        $pw = isset($material['password']) ? trim((string) $material['password']) : '';
        $pk = isset($material['private_key']) ? trim((string) $material['private_key']) : '';
        $pp = isset($material['passphrase']) ? trim((string) $material['passphrase']) : '';
        if ($errU = $rejectUnknown($material, ['password', 'private_key', 'passphrase'])) {
            return [[], $errU];
        }
        if ($pw !== '' && $pk !== '') {
            return [[], 'Use either password or private_key for SSH, not both'];
        }
        if ($pw === '' && $pk === '') {
            return [[], 'SSH secret requires password or private_key'];
        }
        if ($pw !== '' && $pp !== '') {
            return [[], 'passphrase is only valid with private_key (not with password auth)'];
        }
        $out = [];
        if ($pw !== '') {
            $out['password'] = $clip($pw, 4096);
        } else {
            $out['private_key'] = $clip($pk, 65536);
            if ($pp !== '') {
                $out['passphrase'] = $clip($pp, 1024);
            }
        }

        return [$out, null];
    }
    if ($t === 'snmpv3') {
        if ($errU = $rejectUnknown($material, ['auth_password', 'priv_password'])) {
            return [[], $errU];
        }
        $a = isset($material['auth_password']) ? trim((string) $material['auth_password']) : '';
        $p = isset($material['priv_password']) ? trim((string) $material['priv_password']) : '';
        if ($a === '' && $p === '') {
            return [[], 'SNMPv3 secret requires auth_password and/or priv_password'];
        }
        $out = [];
        if ($a !== '') {
            $out['auth_password'] = $clip($a, 4096);
        }
        if ($p !== '') {
            $out['priv_password'] = $clip($p, 4096);
        }

        return [$out, null];
    }
    if ($t === 'winrm') {
        if ($errU = $rejectUnknown($material, ['password'])) {
            return [[], $errU];
        }
        $pw = isset($material['password']) ? trim((string) $material['password']) : '';
        if ($pw === '') {
            return [[], 'WinRM secret requires password'];
        }

        return [['password' => $clip($pw, 4096)], null];
    }

    return [[], 'Unknown transport'];
}

function st_cred_profile_summarize_scope(array $sj): string
{
    if ($sj === []) {
        return '—';
    }
    $parts = [];
    if (isset($sj['scope_ids']) && is_array($sj['scope_ids'])) {
        $parts[] = 'scopes: ' . count($sj['scope_ids']);
    }
    if (isset($sj['asset_ids']) && is_array($sj['asset_ids'])) {
        $parts[] = 'assets: ' . count($sj['asset_ids']);
    }
    if (isset($sj['tags']) && is_array($sj['tags'])) {
        $parts[] = 'tags: ' . count($sj['tags']);
    }

    return $parts !== [] ? implode(' · ', $parts) : 'custom JSON';
}

/**
 * @return list<array<string, mixed>>
 */
function st_cred_profile_list_active(PDO $pdo): array
{
    if (! st_cred_profile_tables_ready($pdo)) {
        return [];
    }
    $st = $pdo->query(
        "SELECT id, name, transport, principal_json, scope_json, enabled, created_by, created_at, updated_at,
                last_test_at, last_test_status, last_test_error_code, last_test_duration_ms,
                length(COALESCE(secret_ciphertext, '')) AS _secret_len,
                CASE WHEN length(COALESCE(secret_ciphertext, '')) > 0 THEN secret_ciphertext ELSE NULL END AS _secret_envelope_raw
         FROM credential_profiles
         WHERE deleted_at IS NULL
         ORDER BY name COLLATE NOCASE ASC, id ASC"
    );
    $out = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
        if (is_array($r)) {
            $out[] = st_cred_profile_public_row($r);
        }
    }

    return $out;
}

/**
 * @return array<string, mixed>|null
 */
function st_cred_profile_get_active(PDO $pdo, int $id): ?array
{
    if ($id < 1 || ! st_cred_profile_tables_ready($pdo)) {
        return null;
    }
    $st = $pdo->prepare(
        "SELECT id, name, transport, principal_json, scope_json, enabled, created_by, created_at, updated_at,
                last_test_at, last_test_status, last_test_error_code, last_test_duration_ms,
                length(COALESCE(secret_ciphertext, '')) AS _secret_len,
                CASE WHEN length(COALESCE(secret_ciphertext, '')) > 0 THEN secret_ciphertext ELSE NULL END AS _secret_envelope_raw
         FROM credential_profiles WHERE id = ? AND deleted_at IS NULL LIMIT 1"
    );
    $st->execute([$id]);
    $r = $st->fetch(PDO::FETCH_ASSOC);

    return is_array($r) ? st_cred_profile_public_row($r) : null;
}
