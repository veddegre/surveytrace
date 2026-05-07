#!/usr/bin/env php
<?php
/**
 * Manual credential secret envelope rewrap utility.
 *
 * Default mode is dry-run; pass --apply to write changes.
 *
 * Usage:
 *   php scripts/rewrap_credential_secrets.php [--apply] [--profile-id=N] [--db=/path/to/surveytrace.db]
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_secrets.php';

const ST_REWRAP_ACTOR = 'system_maintenance';

/**
 * @return array{apply:bool,profile_id:int,db_path:string}
 */
function st_rewrap_parse_args(array $argv): array
{
    $apply = false;
    $profileId = 0;
    $dbPath = dirname(__DIR__) . '/data/surveytrace.db';
    foreach (array_slice($argv, 1) as $arg) {
        if ($arg === '--apply') {
            $apply = true;
            continue;
        }
        if ($arg === '--dry-run') {
            $apply = false;
            continue;
        }
        if ($arg === '--help' || $arg === '-h') {
            fwrite(STDOUT, "Usage: php scripts/rewrap_credential_secrets.php [--apply] [--profile-id=N] [--db=/path/to/surveytrace.db]\n");
            exit(0);
        }
        if (str_starts_with($arg, '--profile-id=')) {
            $profileId = (int) substr($arg, strlen('--profile-id='));
            continue;
        }
        if (str_starts_with($arg, '--db=')) {
            $dbPath = (string) substr($arg, strlen('--db='));
            continue;
        }
        fwrite(STDERR, "Unknown argument: {$arg}\n");
        exit(2);
    }

    return ['apply' => $apply, 'profile_id' => max(0, $profileId), 'db_path' => $dbPath];
}

function st_rewrap_ensure_audit_table(PDO $pdo): void
{
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS user_audit_log (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id    INTEGER,
            actor_username   TEXT,
            target_user_id   INTEGER,
            target_username  TEXT,
            action           TEXT NOT NULL,
            details_json     TEXT,
            source_ip        TEXT,
            created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );
}

function st_rewrap_audit(PDO $pdo, int $profileId, array $details = []): void
{
    $payload = [
        'credential_profile_id' => $profileId,
        'mode' => 'manual_rewrap',
    ] + $details;
    $enc = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $pdo->prepare(
        "INSERT INTO user_audit_log
         (actor_user_id, actor_username, target_user_id, target_username, action, details_json, source_ip)
         VALUES (NULL, ?, NULL, NULL, ?, ?, '127.0.0.1')"
    )->execute([ST_REWRAP_ACTOR, 'credential_profile.secret_rewrapped', $enc !== false ? $enc : null]);
}

/**
 * @return array{needs:bool,reason:string}
 */
function st_rewrap_needed(?array $env): array
{
    if (! is_array($env)) {
        return ['needs' => true, 'reason' => 'envelope_parse_error'];
    }
    $v = isset($env['v']) ? (int) $env['v'] : 0;
    if ($v < ST_SECRET_ENVELOPE_VERSION) {
        return ['needs' => true, 'reason' => 'older_version'];
    }
    $alg = isset($env['alg']) ? (string) $env['alg'] : '';
    if ($alg === ST_SECRET_ALG_SODIUM) {
        $ctxh = isset($env['ctxh']) ? trim((string) $env['ctxh']) : '';
        if ($ctxh === '') {
            return ['needs' => true, 'reason' => 'missing_ctxh'];
        }
    }

    return ['needs' => false, 'reason' => 'current'];
}

function st_rewrap_safe_code(Throwable $e): string
{
    $m = strtolower($e->getMessage());
    if (str_contains($m, 'not configured')) {
        return 'encryption_unavailable';
    }
    if (str_contains($m, 'context mismatch')) {
        return 'context_mismatch';
    }
    if (str_contains($m, 'invalid envelope')) {
        return 'invalid_envelope';
    }

    return 'decrypt_failed';
}

$opt = st_rewrap_parse_args($argv);

if (! st_secret_available()) {
    fwrite(STDERR, "FAIL: credential encryption key is not configured for rewrap.\n");
    exit(1);
}

try {
    $pdo = new PDO('sqlite:' . $opt['db_path'], null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA busy_timeout = 60000');
} catch (Throwable) {
    fwrite(STDERR, "FAIL: unable to open database.\n");
    exit(1);
}

$tbl = $pdo->query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='credential_profiles' LIMIT 1")->fetchColumn();
if ($tbl === false || $tbl === null) {
    fwrite(STDERR, "FAIL: credential_profiles table not found.\n");
    exit(1);
}

$where = "WHERE deleted_at IS NULL AND length(trim(COALESCE(secret_ciphertext, ''))) > 0";
$params = [];
if ($opt['profile_id'] > 0) {
    $where .= " AND id = ?";
    $params[] = $opt['profile_id'];
}
$st = $pdo->prepare("SELECT id, secret_ciphertext FROM credential_profiles {$where} ORDER BY id ASC");
$st->execute($params);
$rows = $st->fetchAll(PDO::FETCH_ASSOC);

$out = [
    'mode' => $opt['apply'] ? 'apply' : 'dry_run',
    'total_profiles_with_secrets' => 0,
    'already_current' => 0,
    'needs_rewrap' => 0,
    'rewrapped' => 0,
    'failed' => 0,
];
$failCodes = [];

if ($opt['apply']) {
    st_rewrap_ensure_audit_table($pdo);
}

foreach ($rows as $row) {
    $out['total_profiles_with_secrets']++;
    $id = (int) ($row['id'] ?? 0);
    $cipher = (string) ($row['secret_ciphertext'] ?? '');
    $envDecoded = null;
    try {
        $tmp = json_decode($cipher, true, 16, JSON_THROW_ON_ERROR);
        if (is_array($tmp)) {
            $envDecoded = $tmp;
        }
    } catch (Throwable) {
        $envDecoded = null;
    }
    $chk = st_rewrap_needed($envDecoded);
    if (! $chk['needs']) {
        $out['already_current']++;
        continue;
    }
    $out['needs_rewrap']++;
    if (! $opt['apply']) {
        continue;
    }
    try {
        $plain = st_secret_decrypt($cipher, ['credential_profile_id' => $id]);
        $newEnv = st_secret_encrypt($plain, ['credential_profile_id' => $id]);
        $pdo->beginTransaction();
        $pdo->prepare("UPDATE credential_profiles SET secret_ciphertext = ?, updated_at = datetime('now') WHERE id = ?")
            ->execute([$newEnv, $id]);
        st_rewrap_audit($pdo, $id, ['reason' => $chk['reason']]);
        $pdo->commit();
        $out['rewrapped']++;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        $code = st_rewrap_safe_code($e);
        $failCodes[$code] = ($failCodes[$code] ?? 0) + 1;
        $out['failed']++;
    }
}

fwrite(STDOUT, json_encode([
    'ok' => true,
    'result' => $out,
    'failure_codes' => $failCodes,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "\n");
exit(0);
