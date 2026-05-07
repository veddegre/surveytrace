#!/usr/bin/env php
<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_secrets.php';
require_once dirname(__DIR__) . '/api/lib_credential_profiles.php';

function tfail(string $msg): void
{
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

function run_cli(string $script, array $args, array $env = []): array
{
    $cmd = array_merge([PHP_BINARY, $script], $args);
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $spec, $pipes, dirname(__DIR__), $env !== [] ? $env : null);
    if (! is_resource($proc)) {
        tfail('proc_open failed');
    }
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $rc = proc_close($proc);

    return [$rc, (string) $out, (string) $err];
}

$tmpDir = sys_get_temp_dir() . '/st_rewrap_' . bin2hex(random_bytes(4));
if (! mkdir($tmpDir, 0700, true) && ! is_dir($tmpDir)) {
    tfail('tmp dir create failed');
}
$db = $tmpDir . '/test.db';
$schema = dirname(__DIR__) . '/sql/schema.sql';
$schemaSql = @file_get_contents($schema);
if (! is_string($schemaSql) || $schemaSql === '') {
    tfail('schema read failed');
}

try {
    $pdo = new PDO('sqlite:' . $db, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec($schemaSql);
    $pdo->exec("CREATE TABLE IF NOT EXISTS user_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER,
        actor_username TEXT,
        target_user_id INTEGER,
        target_username TEXT,
        action TEXT NOT NULL,
        details_json TEXT,
        source_ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
} catch (Throwable $e) {
    tfail('db bootstrap failed: ' . $e->getMessage());
}

$key = base64_encode(random_bytes(32));
putenv('SURVEYTRACE_CRED_SECRET_KEY=' . $key);
putenv('SURVEYTRACE_CRED_SECRET_KEY_STRICT=1');

$pdo->prepare(
    "INSERT INTO credential_profiles (name, transport, principal_json, enabled, created_at, updated_at, deleted_at)
     VALUES ('selftest', 'ssh', '{\"username\":\"u\"}', 1, datetime('now'), datetime('now'), NULL)"
)->execute();
$profileId = (int) $pdo->lastInsertId();
if ($profileId < 1) {
    tfail('profile insert failed');
}

$plain = json_encode(['password' => 'p@ssw0rd'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if (! is_string($plain)) {
    tfail('plain encode failed');
}
$env = st_secret_encrypt($plain, ['credential_profile_id' => $profileId]);
$dec = json_decode($env, true);
if (! is_array($dec)) {
    tfail('envelope decode failed');
}
$dec['v'] = 0; // legacy/older version marker
unset($dec['ctxh']); // legacy sodium path marker when present
$legacy = json_encode($dec, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if (! is_string($legacy)) {
    tfail('legacy envelope encode failed');
}
$pdo->prepare("UPDATE credential_profiles SET secret_ciphertext = ? WHERE id = ?")->execute([$legacy, $profileId]);

$rewrapScript = dirname(__DIR__) . '/scripts/rewrap_credential_secrets.php';
[$rcDry, $outDry, $errDry] = run_cli($rewrapScript, ['--db=' . $db]);
if ($rcDry !== 0) {
    tfail('dry-run rc=' . $rcDry . ' err=' . trim($errDry));
}
$dry = json_decode($outDry, true);
if (! is_array($dry) || ! isset($dry['result'])) {
    tfail('dry-run output parse failed');
}
if ((int) ($dry['result']['needs_rewrap'] ?? 0) !== 1 || (int) ($dry['result']['rewrapped'] ?? 0) !== 0) {
    tfail('dry-run counts unexpected');
}

[$rcApply, $outApply, $errApply] = run_cli($rewrapScript, ['--db=' . $db, '--apply']);
if ($rcApply !== 0) {
    tfail('apply rc=' . $rcApply . ' err=' . trim($errApply));
}
$ap = json_decode($outApply, true);
if (! is_array($ap) || (int) ($ap['result']['rewrapped'] ?? 0) !== 1 || (int) ($ap['result']['failed'] ?? 0) !== 0) {
    tfail('apply counts unexpected');
}

$cipherNew = (string) $pdo->query("SELECT secret_ciphertext FROM credential_profiles WHERE id = {$profileId}")->fetchColumn();
$plainNew = st_secret_decrypt($cipherNew, ['credential_profile_id' => $profileId]);
if (! hash_equals($plain, $plainNew)) {
    tfail('rewrap changed plaintext');
}

$pub = st_cred_profile_get_active($pdo, $profileId);
if (! is_array($pub) || empty($pub['has_secret'])) {
    tfail('metadata read failed after rewrap');
}

$auditCount = (int) $pdo->query("SELECT COUNT(*) FROM user_audit_log WHERE action='credential_profile.secret_rewrapped'")->fetchColumn();
if ($auditCount < 1) {
    tfail('expected rewrap audit row');
}

putenv('SURVEYTRACE_CRED_SECRET_KEY');
[$rcMissing, , $errMissing] = run_cli($rewrapScript, ['--db=' . $db]);
if ($rcMissing === 0 || ! str_contains($errMissing, 'not configured')) {
    tfail('missing-key safety check failed');
}

fwrite(STDERR, "OK st_cred_secret_rewrap_selftest\n");
exit(0);
