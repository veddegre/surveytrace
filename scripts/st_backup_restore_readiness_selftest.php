#!/usr/bin/env php
<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_secrets.php';

function bfail(string $msg): void
{
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

/**
 * @return array{0:int,1:string,2:string}
 */
function brun(string $script, array $args, array $env = []): array
{
    $cmd = array_merge([PHP_BINARY, $script], $args);
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $spec, $pipes, dirname(__DIR__), $env !== [] ? $env : null);
    if (! is_resource($proc)) {
        bfail('proc_open failed');
    }
    fclose($pipes[0]);
    $out = (string) stream_get_contents($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $rc = proc_close($proc);

    return [$rc, $out, $err];
}

$tmp = sys_get_temp_dir() . '/st_brr_' . bin2hex(random_bytes(4));
if (! mkdir($tmp, 0700, true) && ! is_dir($tmp)) {
    bfail('tmp dir create failed');
}
$db = $tmp . '/test.db';
$schema = @file_get_contents(dirname(__DIR__) . '/sql/schema.sql');
if (! is_string($schema) || $schema === '') {
    bfail('schema read failed');
}

try {
    $pdo = new PDO('sqlite:' . $db, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec($schema);
} catch (Throwable $e) {
    bfail('db bootstrap failed: ' . $e->getMessage());
}

$validator = dirname(__DIR__) . '/scripts/validate_backup_restore_readiness.php';

// Case 1: no stored secrets => should pass with possible WARN (missing key acceptable).
[$rc1, $out1, $err1] = brun($validator, ['--db=' . $db]);
if ($rc1 !== 0) {
    bfail('validator no-secret case failed rc=' . $rc1 . ' err=' . trim($err1));
}
if (! str_contains($out1, 'Credential profiles with stored secrets: 0')) {
    bfail('no-secret case missing expected count');
}

// Case 2: add encrypted secret + key => decrypt validation should pass.
$key = base64_encode(random_bytes(32));
putenv('SURVEYTRACE_CRED_SECRET_KEY=' . $key);
putenv('SURVEYTRACE_CRED_SECRET_KEY_STRICT=1');
$pdo->prepare(
    "INSERT INTO credential_profiles (name, transport, principal_json, enabled, created_at, updated_at, deleted_at)
     VALUES ('brr-selftest', 'ssh', '{\"username\":\"u\"}', 1, datetime('now'), datetime('now'), NULL)"
)->execute();
$pid = (int) $pdo->lastInsertId();
if ($pid < 1) {
    bfail('profile insert failed');
}
$cipher = st_secret_encrypt(json_encode(['password' => 'x'], JSON_UNESCAPED_SLASHES), ['credential_profile_id' => $pid]);
$pdo->prepare("UPDATE credential_profiles SET secret_ciphertext = ? WHERE id = ?")->execute([$cipher, $pid]);

[$rc2, $out2, $err2] = brun($validator, ['--db=' . $db], [
    'SURVEYTRACE_CRED_SECRET_KEY' => $key,
    'SURVEYTRACE_CRED_SECRET_KEY_STRICT' => '1',
]);
if ($rc2 !== 0) {
    bfail('validator secret case failed rc=' . $rc2 . ' err=' . trim($err2));
}
if (! str_contains($out2, 'Decrypt validation succeeded on one stored profile secret.')) {
    bfail('secret case missing decrypt success');
}

fwrite(STDERR, "OK st_backup_restore_readiness_selftest\n");
exit(0);
