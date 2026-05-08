#!/usr/bin/env php
<?php
/**
 * Smoke test for scripts/security_runtime_audit.php (syntax + CLI + non-crash).
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$audit = $root . '/scripts/security_runtime_audit.php';

passthru(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($audit), $ec);
if ($ec !== 0) {
    fwrite(STDERR, "FAIL php -l security_runtime_audit.php\n");
    exit(2);
}

$json = [];
$des = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];
$proc = proc_open(
    [PHP_BINARY, $audit, '--install-root=' . $root, '--json'],
    $des,
    $pipes,
    $root,
    null,
    ['bypass_shell' => true]
);
if (! is_resource($proc)) {
    fwrite(STDERR, "FAIL proc_open audit\n");
    exit(2);
}
fclose($pipes[0]);
$out = stream_get_contents($pipes[1]);
fclose($pipes[1]);
fclose($pipes[2]);
$code = proc_close($proc);
$j = json_decode((string) $out, true);
if (! is_array($j) || ! isset($j['summary'])) {
    fwrite(STDERR, "FAIL audit JSON parse\n");
    exit(2);
}
if ($code === 2) {
    fwrite(STDERR, "FAIL audit exit 2 (runtime error)\n");
    exit(2);
}
if ($code !== 0 && $code !== 1) {
    fwrite(STDERR, "FAIL audit unexpected exit {$code}\n");
    exit(2);
}
fwrite(STDOUT, "OK st_security_runtime_audit_selftest (audit exit {$code}, summary keys ok)\n");

exit(0);
