#!/usr/bin/env php
<?php
/**
 * CLI helper for Python daemons — decrypt credential_profiles.secret_ciphertext
 * using the same algorithm as api/lib_secrets.php (env SURVEYTRACE_CRED_SECRET_KEY).
 *
 * Usage: echo -n "$envelope_json" | php daemon/cred_decrypt_cli.php '{"credential_profile_id":123}'
 * Plaintext secret JSON is written to stdout; errors to stderr (exit 1).
 */

declare(strict_types=1);

if ($argc < 2) {
    fwrite(STDERR, "usage: php daemon/cred_decrypt_cli.php '<context_json>' < envelope.txt\n");
    exit(2);
}

$contextJson = $argv[1];
$envelope = stream_get_contents(STDIN);
if (! is_string($envelope) || trim($envelope) === '') {
    fwrite(STDERR, 'empty envelope');
    exit(1);
}

require_once __DIR__ . '/../api/lib_secrets.php';

try {
    $ctx = json_decode($contextJson, true, 512, JSON_THROW_ON_ERROR);
    if (! is_array($ctx)) {
        $ctx = [];
    }
    $plain = st_secret_decrypt($envelope, $ctx);
    echo $plain;
    exit(0);
} catch (Throwable $e) {
    $m = strtolower(trim((string) $e->getMessage()));
    if ($m !== '' && str_contains($m, 'not configured')) {
        fwrite(STDERR, 'encryption_unavailable');
        exit(1);
    }
    if ($m !== '' && (str_contains($m, 'libsodium not available') || str_contains($m, 'openssl not available'))) {
        fwrite(STDERR, 'dependency_missing');
        exit(1);
    }
    fwrite(STDERR, 'decrypt_failed');
    exit(1);
}
