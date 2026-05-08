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

/**
 * Map decrypt failure to a single-line stderr token (no secret material; operators + Python probe).
 */
function st_cred_decrypt_cli_error_token(Throwable $e): string
{
    $m = strtolower((string) $e->getMessage());
    if ($m !== '' && str_contains($m, 'not configured')) {
        return 'encryption_unavailable';
    }
    if ($m !== '' && (str_contains($m, 'libsodium not available') || str_contains($m, 'openssl not available'))) {
        return 'dependency_missing';
    }
    if (str_contains($m, 'envelope context mismatch')) {
        return 'envelope_context_mismatch';
    }
    if (str_contains($m, 'wrong key or corrupt') || str_contains($m, 'decryption failed')) {
        return 'wrong_key_or_corrupt';
    }
    if (str_contains($m, 'invalid envelope encoding')) {
        return 'invalid_envelope_encoding';
    }
    if (str_contains($m, 'invalid gcm tag')) {
        return 'invalid_gcm_tag';
    }
    if (str_contains($m, 'invalid envelope')) {
        return 'invalid_envelope';
    }
    if (str_contains($m, 'unsupported envelope algorithm')) {
        return 'unsupported_envelope_algorithm';
    }

    return 'decrypt_unknown';
}

try {
    $ctx = json_decode($contextJson, true, 512, JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    fwrite(STDERR, 'context_json_invalid');
    exit(1);
}
if (! is_array($ctx)) {
    $ctx = [];
}

try {
    $plain = st_secret_decrypt($envelope, $ctx);
    echo $plain;
    exit(0);
} catch (Throwable $e) {
    if ($e instanceof JsonException) {
        fwrite(STDERR, 'envelope_json_invalid');
        exit(1);
    }
    $token = st_cred_decrypt_cli_error_token($e);
    if ($token === 'encryption_unavailable') {
        fwrite(STDERR, 'encryption_unavailable');
        exit(1);
    }
    if ($token === 'dependency_missing') {
        fwrite(STDERR, 'dependency_missing');
        exit(1);
    }
    fwrite(STDERR, $token);
    exit(1);
}
