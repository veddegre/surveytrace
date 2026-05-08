<?php
/**
 * SurveyTrace — application credential secret envelope (authenticated encryption).
 *
 * Key material: **environment only** — `SURVEYTRACE_CRED_SECRET_KEY` (never stored in SQLite).
 * On hardened installs the key lives in `/etc/surveytrace/surveytrace.env` (readable by `surveytrace`, not the web pool);
 * the web UI uses **`daemon/cred_secret_ops_cli.php` via sudo** for encrypt/handshake paths instead of loading the key in php-fpm.
 * Accepts: base64-encoded 32 raw bytes, 64-char hex (32 bytes), or any string (SHA-256 → 32-byte key).
 * Prefer: `openssl rand -base64 32` for production.
 *
 * Algorithms: libsodium `crypto_secretbox` when ext-sodium is available; else OpenSSL **AES-256-GCM**.
 * Envelope JSON (stored in `credential_profiles.secret_ciphertext`):
 *   v, alg, nonce (base64), ciphertext (base64), tag (base64, GCM only)
 *
 * @see docs/CREDENTIALED_CHECKS_MVP_PLAN.md
 */

declare(strict_types=1);

const ST_SECRET_ENVELOPE_VERSION = 1;
const ST_SECRET_ALG_SODIUM = 'sodium_secretbox';
const ST_SECRET_ALG_GCM = 'aes-256-gcm';
const ST_SECRET_MAX_PLAINTEXT_BYTES = 262144; // 256 KiB

function st_secret_env_key_raw(): string
{
    $v = getenv('SURVEYTRACE_CRED_SECRET_KEY');

    return is_string($v) ? trim($v) : '';
}

function st_secret_strict_key_mode(): bool
{
    $v = getenv('SURVEYTRACE_CRED_SECRET_KEY_STRICT');
    if (! is_string($v)) {
        return false;
    }
    $t = strtolower(trim($v));

    return $t === '1' || $t === 'true' || $t === 'yes' || $t === 'on';
}

/**
 * Derive exactly 32 bytes for AES-256 / sodium secretbox key.
 */
function st_secret_derive_key_32(string $configured): ?string
{
    if ($configured === '') {
        return null;
    }
    $bin = @base64_decode($configured, true);
    if ($bin !== false && strlen($bin) === 32) {
        return $bin;
    }
    if (strlen($configured) === 64 && ctype_xdigit($configured)) {
        $h = @hex2bin($configured);

        return ($h !== false && strlen($h) === 32) ? $h : null;
    }
    if (st_secret_strict_key_mode()) {
        return null;
    }

    return hash('sha256', $configured, true);
}

function st_secret_available(): bool
{
    return st_secret_derive_key_32(st_secret_env_key_raw()) !== null;
}

/**
 * Safe status for API/UI (no secret material).
 *
 * @return array<string, mixed>
 */
function st_secret_status(): array
{
    $raw = st_secret_env_key_raw();
    $key = st_secret_derive_key_32($raw);
    $fp = null;
    if ($key !== null) {
        $fp = substr(hash('sha256', $key, false), 0, 16);
    }

    $useSodium = extension_loaded('sodium') && function_exists('sodium_crypto_secretbox');

    return [
        'available'        => $key !== null,
        'key_fingerprint'  => $fp,
        'source'           => $raw !== '' ? 'env' : 'missing',
        'preferred_alg'    => $useSodium ? ST_SECRET_ALG_SODIUM : ST_SECRET_ALG_GCM,
        'libsodium_loaded' => $useSodium,
        'openssl_cipher'   => function_exists('openssl_encrypt') ? 'aes-256-gcm' : null,
    ];
}

/**
 * Non-decrypting summary of a stored envelope (for UI / diagnostics).
 *
 * @return array<string, mixed>
 */
function st_secret_redact_summary(?string $envelope): array
{
    if ($envelope === null || trim($envelope) === '') {
        return ['stored' => false];
    }
    try {
        $j = json_decode($envelope, true, 8, JSON_THROW_ON_ERROR);
        if (! is_array($j)) {
            return ['stored' => true, 'envelope_parse_ok' => false];
        }

        return [
            'stored'            => true,
            'envelope_parse_ok' => true,
            'v'                 => isset($j['v']) ? (int) $j['v'] : null,
            'alg'               => isset($j['alg']) ? (string) $j['alg'] : null,
            'nonce_b64_len'     => isset($j['nonce']) ? strlen((string) $j['nonce']) : null,
            'ciphertext_b64_len'=> isset($j['ciphertext']) ? strlen((string) $j['ciphertext']) : null,
        ];
    } catch (Throwable) {
        return ['stored' => true, 'envelope_parse_ok' => false];
    }
}

/**
 * @param array<string, mixed> $context Optional binding (e.g. profile_id) included as AEAD / AAD where supported.
 */
function st_secret_encrypt(string $plaintext, array $context = []): string
{
    if (strlen($plaintext) > ST_SECRET_MAX_PLAINTEXT_BYTES) {
        throw new RuntimeException('Secret payload exceeds maximum size.');
    }
    $keyMat = st_secret_derive_key_32(st_secret_env_key_raw());
    if ($keyMat === null) {
        throw new RuntimeException('Credential encryption is not configured.');
    }
    $aad = $context !== [] ? substr(hash('sha256', json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), true), 0, 16) : '';
    $ctxh = $context !== [] ? hash('sha256', json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), false) : '';

    if (extension_loaded('sodium') && function_exists('sodium_crypto_secretbox')) {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ct = sodium_crypto_secretbox($plaintext, $nonce, $keyMat);
        if ($ct === false) {
            throw new RuntimeException('Encryption failed.');
        }
        $env = [
            'v'          => ST_SECRET_ENVELOPE_VERSION,
            'alg'        => ST_SECRET_ALG_SODIUM,
            'nonce'      => base64_encode($nonce),
            'ciphertext' => base64_encode($ct),
        ];
        // secretbox has no AAD; bind context by storing deterministic hash for decrypt-time verification.
        if ($ctxh !== '') {
            $env['ctxh'] = $ctxh;
        }
        $json = json_encode($env, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new RuntimeException('Envelope encode failed.');
        }

        return $json;
    }

    if (! function_exists('openssl_encrypt')) {
        throw new RuntimeException('Neither libsodium nor OpenSSL encryption is available on this PHP build.');
    }
    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $keyMat, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
    if ($ct === false || strlen($tag) !== 16) {
        throw new RuntimeException('Encryption failed.');
    }
    $env = [
        'v'          => ST_SECRET_ENVELOPE_VERSION,
        'alg'        => ST_SECRET_ALG_GCM,
        'nonce'      => base64_encode($iv),
        'ciphertext' => base64_encode($ct),
        'tag'        => base64_encode($tag),
    ];
    if ($aad !== '') {
        $env['aad'] = base64_encode($aad);
        $env['ctxh'] = $ctxh;
    }
    $json = json_encode($env, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        throw new RuntimeException('Envelope encode failed.');
    }

    return $json;
}

/**
 * @param array<string, mixed> $context Same semantics as encrypt (must match for decrypt).
 */
function st_secret_decrypt(string $envelope, array $context = []): string
{
    $keyMat = st_secret_derive_key_32(st_secret_env_key_raw());
    if ($keyMat === null) {
        throw new RuntimeException('Credential encryption is not configured.');
    }
    $j = json_decode($envelope, true, 16, JSON_THROW_ON_ERROR);
    if (! is_array($j)) {
        throw new RuntimeException('Invalid envelope.');
    }
    $alg = (string) ($j['alg'] ?? '');
    $nonce = isset($j['nonce']) ? base64_decode((string) $j['nonce'], true) : false;
    $ct = isset($j['ciphertext']) ? base64_decode((string) $j['ciphertext'], true) : false;
    if ($nonce === false || $ct === false) {
        throw new RuntimeException('Invalid envelope encoding.');
    }
    $aad = $context !== [] ? substr(hash('sha256', json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), true), 0, 16) : '';
    $ctxh = $context !== [] ? hash('sha256', json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), false) : '';
    if ($alg === ST_SECRET_ALG_SODIUM) {
        if ($ctxh !== '' && isset($j['ctxh']) && is_string($j['ctxh'])) {
            if (! hash_equals($ctxh, (string) $j['ctxh'])) {
                throw new RuntimeException('Envelope context mismatch.');
            }
        }
        if (! extension_loaded('sodium') || ! function_exists('sodium_crypto_secretbox_open')) {
            throw new RuntimeException('libsodium not available for decrypt.');
        }
        $pt = sodium_crypto_secretbox_open($ct, $nonce, $keyMat);
        if ($pt === false) {
            throw new RuntimeException('Decryption failed (wrong key or corrupt data).');
        }

        return $pt;
    }
    if ($alg === ST_SECRET_ALG_GCM) {
        if ($aad !== '') {
            $aadFromEnv = isset($j['aad']) ? base64_decode((string) $j['aad'], true) : false;
            if ($aadFromEnv === false || ! hash_equals($aad, $aadFromEnv)) {
                throw new RuntimeException('Envelope context mismatch.');
            }
        }
        if (! function_exists('openssl_decrypt')) {
            throw new RuntimeException('OpenSSL not available for decrypt.');
        }
        $tag = isset($j['tag']) ? base64_decode((string) $j['tag'], true) : false;
        if ($tag === false || strlen($tag) !== 16) {
            throw new RuntimeException('Invalid GCM tag.');
        }
        $pt = openssl_decrypt($ct, 'aes-256-gcm', $keyMat, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        if ($pt === false) {
            throw new RuntimeException('Decryption failed (wrong key or corrupt data).');
        }

        return $pt;
    }

    throw new RuntimeException('Unsupported envelope algorithm.');
}
