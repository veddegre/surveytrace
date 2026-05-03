<?php
/**
 * Phase 14.1 — outbound HTTPS transport helpers + legacy config-key webhook (`st_integrations_outbound_emit`).
 *
 * Payloads must match **`api/lib_reporting_event_model.php`** (`schema_version` **`surveytrace.reporting.event.v1`**).
 * As of Phase 14.1 **no scheduled or scan path invokes** `st_integrations_outbound_emit()` (materialize hook removed);
 * outbound validation uses **`api/integrations.php`** test/sample on **`integrations`** rows. `st_integrations_outbound_emit()`
 * remains for optional future wiring to **`integration_webhook_*`** settings.
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';

/** Config keys: `integration_webhook_enabled` (0|1), `integration_webhook_url`, `integration_webhook_secret`. */

/**
 * HTTPS (or lab HTTP) JSON POST with short timeouts. Returns HTTP status and curl error fragment.
 *
 * @param list<string> $extraHeaders full "Name: value" lines after Content-Type
 *
 * @return array{ok:bool, http_code:int, error:string}
 */
function st_integrations_http_post_json(string $url, string $body, array $extraHeaders, int $connectTimeout = 5, int $totalTimeout = 12): array
{
    $parts = @parse_url($url);
    if (! is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
        return ['ok' => false, 'http_code' => 0, 'error' => 'invalid_url'];
    }
    $scheme = strtolower((string) $parts['scheme']);
    $allowHttpLab = st_config('security_allow_private_outbound_targets', '0') === '1';
    if ($scheme !== 'https' && ! ($scheme === 'http' && $allowHttpLab)) {
        return ['ok' => false, 'http_code' => 0, 'error' => 'https_required'];
    }
    if (strlen($url) > 2048) {
        return ['ok' => false, 'http_code' => 0, 'error' => 'url_too_long'];
    }
    if (! function_exists('curl_init')) {
        return ['ok' => false, 'http_code' => 0, 'error' => 'curl_required'];
    }
    $headers = array_merge(
        [
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: SurveyTrace-integrations/1',
        ],
        $extraHeaders
    );
    $ch = curl_init($url);
    if ($ch === false) {
        return ['ok' => false, 'http_code' => 0, 'error' => 'curl_init_failed'];
    }
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, max(1, $connectTimeout));
    curl_setopt($ch, CURLOPT_TIMEOUT, max(1, $totalTimeout));
    if (defined('CURLOPT_PROTOCOLS')) {
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    }
    curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = (string) curl_error($ch);
    curl_close($ch);
    $ok = $httpCode >= 200 && $httpCode < 300;

    return ['ok' => $ok, 'http_code' => $httpCode, 'error' => $err];
}

function st_integrations_outbound_emit(PDO $_db, array $canonicalEvent): void
{
    $schema = (string) ($canonicalEvent['schema_version'] ?? '');
    if ($schema !== 'surveytrace.reporting.event.v1') {
        @error_log('SurveyTrace.integrations ' . json_encode([
            '_event' => 'integrations.emit_skip',
            'reason' => 'bad_schema_version',
            'got'    => $schema,
        ], JSON_UNESCAPED_SLASHES));

        return;
    }
    if (st_config('integration_webhook_enabled', '0') !== '1') {
        return;
    }
    $url = trim(st_config('integration_webhook_url', ''));
    if ($url === '') {
        return;
    }

    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    $body = json_encode($canonicalEvent, $flags);
    if ($body === false) {
        $body = '{}';
    }

    $extra = [];
    $secret = trim(st_config('integration_webhook_secret', ''));
    if ($secret !== '') {
        $sig = hash_hmac('sha256', $body, $secret);
        $extra[] = 'X-SurveyTrace-Signature: sha256=' . $sig;
    }

    $res = st_integrations_http_post_json($url, $body, $extra, 5, 12);
    $ok = $res['ok'];
    $httpCode = $res['http_code'];
    $err = $res['error'];

    $log = [
        '_event'     => $ok ? 'integrations.webhook_ok' : 'integrations.webhook_err',
        'http_code'  => $httpCode,
        'event_type' => $canonicalEvent['event_type'] ?? null,
        'event_id'   => $canonicalEvent['event_id'] ?? null,
    ];
    if (! $ok && $err !== '') {
        $log['curl_error'] = substr($err, 0, 200);
    }
    @error_log('SurveyTrace.integrations ' . json_encode($log, JSON_UNESCAPED_SLASHES));
}
