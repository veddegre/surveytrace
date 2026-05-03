<?php
/**
 * Phase 14.1 — integrations foundation (admin CRUD, per-integration pull auth, metrics/events/summary helpers).
 *
 * Canonical payloads use **`api/lib_reporting_event_model.php`** (`surveytrace.reporting.event.v1`).
 * Do not rename that contract here.
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_scan_scopes.php';
require_once __DIR__ . '/lib_reporting_event_model.php';
require_once __DIR__ . '/lib_integrations_outbound.php';

/** @return list<string> */
function st_integrations_types_all(): array
{
    return [
        'splunk_hec',
        'syslog',
        'webhook',
        'loki',
        'prometheus_pull',
        'json_events_pull',
        'report_summary_pull',
        'grafana_infinity_pull',
    ];
}

function st_integrations_type_valid(string $t): bool
{
    return in_array($t, st_integrations_types_all(), true);
}

/** @return list<string> */
function st_integrations_list_types_pull(): array
{
    return ['prometheus_pull', 'json_events_pull', 'report_summary_pull', 'grafana_infinity_pull'];
}

function st_integrations_is_pull_type(string $t): bool
{
    return in_array($t, st_integrations_list_types_pull(), true);
}

/** User-facing label for Integrations UI (internal `type` unchanged). */
function st_integrations_type_display_label(string $t): string
{
    return match ($t) {
        'webhook'             => 'Generic webhook push',
        'splunk_hec'          => 'Splunk HEC push',
        'syslog'              => 'Syslog push',
        'loki'                => 'Grafana Loki push',
        'prometheus_pull'     => 'Prometheus / Grafana metrics pull',
        'json_events_pull'    => 'Splunk scripted input / JSON events pull',
        'report_summary_pull'     => 'Grafana Infinity / report summary pull',
        'grafana_infinity_pull'   => 'Grafana Infinity dashboard pull',
        default                   => $t,
    };
}

/** API paths shown for pull rows (Bearer must match integration type for the route). */
function st_integrations_pull_endpoint_display(string $type): string
{
    return match ($type) {
        'prometheus_pull'       => '/api/integrations_metrics.php',
        'json_events_pull'      => '/api/integrations_events.php',
        'report_summary_pull'   => '/api/integrations_dashboard.php and /api/integrations_report_summary.php',
        'grafana_infinity_pull' => '/api/integrations_dashboard.php (?view=…), /api/integrations_report_summary.php, /api/integrations_events.php?format=json, /api/integrations_metrics.php?format=json',
        default                 => '',
    };
}

/**
 * Destination or API path summary for list UI (no secrets).
 */
function st_integrations_row_destination_summary(array $row): string
{
    $type = (string) ($row['type'] ?? '');
    if (st_integrations_is_pull_type($type)) {
        return st_integrations_pull_endpoint_display($type);
    }
    if ($type === 'syslog') {
        $h = trim((string) ($row['host'] ?? ''));
        $p = isset($row['port']) && $row['port'] !== null && $row['port'] !== ''
            ? (int) $row['port']
            : 514;

        return $h !== '' ? ($h . ':' . $p) : '';
    }

    return trim((string) ($row['endpoint_url'] ?? ''));
}

/**
 * Pull route keys: metrics | events | report_summary | dashboard.
 *
 * Options (route-dependent):
 * - `metrics_format`: `prometheus` (default) or `json` — `grafana_infinity_pull` is allowed only for `json`.
 * - `events_format`: `json` (default) or `jsonl` — `grafana_infinity_pull` is allowed only for `json`.
 *
 * @param array{metrics_format?:string, events_format?:string} $opts
 *
 * @return list<string>
 */
function st_integrations_pull_route_types(string $route, array $opts = []): array
{
    $mf = strtolower(trim((string) ($opts['metrics_format'] ?? 'prometheus')));
    $ef = strtolower(trim((string) ($opts['events_format'] ?? 'json')));

    return match ($route) {
        'metrics' => $mf === 'json'
            ? ['prometheus_pull', 'grafana_infinity_pull']
            : ['prometheus_pull'],
        'events' => $ef === 'jsonl'
            ? ['json_events_pull']
            : ['json_events_pull', 'grafana_infinity_pull'],
        'report_summary', 'dashboard' => ['report_summary_pull', 'grafana_infinity_pull'],
        default => [],
    };
}

function st_integrations_any_row_pull_token_configured(PDO $db): bool
{
    if (! st_sqlite_table_exists($db, 'integrations')) {
        return false;
    }
    $types = st_integrations_list_types_pull();
    $ph = implode(',', array_fill(0, count($types), '?'));
    $st = $db->prepare(
        "SELECT COUNT(*) FROM integrations WHERE enabled = 1 AND type IN ($ph)
         AND token_hash IS NOT NULL AND TRIM(token_hash) != ''
         AND SUBSTR(TRIM(token_hash), 1, 1) = '\$'"
    );
    $st->execute($types);

    return (int) $st->fetchColumn() > 0;
}

/**
 * Raw Authorization header value (nginx/php-fpm often omits HTTP_AUTHORIZATION unless configured).
 */
function st_integrations_pull_authorization_header_raw(): string
{
    foreach ([$_SERVER['HTTP_AUTHORIZATION'] ?? null, $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null] as $v) {
        if (is_string($v)) {
            $v = trim($v);
            if ($v !== '') {
                return $v;
            }
        }
    }
    $scan = static function (?array $hdrs): string {
        if (! is_array($hdrs)) {
            return '';
        }
        foreach ($hdrs as $k => $v) {
            if (strcasecmp((string) $k, 'Authorization') !== 0 || ! is_string($v)) {
                continue;
            }
            $v = trim($v);
            if ($v !== '') {
                return $v;
            }
        }

        return '';
    };
    if (function_exists('apache_request_headers')) {
        $h = @apache_request_headers();
        $found = $scan(is_array($h) ? $h : null);
        if ($found !== '') {
            return $found;
        }
    }
    if (function_exists('getallheaders')) {
        $h = @getallheaders();
        $found = $scan(is_array($h) ? $h : null);
        if ($found !== '') {
            return $found;
        }
    }

    return '';
}

/**
 * Plaintext pull token and how it was supplied (for logging; never log the token).
 *
 * @return array{plain:string, source:string} source: query_token|bearer_header|none
 */
function st_integrations_pull_token_from_request_meta(): array
{
    $q = isset($_GET['token']) ? trim((string) $_GET['token']) : '';
    if ($q !== '') {
        return ['plain' => $q, 'source' => 'query_token'];
    }
    $auth = st_integrations_pull_authorization_header_raw();
    if ($auth !== '' && stripos($auth, 'Bearer ') === 0) {
        $plain = trim(substr($auth, 7));
        if ($plain !== '') {
            return ['plain' => $plain, 'source' => 'bearer_header'];
        }
    }

    return ['plain' => '', 'source' => 'none'];
}

/**
 * Verify pull request: Authorization: Bearer … or ?token=
 */
function st_integrations_pull_token_from_request(): string
{
    return st_integrations_pull_token_from_request_meta()['plain'];
}

function st_integrations_pull_client_ip(): string
{
    $ip = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    if (strlen($ip) > 45) {
        return substr($ip, 0, 45);
    }

    return $ip;
}

/**
 * @param list<string> $types
 */
function st_integrations_pull_auth_available(PDO $db, array $types): bool
{
    if (! st_sqlite_table_exists($db, 'integrations') || $types === []) {
        return false;
    }
    $ph = implode(',', array_fill(0, count($types), '?'));
    $st = $db->prepare(
        "SELECT COUNT(*) FROM integrations WHERE enabled = 1 AND type IN ($ph)
         AND token_hash IS NOT NULL AND TRIM(token_hash) != ''
         AND SUBSTR(TRIM(token_hash), 1, 1) = '\$'"
    );
    $st->execute($types);

    return (int) $st->fetchColumn() > 0;
}

/**
 * @param list<string> $types
 *
 * @return list<array<string,mixed>>
 */
function st_integrations_pull_candidate_rows(PDO $db, array $types): array
{
    if (! st_sqlite_table_exists($db, 'integrations') || $types === []) {
        return [];
    }
    $ph = implode(',', array_fill(0, count($types), '?'));
    $st = $db->prepare(
        "SELECT id, name, type, token_hash FROM integrations
         WHERE enabled = 1 AND type IN ($ph)
           AND token_hash IS NOT NULL AND TRIM(token_hash) != ''
           AND SUBSTR(TRIM(token_hash), 1, 1) = '\$'"
    );
    $st->execute($types);

    return $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
}

/**
 * @return array{integration_id:int, integration_name:string, integration_type:string}|null
 */
function st_integrations_pull_resolve_context(PDO $db, string $route, string $plain, array $routeOpts = []): ?array
{
    $plain = trim($plain);
    if ($plain === '') {
        return null;
    }
    $types = st_integrations_pull_route_types($route, $routeOpts);
    foreach (st_integrations_pull_candidate_rows($db, $types) as $r) {
        $hash = (string) ($r['token_hash'] ?? '');
        if ($hash === '' || ! password_verify($plain, $hash)) {
            continue;
        }

        return [
            'integration_id'   => (int) ($r['id'] ?? 0),
            'integration_name' => (string) ($r['name'] ?? ''),
            'integration_type' => (string) ($r['type'] ?? ''),
        ];
    }

    return null;
}

function st_integrations_pull_touch_used(PDO $db, int $integrationId, string $clientIp): void
{
    if ($integrationId <= 0) {
        return;
    }
    try {
        $db->prepare(
            'UPDATE integrations SET token_last_used_at = datetime(\'now\'), token_last_used_ip = ?, updated_at = datetime(\'now\') WHERE id = ?'
        )->execute([$clientIp, $integrationId]);
    } catch (Throwable $e) {
        @error_log('SurveyTrace.integrations ' . json_encode([
            '_event'  => 'pull_token_touch_failed',
            'id'      => $integrationId,
            'message' => st_integrations_redact_string(st_integrations_sanitize_exception_message($e)),
        ], JSON_UNESCAPED_SLASHES));
    }
}

function st_integrations_pull_auth_failure_log(
    string $route,
    string $reason,
    string $auth_source_detected,
    int $candidate_count,
    array $allowed_types
): void {
    @error_log('SurveyTrace.integrations ' . json_encode([
        '_event'               => 'integrations.pull_auth_failed',
        'route'                => $route,
        'reason'               => $reason,
        'auth_source_detected' => $auth_source_detected,
        'candidate_count'      => $candidate_count,
        'allowed_types'        => $allowed_types,
    ], JSON_UNESCAPED_SLASHES));
}

/**
 * Authenticate pull request; exits with JSON 401/503/500 on failure.
 *
 * @param array{metrics_format?:string, events_format?:string} $routeOpts
 *
 * @return array{integration_id:int, integration_name:string, integration_type:string}
 */
function st_integrations_pull_require_token_for(PDO $db, string $route, array $routeOpts = []): array
{
    $types = st_integrations_pull_route_types($route, $routeOpts);
    if ($types === []) {
        st_integrations_pull_auth_failure_log($route, 'invalid_token', 'none', 0, []);
        st_json(['ok' => false, 'error' => 'invalid pull route'], 500);
    }
    if (! st_integrations_pull_token_schema_ready($db)) {
        st_integrations_pull_auth_failure_log($route, 'schema_error', 'none', 0, $types);
        st_json(['ok' => false, 'error' => 'database schema incomplete for pull integrations'], 500);
    }
    if (! st_integrations_pull_auth_available($db, $types)) {
        st_integrations_pull_auth_failure_log($route, 'no_candidates', 'none', 0, $types);
        st_json(['ok' => false, 'error' => 'no enabled pull integration token configured for this endpoint'], 503);
    }
    $meta = st_integrations_pull_token_from_request_meta();
    $plain = $meta['plain'];
    $source = $meta['source'];
    if ($plain === '') {
        $candidates = st_integrations_pull_candidate_rows($db, $types);
        st_integrations_pull_auth_failure_log($route, 'missing_token', $source, count($candidates), $types);
        st_json(['ok' => false, 'error' => 'token required'], 401);
    }
    $ctx = st_integrations_pull_resolve_context($db, $route, $plain, $routeOpts);
    if ($ctx === null) {
        $candidates = st_integrations_pull_candidate_rows($db, $types);
        st_integrations_pull_auth_failure_log($route, 'invalid_token', $source, count($candidates), $types);
        st_json(['ok' => false, 'error' => 'invalid token for this endpoint'], 401);
    }
    if (($ctx['integration_id'] ?? 0) > 0) {
        st_integrations_pull_touch_used($db, (int) $ctx['integration_id'], st_integrations_pull_client_ip());
    }

    return $ctx;
}

/**
 * Safe metadata for JSON pull responses.
 *
 * @param array{integration_id:int, integration_name:string, integration_type:string} $ctx
 *
 * @return array{integration_id:int|null, integration_name:string, integration_type:string}
 */
function st_integrations_pull_client_public(array $ctx): array
{
    return [
        'integration_id'   => (int) ($ctx['integration_id'] ?? 0) > 0 ? (int) $ctx['integration_id'] : null,
        'integration_name' => (string) ($ctx['integration_name'] ?? ''),
        'integration_type' => (string) ($ctx['integration_type'] ?? ''),
    ];
}

/**
 * Admin diagnostic: verify a plaintext token against one integration row (never returns token or hash).
 *
 * @return array<string, mixed>
 */
function st_integrations_debug_pull_token_payload(
    PDO $db,
    int $integrationId,
    string $route,
    string $plainToken,
    string $auth_source_detected,
    array $routeOpts = []
): array {
    $row = st_integrations_get_by_id($db, $integrationId);
    $exists = $row !== null;
    $type = $exists ? strtolower(trim((string) ($row['type'] ?? ''))) : '';
    $enabled = $exists ? (int) ($row['enabled'] ?? 0) : 0;
    $hash = $exists ? trim((string) ($row['token_hash'] ?? '')) : '';
    $hashLooksStored = $hash !== '' && str_starts_with($hash, '$');
    $allowed = st_integrations_pull_route_types($route, $routeOpts);
    $routeAllowed = $exists && in_array($type, $allowed, true);
    $hashPrefix = 'none';
    if ($hashLooksStored) {
        $hashPrefix = strlen($hash) <= 16 ? $hash : substr($hash, 0, 16);
    }
    $pv = null;
    if ($plainToken !== '') {
        $pv = $hashLooksStored && password_verify($plainToken, $hash);
    }

    return [
        'integration_exists'      => $exists,
        'integration_id'          => $integrationId,
        'type'                    => $type,
        'enabled'                 => $enabled,
        'token_configured'        => $hashLooksStored,
        'route'                   => $route,
        'route_allowed_for_type'  => $routeAllowed,
        'hash_prefix'             => $hashPrefix,
        'password_verify_result'  => $pv,
        'auth_source_detected'    => $auth_source_detected,
    ];
}

/**
 * Per-integration pull token rotation (plaintext returned once by caller).
 *
 * @return array{ok:bool, token?:string, error?:string}
 */
function st_integrations_pull_token_rotate_for_row(PDO $db, int $id): array
{
    if ($id <= 0) {
        return ['ok' => false, 'error' => 'invalid_id'];
    }
    if (! st_integrations_pull_token_schema_ready($db)) {
        return ['ok' => false, 'error' => 'pull_token_schema_missing'];
    }
    $raw = 'st_int_' . bin2hex(random_bytes(24));
    $hash = password_hash($raw, PASSWORD_DEFAULT);
    if ($hash === false) {
        return ['ok' => false, 'error' => 'hash_failed'];
    }
    $st = $db->prepare(
        'UPDATE integrations SET token_hash = ?, token_created_at = datetime(\'now\'),
            token_last_used_at = NULL, token_last_used_ip = NULL, updated_at = datetime(\'now\')
         WHERE id = ?'
    );
    $st->execute([$hash, $id]);
    if ($st->rowCount() < 1) {
        return ['ok' => false, 'error' => 'not_found'];
    }

    return ['ok' => true, 'token' => $raw];
}

/** Strip secrets for API responses and error_log lines. */
function st_integrations_redact_string(string $s): string
{
    $out = preg_replace('/Splunk\\s+[A-Fa-f0-9\\-]{10,}/', 'Splunk [REDACTED]', $s) ?? $s;
    $out = preg_replace('/Bearer\\s+\\S+/', 'Bearer [REDACTED]', $out) ?? $out;
    $out = preg_replace('/st_int_[a-f0-9]{20,}/i', 'st_int_[REDACTED]', $out) ?? $out;
    $out = preg_replace('/([?&])token=[^&\\s#]+/i', '$1token=[REDACTED]', $out) ?? $out;

    return $out;
}

/**
 * @param array<string,mixed> $row DB row including optional auth_secret
 *
 * @return array<string,mixed>
 */
function st_integrations_row_for_api(array $row): array
{
    unset($row['auth_secret']);
    $type = (string) ($row['type'] ?? '');
    $row['type_label'] = st_integrations_type_display_label($type);
    $row['mode'] = st_integrations_is_pull_type($type) ? 'pull' : 'push';
    $row['destination_summary'] = st_integrations_row_destination_summary($row);

    $row['auth_configured'] = ! empty($row['auth_configured_flag']);
    unset($row['auth_configured_flag']);
    unset($row['token_hash']);
    $isPull = st_integrations_is_pull_type($type);
    $row['token_configured'] = ! empty($row['pull_token_flag']);
    unset($row['pull_token_flag']);
    if (! $isPull) {
        unset($row['token_configured'], $row['token_created_at'], $row['token_last_used_at'], $row['token_last_used_ip']);
    }

    return $row;
}

/**
 * @return list<string>
 */
function st_integrations_list_types_push(): array
{
    return ['splunk_hec', 'syslog', 'webhook', 'loki'];
}

function st_integrations_is_push_type(string $t): bool
{
    return in_array($t, st_integrations_list_types_push(), true);
}

/**
 * @return array<string,mixed>|null
 */
function st_integrations_get_by_id(PDO $db, int $id): ?array
{
    if ($id <= 0 || ! st_sqlite_table_exists($db, 'integrations')) {
        return null;
    }
    $st = $db->prepare(
        'SELECT id, name, type, enabled, endpoint_url, host, port, extra_json, created_at, updated_at,
                last_test_at, last_test_status, last_error,
                token_hash, token_created_at, token_last_used_at, token_last_used_ip,
                CASE WHEN auth_secret IS NOT NULL AND TRIM(auth_secret) != \'\' THEN 1 ELSE 0 END AS auth_configured_flag,
                auth_secret
         FROM integrations WHERE id = ? LIMIT 1'
    );
    $st->execute([$id]);
    $r = $st->fetch(PDO::FETCH_ASSOC);

    return $r !== false ? $r : null;
}

/**
 * @return list<array<string,mixed>>
 */
function st_integrations_list(PDO $db): array
{
    if (! st_sqlite_table_exists($db, 'integrations')) {
        return [];
    }
    $rows = $db->query(
        'SELECT id, name, type, enabled, endpoint_url, host, port, extra_json, created_at, updated_at,
                last_test_at, last_test_status, last_error,
                token_created_at, token_last_used_at, token_last_used_ip,
                CASE WHEN auth_secret IS NOT NULL AND TRIM(auth_secret) != \'\' THEN 1 ELSE 0 END AS auth_configured_flag,
                CASE WHEN token_hash IS NOT NULL AND TRIM(token_hash) != \'\' THEN 1 ELSE 0 END AS pull_token_flag
         FROM integrations ORDER BY id ASC'
    )->fetchAll(PDO::FETCH_ASSOC);
    $out = [];
    foreach ($rows as $r) {
        $out[] = st_integrations_row_for_api($r);
    }

    return $out;
}

function st_integrations_update_test_status(PDO $db, int $id, string $status, ?string $err): void
{
    $db->prepare(
        'UPDATE integrations SET last_test_at = datetime(\'now\'), last_test_status = ?, last_error = ?, updated_at = datetime(\'now\') WHERE id = ?'
    )->execute([$status, $err, $id]);
}

/**
 * Small synthetic canonical event for manual test/sample (never includes secrets).
 *
 * @return array<string,mixed>
 */
function st_integrations_sample_canonical_event(): array
{
    $e = st_reporting_event_canonical_skeleton();
    $e['event_id'] = 'integration:sample:' . bin2hex(random_bytes(8));
    $e['source'] = 'integrations.manual';
    $e['occurred_at'] = gmdate('Y-m-d\TH:i:s\Z');
    $e['event_type'] = 'integration.sample';
    $e['severity'] = 'info';
    $e['scope'] = ['scope_id' => null, 'scope_name' => null];
    $e['subject'] = ['job_id' => null, 'finding_id' => null, 'asset_id' => null];
    $e['data_plane'] = 'live';
    $e['payload'] = [
        'message' => 'SurveyTrace manual integration test payload',
    ];

    return $e;
}

/**
 * Encode canonical event for JSON body.
 */
function st_integrations_json_body(array $canonicalEvent): string
{
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    $body = json_encode($canonicalEvent, $flags);

    return $body !== false ? $body : '{}';
}

/**
 * Manual outbound test for one integration row (best-effort; does not throw).
 *
 * @return array{ok:bool, http_code?:int, detail:string}
 */
function st_integrations_push_send_test(PDO $db, array $row, array $canonicalEvent): array
{
    $type = (string) ($row['type'] ?? '');
    $id = (int) ($row['id'] ?? 0);
    if (! st_integrations_is_push_type($type)) {
        return ['ok' => false, 'detail' => 'not_a_push_integration_type'];
    }
    $body = st_integrations_json_body($canonicalEvent);

    try {
        if ($type === 'webhook') {
            $url = trim((string) ($row['endpoint_url'] ?? ''));
            if ($url === '') {
                return ['ok' => false, 'detail' => 'endpoint_url required'];
            }
            $extra = [];
            $sec = trim((string) ($row['auth_secret'] ?? ''));
            if ($sec !== '') {
                $sig = hash_hmac('sha256', $body, $sec);
                $extra[] = 'X-SurveyTrace-Signature: sha256=' . $sig;
            }
            $res = st_integrations_http_post_json($url, $body, $extra, 4, 10);
            $detail = $res['ok'] ? 'ok' : st_integrations_redact_string($res['error'] ?: ('http ' . $res['http_code']));
            st_integrations_update_test_status($db, $id, $res['ok'] ? 'ok' : 'error', $res['ok'] ? null : substr($detail, 0, 500));

            return ['ok' => $res['ok'], 'http_code' => $res['http_code'], 'detail' => $detail];
        }
        if ($type === 'splunk_hec') {
            $url = trim((string) ($row['endpoint_url'] ?? ''));
            $tok = trim((string) ($row['auth_secret'] ?? ''));
            if ($url === '' || $tok === '') {
                return ['ok' => false, 'detail' => 'endpoint_url and auth_secret (HEC token) required'];
            }
            $wrapped = json_encode(
                ['time' => time(), 'source' => 'surveytrace', 'sourcetype' => '_json', 'event' => $canonicalEvent],
                JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            );
            if ($wrapped === false) {
                $wrapped = '{"event":{}}';
            }
            $extra = ['Authorization: Splunk ' . $tok];
            $res = st_integrations_http_post_json($url, $wrapped, $extra, 4, 10);
            $detail = $res['ok'] ? 'ok' : st_integrations_redact_string($res['error'] ?: ('http ' . $res['http_code']));
            st_integrations_update_test_status($db, $id, $res['ok'] ? 'ok' : 'error', $res['ok'] ? null : substr($detail, 0, 500));

            return ['ok' => $res['ok'], 'http_code' => $res['http_code'], 'detail' => $detail];
        }
        if ($type === 'loki') {
            $url = trim((string) ($row['endpoint_url'] ?? ''));
            if ($url === '') {
                return ['ok' => false, 'detail' => 'endpoint_url required (Loki push URL)'];
            }
            $ns = (string) (int) (microtime(true) * 1_000_000_000);
            $line = str_replace(["\n", "\r"], ' ', $body);
            $streams = [
                'streams' => [
                    [
                        'stream' => ['job' => 'surveytrace', 'integration_id' => (string) $id],
                        'values'  => [[$ns, $line]],
                    ],
                ],
            ];
            $payload = json_encode($streams, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($payload === false) {
                $payload = '{"streams":[]}';
            }
            $extra = [];
            $tok = trim((string) ($row['auth_secret'] ?? ''));
            if ($tok !== '') {
                $extra[] = 'Authorization: Bearer ' . $tok;
            }
            $res = st_integrations_http_post_json($url, $payload, $extra, 4, 10);
            $detail = $res['ok'] ? 'ok' : st_integrations_redact_string($res['error'] ?: ('http ' . $res['http_code']));
            st_integrations_update_test_status($db, $id, $res['ok'] ? 'ok' : 'error', $res['ok'] ? null : substr($detail, 0, 500));

            return ['ok' => $res['ok'], 'http_code' => $res['http_code'], 'detail' => $detail];
        }
        if ($type === 'syslog') {
            $host = trim((string) ($row['host'] ?? ''));
            $port = isset($row['port']) ? (int) $row['port'] : 514;
            if ($host === '' || $port <= 0 || $port > 65535) {
                return ['ok' => false, 'detail' => 'host and valid port required'];
            }
            $pri = 134;
            $ts = gmdate('Y-m-d\TH:i:s\Z');
            $h = php_uname('n');
            if ($h === '' || $h === false) {
                $h = 'surveytrace';
            }
            $msg = '<' . $pri . '>1 ' . $ts . ' ' . $h . ' surveytrace - - - ' . str_replace(["\n", "\r"], ' ', $body);
            if (strlen($msg) > 8000) {
                $msg = substr($msg, 0, 8000) . '…';
            }
            $proto = 'udp';
            $ej = [];
            if (! empty($row['extra_json'])) {
                $d = json_decode((string) $row['extra_json'], true);
                if (is_array($d) && isset($d['syslog_transport']) && strtolower((string) $d['syslog_transport']) === 'tcp') {
                    $proto = 'tcp';
                }
            }
            $ok = false;
            $err = '';
            if ($proto === 'tcp') {
                $fp = @fsockopen($host, $port, $errno, $errstr, 3.0);
                if (is_resource($fp)) {
                    stream_set_timeout($fp, 3);
                    fwrite($fp, $msg . "\n");
                    fclose($fp);
                    $ok = true;
                } else {
                    $err = $errstr !== '' ? $errstr : ('errno ' . $errno);
                }
            } else {
                $fp = @fsockopen('udp://' . $host, $port, $errno, $errstr, 2.0);
                if (is_resource($fp)) {
                    fwrite($fp, $msg);
                    fclose($fp);
                    $ok = true;
                } else {
                    $err = $errstr !== '' ? $errstr : ('errno ' . $errno);
                }
            }
            $detail = $ok ? 'ok' : st_integrations_redact_string($err);
            st_integrations_update_test_status($db, $id, $ok ? 'ok' : 'error', $ok ? null : substr($detail, 0, 500));

            return ['ok' => $ok, 'detail' => $detail];
        }
    } catch (Throwable $e) {
        $m = st_integrations_redact_string(st_integrations_sanitize_exception_message($e));
        st_integrations_update_test_status($db, $id, 'error', substr($m, 0, 500));

        return ['ok' => false, 'detail' => $m];
    }

    return ['ok' => false, 'detail' => 'unknown_type'];
}

/**
 * Latest completed job id for scope filter (null = global latest).
 */
function st_integrations_latest_done_job_id(PDO $db, ?int $scopeFilter): ?int
{
    if (! st_sqlite_table_exists($db, 'scan_jobs')) {
        return null;
    }
    $scopeSql = '';
    $binds = [];
    if (st_scan_scopes_table_scan_jobs_has_scope_id($db) && $scopeFilter !== null) {
        if ($scopeFilter === 0) {
            $scopeSql = ' AND (j.scope_id IS NULL OR j.scope_id = 0) ';
        } elseif ($scopeFilter > 0) {
            $scopeSql = ' AND j.scope_id = ? ';
            $binds[] = $scopeFilter;
        }
    }
    $st = $db->prepare(
        "SELECT j.id FROM scan_jobs j
         WHERE j.status = 'done' AND (j.deleted_at IS NULL OR j.deleted_at = '')
           AND j.finished_at IS NOT NULL
           $scopeSql
         ORDER BY datetime(j.finished_at) DESC, j.id DESC LIMIT 1"
    );
    $st->execute($binds);
    $v = $st->fetchColumn();

    return $v !== false ? (int) $v : null;
}

/**
 * Live inventory + per-scope snapshot gauges as JSON (Infinity / starters). Bounded; `data_plane` is **live**
 * for fleet-wide counts; per-scope rows are latest **snapshot** job in that scope.
 *
 * @return array<string, mixed>
 */
function st_integrations_metrics_snapshot(PDO $db): array
{
    $assets = st_sqlite_table_exists($db, 'assets')
        ? (int) $db->query('SELECT COUNT(*) FROM assets')->fetchColumn()
        : 0;
    $openF = st_sqlite_table_exists($db, 'findings')
        ? (int) $db->query('SELECT COUNT(*) FROM findings WHERE resolved = 0')->fetchColumn()
        : 0;
    $bySev = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'unknown' => 0];
    $bySevProm = [];
    if (st_sqlite_table_exists($db, 'findings')) {
        $q = $db->query(
            "SELECT LOWER(COALESCE(severity,'')) AS sev, COUNT(*) AS c FROM findings WHERE resolved = 0 GROUP BY LOWER(COALESCE(severity,''))"
        );
        foreach ($q->fetchAll(PDO::FETCH_ASSOC) as $r) {
            $k = (string) ($r['sev'] ?? '');
            if ($k === '' || $k === 'null') {
                $k = 'unknown';
            }
            if (! array_key_exists($k, $bySev)) {
                $bySev['unknown'] += (int) ($r['c'] ?? 0);
            } else {
                $bySev[$k] = (int) ($r['c'] ?? 0);
            }
            $sevLabel = preg_replace('/[^a-z0-9_\\-]/', '_', $k) ?: 'unknown';
            $bySevProm[$sevLabel] = (int) ($r['c'] ?? 0);
        }
    }
    $ts = 0;
    if (st_sqlite_table_exists($db, 'scan_jobs')) {
        $raw = $db->query(
            "SELECT finished_at FROM scan_jobs WHERE status = 'done' AND (deleted_at IS NULL OR deleted_at = '') AND finished_at IS NOT NULL ORDER BY datetime(finished_at) DESC, id DESC LIMIT 1"
        )->fetchColumn();
        if (is_string($raw) && $raw !== '') {
            $t = strtotime($raw . ' UTC');
            $ts = $t !== false ? $t : 0;
        }
    }
    $scopes = [];
    if (st_sqlite_table_exists($db, 'scan_scopes') && st_scan_scopes_table_scan_jobs_has_scope_id($db)) {
        $ids = $db->query('SELECT id FROM scan_scopes ORDER BY id ASC LIMIT 25')->fetchAll(PDO::FETCH_COLUMN);
        foreach ($ids as $sidRaw) {
            $sid = (int) $sidRaw;
            $jid = st_integrations_latest_done_job_id($db, $sid);
            $ac = 0;
            $fc = 0;
            if ($jid !== null && $jid > 0) {
                if (st_sqlite_table_exists($db, 'scan_asset_snapshots')) {
                    $aSt = $db->prepare('SELECT COUNT(*) FROM scan_asset_snapshots WHERE job_id = ?');
                    $aSt->execute([$jid]);
                    $ac = (int) $aSt->fetchColumn();
                }
                if (st_sqlite_table_exists($db, 'scan_finding_snapshots')) {
                    $fSt = $db->prepare(
                        'SELECT COUNT(*) FROM scan_finding_snapshots WHERE job_id = ? AND COALESCE(resolved,0) = 0'
                    );
                    $fSt->execute([$jid]);
                    $fc = (int) $fSt->fetchColumn();
                }
            }
            $scopes[] = [
                'scope_id'               => $sid,
                'scope_name'             => st_scan_scopes_resolve_name($db, $sid),
                'latest_done_job_id'     => ($jid !== null && $jid > 0) ? $jid : null,
                'snapshot_asset_count'   => $ac,
                'snapshot_open_findings' => $fc,
            ];
        }
    }

    return [
        'schema_version'             => 'surveytrace.integrations.metrics.v1',
        'generated_at'               => gmdate('Y-m-d\TH:i:s\Z'),
        'data_plane'                 => 'live',
        'scope_id'                   => null,
        'scope_name'                 => null,
        'assets_total'               => $assets,
        'open_findings_total'        => $openF,
        'open_findings_by_severity'  => $bySev,
        'open_findings_by_severity_raw' => $bySevProm,
        'last_scan_finished_unix'    => $ts,
        'scopes'                     => $scopes,
    ];
}

/**
 * Prometheus text exposition (bounded queries).
 */
function st_integrations_prometheus_text(PDO $db): string
{
    $snap = st_integrations_metrics_snapshot($db);
    $lines = [];
    $lines[] = '# HELP surveytrace_assets_total Assets in live inventory table.';
    $lines[] = '# TYPE surveytrace_assets_total gauge';
    $lines[] = 'surveytrace_assets_total ' . (int) ($snap['assets_total'] ?? 0);

    $lines[] = '# HELP surveytrace_open_findings_total Open findings (resolved=0).';
    $lines[] = '# TYPE surveytrace_open_findings_total gauge';
    $lines[] = 'surveytrace_open_findings_total ' . (int) ($snap['open_findings_total'] ?? 0);

    $lines[] = '# HELP surveytrace_open_findings_by_severity Open findings by severity label.';
    $lines[] = '# TYPE surveytrace_open_findings_by_severity gauge';
    foreach ($snap['open_findings_by_severity_raw'] ?? [] as $sev => $cnt) {
        $label = preg_replace('/[^a-z0-9_\\-]/', '_', (string) $sev) ?: 'unknown';
        $lines[] = 'surveytrace_open_findings_by_severity{severity="' . $label . '"} ' . (int) $cnt;
    }

    $lines[] = '# HELP surveytrace_last_scan_timestamp Unix time of latest finished scan (UTC).';
    $lines[] = '# TYPE surveytrace_last_scan_timestamp gauge';
    $lines[] = 'surveytrace_last_scan_timestamp ' . (int) ($snap['last_scan_finished_unix'] ?? 0);

    $lines[] = '# HELP surveytrace_scope_assets_total Asset snapshot rows on the latest completed job per scope (max 25 scopes).';
    $lines[] = '# TYPE surveytrace_scope_assets_total gauge';
    $lines[] = '# HELP surveytrace_scope_open_findings_total Open finding snapshots on that same latest per-scope job.';
    $lines[] = '# TYPE surveytrace_scope_open_findings_total gauge';

    foreach ($snap['scopes'] ?? [] as $sc) {
        $sid = (int) ($sc['scope_id'] ?? 0);
        $lines[] = 'surveytrace_scope_assets_total{scope_id="' . $sid . '"} ' . (int) ($sc['snapshot_asset_count'] ?? 0);
        $lines[] = 'surveytrace_scope_open_findings_total{scope_id="' . $sid . '"} ' . (int) ($sc['snapshot_open_findings'] ?? 0);
    }

    return implode("\n", $lines) . "\n";
}

/**
 * Export integration events: change_alerts + recent report artifacts (bounded).
 *
 * @return list<array<string,mixed>>
 */
function st_integrations_events_export(PDO $db, string $sinceSql, int $limit): array
{
    $limit = max(1, min(500, $limit));
    $out = [];
    if (st_sqlite_table_exists($db, 'change_alerts')) {
        $st = $db->prepare(
            "SELECT c.id, c.created_at, c.alert_type, c.job_id, c.asset_id, c.finding_id, c.detail_json,
                    c.dismissed_at, a.ip AS asset_ip
             FROM change_alerts c
             LEFT JOIN assets a ON a.id = c.asset_id
             WHERE datetime(c.created_at) >= datetime(?)
             ORDER BY c.id ASC
             LIMIT " . (int) $limit
        );
        $st->execute([$sinceSql]);
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
            $dj = [];
            if (! empty($r['detail_json'])) {
                $decoded = json_decode((string) $r['detail_json'], true);
                $dj = is_array($decoded) ? $decoded : [];
            }
            $apiRow = [
                'id'         => (int) $r['id'],
                'created_at' => (string) ($r['created_at'] ?? ''),
                'alert_type' => (string) ($r['alert_type'] ?? ''),
                'job_id'     => (int) ($r['job_id'] ?? 0),
                'asset_id'   => $r['asset_id'] !== null ? (int) $r['asset_id'] : null,
                'finding_id' => $r['finding_id'] !== null ? (int) $r['finding_id'] : null,
                'detail'     => $dj,
                'asset_ip'   => (string) ($r['asset_ip'] ?? ''),
                'dismissed_at' => $r['dismissed_at'] ? (string) $r['dismissed_at'] : null,
            ];
            $out[] = st_reporting_event_from_change_alert_row($apiRow);
        }
    }
    $remain = $limit - count($out);
    if ($remain > 0 && st_sqlite_table_exists($db, 'report_artifacts')) {
        $st = $db->prepare(
            "SELECT id, created_at, schedule_id, baseline_job_id, compare_job_id, title
             FROM report_artifacts
             WHERE datetime(created_at) >= datetime(?)
             ORDER BY id ASC LIMIT " . (int) $remain
        );
        $st->execute([$sinceSql]);
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
            $out[] = st_reporting_event_from_report_artifact_row($r);
        }
    }

    return $out;
}

function st_integrations_sanitize_exception_message(Throwable $e): string
{
    $m = preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $e->getMessage());
    if ($m === null || $m === '') {
        return $e::class;
    }
    if (strlen($m) > 500) {
        return substr($m, 0, 500) . '…';
    }

    return $m;
}
