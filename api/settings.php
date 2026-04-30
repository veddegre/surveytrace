<?php
/**
 * SurveyTrace — /api/settings.php
 *
 * GET  — UI settings (requires auth when password is configured)
 * POST — update settings
 *   body may include:
 *   - session_timeout_minutes: int (5..10080)
 *   - extra_safe_ports: comma/space separated ports (1..65535)
 *   - db_backup_enabled: bool
 *   - db_backup_cron: cron expression (5-field or @preset)
 *   - db_backup_retention_days: int (1..365)
 *   - db_backup_keep_count: int (1..500)
 *   - ai_enrichment_enabled: bool
 *   - ai_provider: string (ollama | openai | anthropic | google | openwebui)
 *   - ai_openai_api_key / ai_anthropic_api_key / ai_gemini_api_key — optional; env OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY or GOOGLE_API_KEY overrides DB
 *   - ai_openwebui_base_url — http(s) origin of Open WebUI (no trailing slash required); env OPENWEBUI_BASE_URL overrides DB
 *   - ai_openwebui_api_key — Bearer token for Open WebUI API; env OPENWEBUI_API_KEY overrides DB
 *   - security_allow_private_outbound_targets: bool (default false; allow private/loopback OIDC/OpenWebUI endpoints)
 *   - ai_model: string (Ollama tag, e.g. phi3:mini)
 *   - ai_timeout_ms: int (100..5000)
 *   - ai_operator_ollama_timeout_s: int (120..3600) — UI host summary / scan AI refresh Ollama wall clock
 *   - ai_operator_ollama_num_predict: int (0..8192) — Ollama num_predict; 0 = omit (model default, slower)
 *   - ai_operator_ollama_temperature: float (0..2)
 *   - ai_operator_prompt_banner_max_lines / val_max / max_chars — host AI prompt size (smaller = faster)
 *   - ai_operator_ollama_num_thread: int (0..256) — Ollama num_thread; 0 = auto
 *   - ai_operator_ollama_num_ctx: int (0 or 512..131072) — Ollama num_ctx; 0 = model default (lower = faster CPU prefill; too low truncates long prompts)
 *   - ai_max_hosts_per_scan: int (1..5000)
 *   - ai_ambiguous_only: bool
 *   - ai_suggest_only: bool
 *   - ai_conflict_only: bool
 *   - ai_conf_threshold: float (0.50..0.99)
 *   - ai_conf_threshold_net_srv: float (0.50..0.99)
 *   - ai_install_ollama: truthy — attempt local Ollama install/start
 *   - ai_pull_model: string — pull a model with ollama pull
 *   - nvd_api_key: string (optional; NIST UUID key, 30–128 chars) — saved only when no key exists yet; never returned on GET
 *   - nvd_api_key_remove: truthy — clears stored key (required before saving a replacement from the UI)
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_ai_cloud.php';

st_auth();
st_require_role(['admin']);

function st_shell_available_for_settings(): bool {
    $df = (string)ini_get('disable_functions');
    if ($df === '') return true;
    $parts = array_map('trim', explode(',', $df));
    return !in_array('exec', $parts, true) && !in_array('shell_exec', $parts, true);
}

function st_cmd_available(string $cmd): bool {
    if (!st_shell_available_for_settings()) return false;
    $out = @shell_exec('command -v ' . escapeshellarg($cmd) . ' 2>/dev/null');
    return is_string($out) && trim($out) !== '';
}

function st_ollama_api_tags(): array {
    $url = 'http://127.0.0.1:11434/api/tags';
    $raw = '';
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if (defined('CURLOPT_NOSIGNAL')) {
            curl_setopt($ch, CURLOPT_NOSIGNAL, true);
        }
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        $res = curl_exec($ch);
        if (is_string($res)) {
            $raw = $res;
        }
        curl_close($ch);
    }
    if ($raw === '') {
        $ctx = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 2,
            ],
        ]);
        $res = @file_get_contents($url, false, $ctx);
        if (is_string($res)) {
            $raw = $res;
        }
    }
    if ($raw === '') return [];
    $doc = json_decode($raw, true);
    if (!is_array($doc) || !isset($doc['models']) || !is_array($doc['models'])) return [];
    $mods = [];
    foreach ($doc['models'] as $m) {
        if (!is_array($m)) continue;
        $name = trim((string)($m['name'] ?? ''));
        if ($name !== '') $mods[] = $name;
    }
    return array_values(array_unique($mods));
}

function st_ollama_runtime_status(): array {
    $installed = st_cmd_available('ollama');
    $running = false;
    $version = '';
    $models = [];
    $apiModels = st_ollama_api_tags();
    if ($apiModels) {
        $running = true;
        $models = $apiModels;
    } elseif ($installed && st_shell_available_for_settings()) {
        $vout = @shell_exec('ollama --version 2>/dev/null');
        if (is_string($vout)) {
            $version = trim($vout);
        }
        $rows = [];
        $code = 1;
        @exec('ollama list 2>&1', $rows, $code);
        if ($code === 0) {
            $running = true;
            foreach ($rows as $idx => $line) {
                if ($idx === 0 && stripos((string)$line, 'NAME') !== false) {
                    continue;
                }
                $line = trim((string)$line);
                if ($line === '') continue;
                $parts = preg_split('/\s+/', $line);
                if (!$parts || !$parts[0]) continue;
                $models[] = (string)$parts[0];
            }
        }
    }
    if ($version === '' && $installed && st_shell_available_for_settings()) {
        $vout = @shell_exec('ollama --version 2>/dev/null');
        if (is_string($vout)) {
            $version = trim($vout);
        }
    }
    if (!$installed && $running) {
        // Runtime is reachable (likely system service), even if CLI is unavailable in PATH for PHP.
        $installed = true;
    }
    $cfgModel = trim((string)st_config('ai_model', 'phi3:mini'));
    if ($cfgModel === '') $cfgModel = 'phi3:mini';
    $modelInstalled = in_array($cfgModel, $models, true);
    return [
        'installed' => $installed,
        'running' => $running,
        'version' => $version,
        'models' => array_values(array_unique($models)),
        'compact_recommended_model' => 'phi3:mini',
        'update' => st_ollama_update_status($version),
        'model_update' => [
            'configured_model' => $cfgModel,
            'installed' => $modelInstalled,
            'known' => $installed && $running,
            'update_available' => $modelInstalled, // refresh available via pull
            'shell_update_command' => 'ollama pull ' . escapeshellarg($cfgModel),
            'detail' => $modelInstalled
                ? 'Configured model is installed. Run pull to refresh to latest model data.'
                : 'Configured model is not installed yet.',
        ],
    ];
}

function st_ollama_parse_version(string $raw): string {
    if (preg_match('/(\d+\.\d+\.\d+)/', $raw, $m)) {
        return $m[1];
    }
    return '';
}

function st_ollama_latest_release_version(): string {
    $url = 'https://api.github.com/repos/ollama/ollama/releases/latest';
    $json = '';
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['User-Agent: SurveyTrace']);
        $res = curl_exec($ch);
        if (is_string($res)) {
            $json = $res;
        }
        curl_close($ch);
    }
    if ($json === '') {
        $ctx = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 3,
                'header' => "User-Agent: SurveyTrace\r\n",
            ],
        ]);
        $res = @file_get_contents($url, false, $ctx);
        if (is_string($res)) {
            $json = $res;
        }
    }
    if ($json === '') return '';
    $doc = json_decode($json, true);
    if (!is_array($doc)) return '';
    $tag = trim((string)($doc['tag_name'] ?? ''));
    return st_ollama_parse_version($tag);
}

function st_ollama_update_status(string $localVersionRaw): array {
    $local = st_ollama_parse_version($localVersionRaw);
    if ($local === '') {
        return [
            'known' => false,
            'update_available' => false,
            'local_version' => '',
            'latest_version' => '',
            'shell_update_command' => '',
            'detail' => 'Local version unavailable',
        ];
    }
    $latest = st_ollama_latest_release_version();
    if ($latest === '') {
        return [
            'known' => false,
            'update_available' => false,
            'local_version' => $local,
            'latest_version' => '',
            'shell_update_command' => '',
            'detail' => 'Could not reach update source',
        ];
    }
    $avail = version_compare($latest, $local, '>');
    return [
        'known' => true,
        'update_available' => $avail,
        'local_version' => $local,
        'latest_version' => $latest,
        'shell_update_command' => $avail
            ? 'curl -fsSL https://ollama.com/install.sh | sh && sudo systemctl restart ollama'
            : '',
        'detail' => $avail ? 'Update available' : 'Up to date',
    ];
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    $mode = strtolower(trim(st_config('auth_mode', 'session')));
    if ($mode === 'saml') {
        $mode = 'oidc';
    }
    if (!in_array($mode, ['basic', 'session', 'oidc'], true)) {
        $mode = 'session';
    }
    $m = max(5, min(10080, (int)st_config('session_timeout_minutes', '480')));
    $extra = trim((string)st_config('extra_safe_ports', ''));
    $nvdKey = trim((string)st_config('nvd_api_key', ''));
    $dbBackupEnabled = st_config('db_backup_enabled', '0') === '1';
    $dbBackupCron = trim((string)st_config('db_backup_cron', '15 2 * * *'));
    if ($dbBackupCron === '') $dbBackupCron = '15 2 * * *';
    $dbBackupRetention = max(1, min(365, (int)st_config('db_backup_retention_days', '14')));
    $dbBackupKeepCount = max(1, min(500, (int)st_config('db_backup_keep_count', '30')));
    $dbBackupLastRun = trim((string)st_config('db_backup_last_run', ''));
    $dbBackupLastStatus = trim((string)st_config('db_backup_last_status', ''));
    $dbBackupLastPath = trim((string)st_config('db_backup_last_path', ''));
    $dbBackupLastError = trim((string)st_config('db_backup_last_error', ''));
    $ai = st_ollama_runtime_status();
    $aiOllamaNumCtx = (int)st_config('ai_operator_ollama_num_ctx', '0');
    if ($aiOllamaNumCtx !== 0 && ($aiOllamaNumCtx < 512 || $aiOllamaNumCtx > 131072)) {
        $aiOllamaNumCtx = 0;
    }
    st_json([
        'ok' => true,
        'session_timeout_minutes' => $m,
        'extra_safe_ports' => $extra,
        'auth_mode' => $mode,
        'oidc_enabled' => st_config('oidc_enabled', '0') === '1',
        'oidc_issuer_url' => (string)st_config('oidc_issuer_url', ''),
        'oidc_client_id' => (string)st_config('oidc_client_id', ''),
        'oidc_redirect_uri' => (string)st_config('oidc_redirect_uri', ''),
        'oidc_role_claim' => (string)st_config('oidc_role_claim', 'groups'),
        'oidc_role_map' => (string)st_config('oidc_role_map', ''),
        'sso_role_source' => (string)st_config('sso_role_source', 'surveytrace'),
        'breakglass_enabled' => st_config('breakglass_enabled', '1') === '1',
        'breakglass_username' => (string)st_config('breakglass_username', 'admin'),
        'security_allow_private_outbound_targets' => st_config('security_allow_private_outbound_targets', '0') === '1',
        'password_policy' => st_password_policy(),
        'password_hash_algo' => st_password_hash_algo(),
        'login_max_attempts' => st_login_max_attempts(),
        'login_lockout_minutes' => st_login_lockout_minutes(),
        'db_backup_enabled' => $dbBackupEnabled,
        'db_backup_cron' => $dbBackupCron,
        'db_backup_retention_days' => $dbBackupRetention,
        'db_backup_keep_count' => $dbBackupKeepCount,
        'db_backup_last_run' => $dbBackupLastRun,
        'db_backup_last_status' => $dbBackupLastStatus,
        'db_backup_last_path' => $dbBackupLastPath,
        'db_backup_last_error' => $dbBackupLastError,
        'ai_enrichment_enabled' => st_config('ai_enrichment_enabled', '0') === '1',
        'ai_provider' => (string)st_config('ai_provider', 'ollama'),
        'ai_model' => (string)st_config('ai_model', 'phi3:mini'),
        'ai_timeout_ms' => max(100, min(5000, (int)st_config('ai_timeout_ms', '700'))),
        'ai_operator_ollama_timeout_s' => st_ai_operator_ollama_timeout_cap(),
        'ai_operator_ollama_num_predict' => max(0, min(8192, (int)st_config('ai_operator_ollama_num_predict', '768'))),
        'ai_operator_ollama_temperature' => max(0.0, min(2.0, (float)st_config('ai_operator_ollama_temperature', '0.25'))),
        'ai_operator_prompt_banner_max_lines' => max(12, min(200, (int)st_config('ai_operator_prompt_banner_max_lines', '72'))),
        'ai_operator_prompt_banner_val_max' => max(40, min(240, (int)st_config('ai_operator_prompt_banner_val_max', '96'))),
        'ai_operator_prompt_banner_max_chars' => max(2000, min(20000, (int)st_config('ai_operator_prompt_banner_max_chars', '8000'))),
        'ai_operator_ollama_num_thread' => max(0, min(256, (int)st_config('ai_operator_ollama_num_thread', '0'))),
        'ai_operator_ollama_num_ctx' => $aiOllamaNumCtx,
        'ai_max_hosts_per_scan' => max(1, min(5000, (int)st_config('ai_max_hosts_per_scan', '40'))),
        'ai_ambiguous_only' => st_config('ai_ambiguous_only', '1') === '1',
        'ai_suggest_only' => st_config('ai_suggest_only', '0') === '1',
        'ai_conflict_only' => st_config('ai_conflict_only', '1') === '1',
        'ai_conf_threshold' => max(0.50, min(0.99, (float)st_config('ai_conf_threshold', '0.72'))),
        'ai_conf_threshold_net_srv' => max(0.50, min(0.99, (float)st_config('ai_conf_threshold_net_srv', '0.82'))),
        'ai_runtime' => $ai,
        'scan_trash_retention_days' => max(1, min(365, (int)st_config('scan_trash_retention_days', '30'))),
        'nvd_api_key_configured' => $nvdKey !== '',
        'ai_openai_key_configured' => trim((string)(getenv('OPENAI_API_KEY') ?: '')) !== ''
            || trim((string)st_config('ai_openai_api_key', '')) !== '',
        'ai_anthropic_key_configured' => trim((string)(getenv('ANTHROPIC_API_KEY') ?: '')) !== ''
            || trim((string)st_config('ai_anthropic_api_key', '')) !== '',
        'ai_gemini_key_configured' => trim((string)(getenv('GEMINI_API_KEY') ?: getenv('GOOGLE_API_KEY') ?: '')) !== ''
            || trim((string)st_config('ai_gemini_api_key', '')) !== '',
        'ai_openwebui_base_url' => st_ai_resolve_openwebui_base(),
        'ai_openwebui_key_configured' => trim((string)(getenv('OPENWEBUI_API_KEY') ?: '')) !== ''
            || trim((string)st_config('ai_openwebui_api_key', '')) !== '',
        'collector_install_token_configured' => trim((string)st_config('collector_install_token', '')) !== '',
        'collector_token_ttl_hours' => max(1, min(24 * 365, (int)st_config('collector_token_ttl_hours', '720'))),
        'collector_lease_seconds' => max(60, min(3600, (int)st_config('collector_lease_seconds', '600'))),
        'collector_rate_default_rps' => max(1, min(50, (int)st_config('collector_rate_default_rps', '5'))),
        'collector_submit_max_mb' => max(1, min(256, (int)st_config('collector_submit_max_mb', '8'))),
        'collector_artifact_store' => (string)st_config('collector_artifact_store', 's3'),
        'collector_artifact_s3_endpoint' => (string)st_config('collector_artifact_s3_endpoint', ''),
        'collector_artifact_s3_bucket' => (string)st_config('collector_artifact_s3_bucket', ''),
        'collector_artifact_s3_region' => (string)st_config('collector_artifact_s3_region', 'us-east-1'),
        'collector_artifact_s3_access_key_configured' => trim((string)st_config('collector_artifact_s3_access_key', '')) !== '',
        'collector_artifact_s3_secret_key_configured' => trim((string)st_config('collector_artifact_s3_secret_key', '')) !== '',
        'collector_artifact_s3_prefix' => (string)st_config('collector_artifact_s3_prefix', 'surveytrace/collector-artifacts'),
        'collector_artifact_s3_path_style' => st_config('collector_artifact_s3_path_style', '1') === '1',
        'collector_artifact_s3_tls_verify' => st_config('collector_artifact_s3_tls_verify', '1') === '1',
    ]);
}

st_method('POST');
$body = st_input();
$changed = [];
$dbBackupBefore = [
    'enabled' => st_config('db_backup_enabled', '0') === '1',
    'cron' => trim((string)st_config('db_backup_cron', '15 2 * * *')),
    'retention_days' => max(1, min(365, (int)st_config('db_backup_retention_days', '14'))),
    'keep_count' => max(1, min(500, (int)st_config('db_backup_keep_count', '30'))),
];

if (!empty($body['db_backup_run_now'])) {
    $script = realpath(__DIR__ . '/../daemon/backup_db.sh');
    if (!$script || !is_file($script)) {
        st_json(['error' => 'Backup script not found'], 500);
    }
    $cmd = 'bash ' . escapeshellarg($script) . ' 2>&1';
    $out = [];
    $code = 0;
    @exec($cmd, $out, $code);
    $last = trim((string)($out ? end($out) : ''));
    $ts = gmdate('Y-m-d H:i:s');
    st_config_set('db_backup_last_run', $ts);
    if ($code === 0) {
        st_config_set('db_backup_last_status', 'ok');
        st_config_set('db_backup_last_path', $last);
        st_config_set('db_backup_last_error', '');
        st_audit_log('db.backup_run_manual', null, null, null, null, [
            'status' => 'ok',
            'path' => $last,
        ]);
        st_json([
            'ok' => true,
            'db_backup_last_run' => $ts,
            'db_backup_last_status' => 'ok',
            'db_backup_last_path' => $last,
        ]);
    }
    $err = trim((string)implode("\n", $out));
    if ($err === '') $err = 'Backup command failed';
    st_config_set('db_backup_last_status', 'error');
    st_config_set('db_backup_last_error', substr($err, 0, 500));
    st_audit_log('db.backup_run_manual', null, null, null, null, [
        'status' => 'error',
        'error' => substr($err, 0, 500),
    ]);
    st_json(['error' => 'Backup failed: ' . substr($err, 0, 220)], 500);
}

if (!empty($body['ai_install_ollama'])) {
    st_json([
        'error' => 'In-app install is disabled. Run install from server shell.',
        'shell_install_command' => 'curl -fsSL https://ollama.com/install.sh | sh',
    ], 400);
}

if (!empty($body['ai_check_updates'])) {
    $changed['ai_runtime'] = st_ollama_runtime_status();
    $changed['ai_check_updates'] = true;
}

if (array_key_exists('ai_pull_model', $body)) {
    $model = trim((string)$body['ai_pull_model']);
    if ($model === '') {
        st_json(['error' => 'ai_pull_model cannot be empty'], 400);
    }
    if (!preg_match('/^[A-Za-z0-9._:-]{2,120}$/', $model)) {
        st_json(['error' => 'Invalid model tag format'], 400);
    }
    if (!st_cmd_available('ollama')) {
        st_json(['error' => 'Ollama is not installed on this server yet'], 400);
    }
    if (!st_shell_available_for_settings()) {
        st_json(['error' => 'Command execution is disabled in PHP (exec/shell_exec).'], 503);
    }
    @set_time_limit(0);
    $out = [];
    $code = 1;
    @exec('ollama pull ' . escapeshellarg($model) . ' 2>&1', $out, $code);
    if ($code !== 0) {
        st_json(['error' => 'ollama pull failed', 'output' => array_slice($out, -12)], 500);
    }
    st_config_set('ai_model', $model);
    $changed['ai_model'] = $model;
    $changed['ai_runtime'] = st_ollama_runtime_status();
}

if (array_key_exists('session_timeout_minutes', $body)) {
    $m = (int)$body['session_timeout_minutes'];
    $m = max(5, min(10080, $m));
    st_config_set('session_timeout_minutes', (string)$m);
    $changed['session_timeout_minutes'] = $m;
}

if (array_key_exists('extra_safe_ports', $body)) {
    $raw = (string)$body['extra_safe_ports'];
    $tokens = preg_split('/[\s,]+/', $raw) ?: [];
    $ports = [];
    foreach ($tokens as $t) {
        $t = trim($t);
        if ($t === '') continue;
        if (!preg_match('/^\d+$/', $t)) {
            st_json(['error' => "invalid port token: $t"], 400);
        }
        $p = (int)$t;
        if ($p < 1 || $p > 65535) {
            st_json(['error' => "port out of range: $p"], 400);
        }
        $ports[$p] = true; // dedupe
    }
    $norm = implode(',', array_keys($ports));
    st_config_set('extra_safe_ports', $norm);
    $changed['extra_safe_ports'] = $norm;
}

if (array_key_exists('auth_mode', $body)) {
    $mode = strtolower(trim((string)$body['auth_mode']));
    if ($mode === 'saml') {
        $mode = 'oidc';
    }
    if (!in_array($mode, ['basic', 'session', 'oidc'], true)) {
        st_json(['error' => 'auth_mode must be one of basic, session, oidc'], 400);
    }
    st_config_set('auth_mode', $mode);
    $changed['auth_mode'] = $mode;
}

if (array_key_exists('oidc_enabled', $body)) {
    $changed['oidc_enabled'] = !empty($body['oidc_enabled']);
    st_config_set('oidc_enabled', $changed['oidc_enabled'] ? '1' : '0');
}
foreach (['oidc_issuer_url', 'oidc_client_id', 'oidc_client_secret', 'oidc_redirect_uri', 'oidc_role_claim', 'oidc_role_map'] as $k) {
    if (array_key_exists($k, $body)) {
        $v = trim((string)$body[$k]);
        if ($k === 'oidc_role_map' && strlen($v) > 8192) {
            st_json(['error' => 'oidc_role_map is too long (max 8192 chars)'], 400);
        }
        st_config_set($k, $v);
        if ($k !== 'oidc_client_secret') {
            $changed[$k] = $v;
        } else {
            $changed['oidc_client_secret_configured'] = ($v !== '');
        }
    }
}
if (array_key_exists('sso_role_source', $body)) {
    $v = strtolower(trim((string)$body['sso_role_source']));
    if (!in_array($v, ['surveytrace', 'idp'], true)) {
        st_json(['error' => 'sso_role_source must be surveytrace or idp'], 400);
    }
    st_config_set('sso_role_source', $v);
    $changed['sso_role_source'] = $v;
}

if (array_key_exists('breakglass_enabled', $body)) {
    $changed['breakglass_enabled'] = !empty($body['breakglass_enabled']);
    st_config_set('breakglass_enabled', $changed['breakglass_enabled'] ? '1' : '0');
}
if (array_key_exists('breakglass_username', $body)) {
    $v = trim((string)$body['breakglass_username']);
    if ($v === '') $v = 'admin';
    st_config_set('breakglass_username', $v);
    $changed['breakglass_username'] = $v;
}
if (array_key_exists('security_allow_private_outbound_targets', $body)) {
    $v = !empty($body['security_allow_private_outbound_targets']);
    st_config_set('security_allow_private_outbound_targets', $v ? '1' : '0');
    $changed['security_allow_private_outbound_targets'] = $v;
}
if (array_key_exists('collector_token_ttl_hours', $body)) {
    $v = max(1, min(24 * 365, (int)$body['collector_token_ttl_hours']));
    st_config_set('collector_token_ttl_hours', (string)$v);
    $changed['collector_token_ttl_hours'] = $v;
}
if (array_key_exists('collector_lease_seconds', $body)) {
    $v = max(60, min(3600, (int)$body['collector_lease_seconds']));
    st_config_set('collector_lease_seconds', (string)$v);
    $changed['collector_lease_seconds'] = $v;
}
if (array_key_exists('collector_rate_default_rps', $body)) {
    $v = max(1, min(50, (int)$body['collector_rate_default_rps']));
    st_config_set('collector_rate_default_rps', (string)$v);
    $changed['collector_rate_default_rps'] = $v;
}
if (array_key_exists('collector_submit_max_mb', $body)) {
    $v = max(1, min(256, (int)$body['collector_submit_max_mb']));
    st_config_set('collector_submit_max_mb', (string)$v);
    $changed['collector_submit_max_mb'] = $v;
}
if (array_key_exists('collector_install_token', $body)) {
    $v = trim((string)$body['collector_install_token']);
    st_config_set('collector_install_token', $v);
    $changed['collector_install_token_configured'] = ($v !== '');
}
if (!empty($body['collector_install_token_generate'])) {
    $v = 'st_install_' . bin2hex(random_bytes(24));
    st_config_set('collector_install_token', $v);
    $changed['collector_install_token_configured'] = true;
    $changed['collector_install_token_generated'] = true;
    $changed['collector_install_token'] = $v;
}
if (array_key_exists('collector_artifact_store', $body)) {
    $v = strtolower(trim((string)$body['collector_artifact_store']));
    if (!in_array($v, ['s3'], true)) {
        st_json(['error' => 'collector_artifact_store must be s3'], 400);
    }
    st_config_set('collector_artifact_store', $v);
    $changed['collector_artifact_store'] = $v;
}
foreach ([
    'collector_artifact_s3_endpoint',
    'collector_artifact_s3_bucket',
    'collector_artifact_s3_region',
    'collector_artifact_s3_prefix',
] as $k) {
    if (array_key_exists($k, $body)) {
        $v = trim((string)$body[$k]);
        st_config_set($k, $v);
        $changed[$k] = $v;
    }
}
if (array_key_exists('collector_artifact_s3_path_style', $body)) {
    $v = !empty($body['collector_artifact_s3_path_style']);
    st_config_set('collector_artifact_s3_path_style', $v ? '1' : '0');
    $changed['collector_artifact_s3_path_style'] = $v;
}
if (array_key_exists('collector_artifact_s3_tls_verify', $body)) {
    $v = !empty($body['collector_artifact_s3_tls_verify']);
    st_config_set('collector_artifact_s3_tls_verify', $v ? '1' : '0');
    $changed['collector_artifact_s3_tls_verify'] = $v;
}
if (array_key_exists('collector_artifact_s3_access_key', $body)) {
    $v = trim((string)$body['collector_artifact_s3_access_key']);
    st_config_set('collector_artifact_s3_access_key', $v);
    $changed['collector_artifact_s3_access_key_configured'] = ($v !== '');
}
if (array_key_exists('collector_artifact_s3_secret_key', $body)) {
    $v = trim((string)$body['collector_artifact_s3_secret_key']);
    st_config_set('collector_artifact_s3_secret_key', $v);
    $changed['collector_artifact_s3_secret_key_configured'] = ($v !== '');
}

if (array_key_exists('password_policy', $body)) {
    $pp = is_array($body['password_policy']) ? $body['password_policy'] : [];
    $minLen = (int)($pp['min_length'] ?? st_password_policy()['min_length']);
    $minLen = max(8, min(128, $minLen));
    $reqUpper = !empty($pp['require_upper']);
    $reqLower = !empty($pp['require_lower']);
    $reqNumber = !empty($pp['require_number']);
    $reqSymbol = !empty($pp['require_symbol']);
    st_config_set('password_min_length', (string)$minLen);
    st_config_set('password_require_upper', $reqUpper ? '1' : '0');
    st_config_set('password_require_lower', $reqLower ? '1' : '0');
    st_config_set('password_require_number', $reqNumber ? '1' : '0');
    st_config_set('password_require_symbol', $reqSymbol ? '1' : '0');
    $changed['password_policy'] = st_password_policy();
}

if (array_key_exists('password_hash_algo', $body)) {
    $algo = strtolower(trim((string)$body['password_hash_algo']));
    if (!in_array($algo, ['argon2id', 'bcrypt'], true)) {
        st_json(['error' => 'password_hash_algo must be argon2id or bcrypt'], 400);
    }
    if ($algo === 'argon2id' && !defined('PASSWORD_ARGON2ID')) {
        st_json(['error' => 'Argon2id is not available on this PHP build'], 400);
    }
    st_config_set('password_hash_algo', $algo);
    $changed['password_hash_algo'] = st_password_hash_algo();
}

if (array_key_exists('login_max_attempts', $body)) {
    $v = (int)$body['login_max_attempts'];
    $v = max(3, min(20, $v));
    st_config_set('login_max_attempts', (string)$v);
    $changed['login_max_attempts'] = $v;
}
if (array_key_exists('login_lockout_minutes', $body)) {
    $v = (int)$body['login_lockout_minutes'];
    $v = max(1, min(1440, $v));
    st_config_set('login_lockout_minutes', (string)$v);
    $changed['login_lockout_minutes'] = $v;
}

if (array_key_exists('scan_trash_retention_days', $body)) {
    $v = (int)$body['scan_trash_retention_days'];
    $v = max(1, min(365, $v));
    st_config_set('scan_trash_retention_days', (string)$v);
    $changed['scan_trash_retention_days'] = $v;
    $actor = st_current_user();
    st_audit_log(
        'scan.trash_retention_updated',
        (int)($actor['id'] ?? 0),
        (string)($actor['username'] ?? ''),
        null,
        null,
        ['days' => $v]
    );
}

if (array_key_exists('db_backup_enabled', $body)) {
    $v = !empty($body['db_backup_enabled']);
    st_config_set('db_backup_enabled', $v ? '1' : '0');
    $changed['db_backup_enabled'] = $v;
}
if (array_key_exists('db_backup_cron', $body)) {
    $v = trim((string)$body['db_backup_cron']);
    if ($v === '') {
        st_json(['error' => 'db_backup_cron cannot be empty'], 400);
    }
    $presetOk = in_array($v, ['@hourly','@daily','@weekly','@monthly'], true);
    if (!$presetOk) {
        $parts = preg_split('/\s+/', $v) ?: [];
        if (count($parts) !== 5) {
            st_json(['error' => 'db_backup_cron must be 5 fields (or @hourly/@daily/@weekly/@monthly)'], 400);
        }
    }
    st_config_set('db_backup_cron', $v);
    // Force scheduler to recalculate immediately.
    st_config_set('db_backup_next_run', '');
    $changed['db_backup_cron'] = $v;
}
if (array_key_exists('db_backup_retention_days', $body)) {
    $v = (int)$body['db_backup_retention_days'];
    $v = max(1, min(365, $v));
    st_config_set('db_backup_retention_days', (string)$v);
    $changed['db_backup_retention_days'] = $v;
}
if (array_key_exists('db_backup_keep_count', $body)) {
    $v = (int)$body['db_backup_keep_count'];
    $v = max(1, min(500, $v));
    st_config_set('db_backup_keep_count', (string)$v);
    $changed['db_backup_keep_count'] = $v;
}

if (array_key_exists('ai_enrichment_enabled', $body)) {
    $v = !empty($body['ai_enrichment_enabled']);
    st_config_set('ai_enrichment_enabled', $v ? '1' : '0');
    $changed['ai_enrichment_enabled'] = $v;
}
if (array_key_exists('ai_provider', $body)) {
    $v = strtolower(trim((string)$body['ai_provider']));
    if (!in_array($v, ['ollama', 'openai', 'anthropic', 'google', 'openwebui'], true)) {
        st_json(['error' => 'ai_provider must be ollama, openai, anthropic, google, or openwebui'], 400);
    }
    st_config_set('ai_provider', $v);
    $changed['ai_provider'] = $v;
}
if (array_key_exists('ai_model', $body)) {
    $v = trim((string)$body['ai_model']);
    if ($v === '' || !preg_match('#^[A-Za-z0-9._:/+-]{2,128}$#', $v)) {
        st_json(['error' => 'Invalid ai_model value'], 400);
    }
    st_config_set('ai_model', $v);
    $changed['ai_model'] = $v;
}
if (array_key_exists('ai_timeout_ms', $body)) {
    $v = (int)$body['ai_timeout_ms'];
    $v = max(100, min(5000, $v));
    st_config_set('ai_timeout_ms', (string)$v);
    $changed['ai_timeout_ms'] = $v;
}
if (array_key_exists('ai_operator_ollama_timeout_s', $body)) {
    $v = (int)$body['ai_operator_ollama_timeout_s'];
    $v = max(120, min(3600, $v));
    st_config_set('ai_operator_ollama_timeout_s', (string)$v);
    $changed['ai_operator_ollama_timeout_s'] = $v;
}
if (array_key_exists('ai_operator_ollama_num_predict', $body)) {
    $v = (int)$body['ai_operator_ollama_num_predict'];
    $v = max(0, min(8192, $v));
    st_config_set('ai_operator_ollama_num_predict', (string)$v);
    $changed['ai_operator_ollama_num_predict'] = $v;
}
if (array_key_exists('ai_operator_ollama_temperature', $body)) {
    $v = (float)$body['ai_operator_ollama_temperature'];
    $v = max(0.0, min(2.0, $v));
    st_config_set('ai_operator_ollama_temperature', (string)$v);
    $changed['ai_operator_ollama_temperature'] = $v;
}
if (array_key_exists('ai_operator_prompt_banner_max_lines', $body)) {
    $v = (int)$body['ai_operator_prompt_banner_max_lines'];
    $v = max(12, min(200, $v));
    st_config_set('ai_operator_prompt_banner_max_lines', (string)$v);
    $changed['ai_operator_prompt_banner_max_lines'] = $v;
}
if (array_key_exists('ai_operator_prompt_banner_val_max', $body)) {
    $v = (int)$body['ai_operator_prompt_banner_val_max'];
    $v = max(40, min(240, $v));
    st_config_set('ai_operator_prompt_banner_val_max', (string)$v);
    $changed['ai_operator_prompt_banner_val_max'] = $v;
}
if (array_key_exists('ai_operator_prompt_banner_max_chars', $body)) {
    $v = (int)$body['ai_operator_prompt_banner_max_chars'];
    $v = max(2000, min(20000, $v));
    st_config_set('ai_operator_prompt_banner_max_chars', (string)$v);
    $changed['ai_operator_prompt_banner_max_chars'] = $v;
}
if (array_key_exists('ai_operator_ollama_num_thread', $body)) {
    $v = (int)$body['ai_operator_ollama_num_thread'];
    $v = max(0, min(256, $v));
    st_config_set('ai_operator_ollama_num_thread', (string)$v);
    $changed['ai_operator_ollama_num_thread'] = $v;
}
if (array_key_exists('ai_operator_ollama_num_ctx', $body)) {
    $v = (int)$body['ai_operator_ollama_num_ctx'];
    if ($v !== 0 && ($v < 512 || $v > 131072)) {
        st_json(['error' => 'ai_operator_ollama_num_ctx must be 0 or 512..131072'], 400);
    }
    st_config_set('ai_operator_ollama_num_ctx', (string)$v);
    $changed['ai_operator_ollama_num_ctx'] = $v;
}
if (array_key_exists('ai_max_hosts_per_scan', $body)) {
    $v = (int)$body['ai_max_hosts_per_scan'];
    $v = max(1, min(5000, $v));
    st_config_set('ai_max_hosts_per_scan', (string)$v);
    $changed['ai_max_hosts_per_scan'] = $v;
}
if (array_key_exists('ai_ambiguous_only', $body)) {
    $v = !empty($body['ai_ambiguous_only']);
    st_config_set('ai_ambiguous_only', $v ? '1' : '0');
    $changed['ai_ambiguous_only'] = $v;
}
if (array_key_exists('ai_suggest_only', $body)) {
    $v = !empty($body['ai_suggest_only']);
    st_config_set('ai_suggest_only', $v ? '1' : '0');
    $changed['ai_suggest_only'] = $v;
}
if (array_key_exists('ai_conflict_only', $body)) {
    $v = !empty($body['ai_conflict_only']);
    st_config_set('ai_conflict_only', $v ? '1' : '0');
    $changed['ai_conflict_only'] = $v;
}
if (array_key_exists('ai_conf_threshold', $body)) {
    $v = (float)$body['ai_conf_threshold'];
    $v = max(0.50, min(0.99, $v));
    st_config_set('ai_conf_threshold', (string)$v);
    $changed['ai_conf_threshold'] = $v;
}
if (array_key_exists('ai_conf_threshold_net_srv', $body)) {
    $v = (float)$body['ai_conf_threshold_net_srv'];
    $v = max(0.50, min(0.99, $v));
    st_config_set('ai_conf_threshold_net_srv', (string)$v);
    $changed['ai_conf_threshold_net_srv'] = $v;
}

if (!empty($body['ai_openai_api_key_remove'])) {
    st_config_set('ai_openai_api_key', '');
    $changed['ai_openai_key_configured'] = false;
} elseif (array_key_exists('ai_openai_api_key', $body)) {
    $nk = trim((string)$body['ai_openai_api_key']);
    if ($nk === '') {
        st_json(['error' => 'ai_openai_api_key is empty — use ai_openai_api_key_remove to clear'], 400);
    }
    if (!preg_match('/^sk-[A-Za-z0-9_-]{20,220}$/', $nk)) {
        st_json(['error' => 'OpenAI API key format looks wrong (expect sk-… from platform.openai.com)'], 400);
    }
    st_config_set('ai_openai_api_key', $nk);
    $changed['ai_openai_key_configured'] = true;
}
if (!empty($body['ai_anthropic_api_key_remove'])) {
    st_config_set('ai_anthropic_api_key', '');
    $changed['ai_anthropic_key_configured'] = false;
} elseif (array_key_exists('ai_anthropic_api_key', $body)) {
    $nk = trim((string)$body['ai_anthropic_api_key']);
    if ($nk === '') {
        st_json(['error' => 'ai_anthropic_api_key is empty — use ai_anthropic_api_key_remove to clear'], 400);
    }
    if (!preg_match('/^sk-ant-[A-Za-z0-9_-]{20,500}$/', $nk)) {
        st_json(['error' => 'Anthropic API key format looks wrong (expect sk-ant-… from console.anthropic.com)'], 400);
    }
    st_config_set('ai_anthropic_api_key', $nk);
    $changed['ai_anthropic_key_configured'] = true;
}
if (!empty($body['ai_gemini_api_key_remove'])) {
    st_config_set('ai_gemini_api_key', '');
    $changed['ai_gemini_key_configured'] = false;
} elseif (array_key_exists('ai_gemini_api_key', $body)) {
    $nk = trim((string)$body['ai_gemini_api_key']);
    if ($nk === '') {
        st_json(['error' => 'ai_gemini_api_key is empty — use ai_gemini_api_key_remove to clear'], 400);
    }
    if (!preg_match('/^[A-Za-z0-9_-]{20,256}$/', $nk)) {
        st_json(['error' => 'Gemini / Google AI API key format looks wrong'], 400);
    }
    st_config_set('ai_gemini_api_key', $nk);
    $changed['ai_gemini_key_configured'] = true;
}

if (array_key_exists('ai_openwebui_base_url', $body)) {
    $bu = trim((string)$body['ai_openwebui_base_url']);
    $allowPrivateOutbound = array_key_exists('security_allow_private_outbound_targets', $changed)
        ? (bool)$changed['security_allow_private_outbound_targets']
        : st_ai_allow_private_outbound_targets();
    if ($bu === '') {
        st_config_set('ai_openwebui_base_url', '');
        $changed['ai_openwebui_base_url'] = '';
    } else {
        $bu = rtrim($bu, '/');
        if (!st_ai_openwebui_base_url_valid($bu, $allowPrivateOutbound)) {
            st_json(['error' => 'ai_openwebui_base_url must be a valid http(s) URL (e.g. http://127.0.0.1:3000)'], 400);
        }
        if (strlen($bu) > 500) {
            st_json(['error' => 'ai_openwebui_base_url is too long'], 400);
        }
        st_config_set('ai_openwebui_base_url', $bu);
        $changed['ai_openwebui_base_url'] = $bu;
    }
}
if (!empty($body['ai_openwebui_api_key_remove'])) {
    st_config_set('ai_openwebui_api_key', '');
    $changed['ai_openwebui_key_configured'] = false;
} elseif (array_key_exists('ai_openwebui_api_key', $body)) {
    $nk = trim((string)$body['ai_openwebui_api_key']);
    if ($nk === '') {
        st_json(['error' => 'ai_openwebui_api_key is empty — use ai_openwebui_api_key_remove to clear'], 400);
    }
    if (strlen($nk) < 8 || strlen($nk) > 500) {
        st_json(['error' => 'Open WebUI API key length looks wrong (8..500 chars)'], 400);
    }
    if (!preg_match('/^[A-Za-z0-9._~+/-=]+$/', $nk)) {
        st_json(['error' => 'Open WebUI API key contains unsupported characters'], 400);
    }
    st_config_set('ai_openwebui_api_key', $nk);
    $changed['ai_openwebui_key_configured'] = true;
}

$dbBackupTouched = array_intersect_key($changed, array_flip([
    'db_backup_enabled', 'db_backup_cron', 'db_backup_retention_days', 'db_backup_keep_count',
]));
if ($dbBackupTouched) {
    $after = [
        'enabled' => array_key_exists('db_backup_enabled', $changed) ? (bool)$changed['db_backup_enabled'] : $dbBackupBefore['enabled'],
        'cron' => array_key_exists('db_backup_cron', $changed) ? (string)$changed['db_backup_cron'] : $dbBackupBefore['cron'],
        'retention_days' => array_key_exists('db_backup_retention_days', $changed) ? (int)$changed['db_backup_retention_days'] : $dbBackupBefore['retention_days'],
        'keep_count' => array_key_exists('db_backup_keep_count', $changed) ? (int)$changed['db_backup_keep_count'] : $dbBackupBefore['keep_count'],
    ];
    st_audit_log('db.backup_settings_updated', null, null, null, null, [
        'before' => $dbBackupBefore,
        'after' => $after,
    ]);
}

if (!empty($body['nvd_api_key_remove'])) {
    st_config_set('nvd_api_key', '');
    $changed['nvd_api_key_configured'] = false;
} elseif (array_key_exists('nvd_api_key', $body)) {
    $existing = trim((string)st_config('nvd_api_key', ''));
    if ($existing !== '') {
        st_json([
            'error' => 'An NVD API key is already saved. Remove it first, then save a new key.',
        ], 409);
    }
    $nk = trim((string)$body['nvd_api_key']);
    if ($nk === '') {
        st_json(['error' => 'nvd_api_key is empty — use nvd_api_key_remove to clear, or paste a key.'], 400);
    }
    if (!preg_match('/^[A-Za-z0-9\-]{30,128}$/', $nk)) {
        st_json(['error' => 'NVD API key format looks wrong (use the UUID from NIST; 30–128 letters, digits, hyphens).'], 400);
    }
    st_config_set('nvd_api_key', $nk);
    $changed['nvd_api_key_configured'] = true;
}

if (!$changed) {
    st_json(['error' => 'no supported settings supplied'], 400);
}

st_json(array_merge(['ok' => true], $changed));
