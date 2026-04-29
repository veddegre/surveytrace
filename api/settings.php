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
 *   - ai_provider: string ("ollama" only for now)
 *   - ai_model: string (Ollama tag, e.g. phi3:mini)
 *   - ai_timeout_ms: int (100..5000)
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
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 1500);
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
        'ai_max_hosts_per_scan' => max(1, min(5000, (int)st_config('ai_max_hosts_per_scan', '40'))),
        'ai_ambiguous_only' => st_config('ai_ambiguous_only', '1') === '1',
        'ai_suggest_only' => st_config('ai_suggest_only', '0') === '1',
        'ai_conflict_only' => st_config('ai_conflict_only', '1') === '1',
        'ai_conf_threshold' => max(0.50, min(0.99, (float)st_config('ai_conf_threshold', '0.72'))),
        'ai_conf_threshold_net_srv' => max(0.50, min(0.99, (float)st_config('ai_conf_threshold_net_srv', '0.82'))),
        'ai_runtime' => $ai,
        'scan_trash_retention_days' => max(1, min(365, (int)st_config('scan_trash_retention_days', '30'))),
        'nvd_api_key_configured' => $nvdKey !== '',
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
    if ($v !== 'ollama') {
        st_json(['error' => 'ai_provider must be ollama'], 400);
    }
    st_config_set('ai_provider', $v);
    $changed['ai_provider'] = $v;
}
if (array_key_exists('ai_model', $body)) {
    $v = trim((string)$body['ai_model']);
    if ($v === '' || !preg_match('/^[A-Za-z0-9._:-]{2,120}$/', $v)) {
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
