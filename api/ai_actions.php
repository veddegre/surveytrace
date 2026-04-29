<?php

/**
 * Emit JSON on fatal errors (missing includes, compile errors) so clients never see an empty HTTP 500.
 */
register_shutdown_function(static function (): void {
    $err = error_get_last();
    if ($err === null) {
        return;
    }
    $type = (int)($err['type'] ?? 0);
    $fatalTypes = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];
    if (!in_array($type, $fatalTypes, true)) {
        return;
    }
    if (headers_sent()) {
        return;
    }
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    $msg = (string)($err['message'] ?? '');
    $file = (string)($err['file'] ?? '');
    $line = (int)($err['line'] ?? 0);
    $hint = '';
    if (stripos($msg, 'Failed opening required') !== false) {
        $hint = 'Redeploy api/ai_actions.php from the current SurveyTrace release (see deploy.sh).';
    }
    $payload = [
        'ok' => false,
        'error' => 'Fatal error in AI endpoint',
        'detail' => $msg,
        'file' => $file,
        'line' => $line,
        'hint' => $hint,
    ];
    $out = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    echo ($out !== false) ? $out : '{"ok":false,"error":"fatal"}';
});

/**
 * SurveyTrace — POST /api/ai_actions.php
 *
 * On-demand AI for operators (Ollama). Body:
 *   { "action": "findings_guidance" | "explain_host" | "refresh_scan_summary",
 *     "asset_id"?: int, "job_id"?: int, "force"?: bool }
 */

require_once __DIR__ . '/db.php';

// ---------------------------------------------------------------------------
// Ollama + operator-AI helpers (inlined so deploy only needs this one file)
// ---------------------------------------------------------------------------

/**
 * @return list<string>|null model names when API responds; null if unreachable
 */
function st_ai_ollama_api_tags(float $timeout_s = 1.5): ?array {
    $url = 'http://127.0.0.1:11434/api/tags';
    $raw = '';
    $sec = max(2, min(10, (int)ceil($timeout_s)));
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if (defined('CURLOPT_NOSIGNAL')) {
            curl_setopt($ch, CURLOPT_NOSIGNAL, true);
        }
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_TIMEOUT, $sec);
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
                'timeout' => max(1, (int)ceil($timeout_s)),
            ],
        ]);
        $res = @file_get_contents($url, false, $ctx);
        if (is_string($res)) {
            $raw = $res;
        }
    }
    if ($raw === '') {
        return null;
    }
    $doc = json_decode($raw, true);
    if (!is_array($doc) || !isset($doc['models']) || !is_array($doc['models'])) {
        return null;
    }
    $mods = [];
    foreach ($doc['models'] as $m) {
        if (!is_array($m)) {
            continue;
        }
        $name = trim((string)($m['name'] ?? ''));
        if ($name !== '') {
            $mods[] = $name;
        }
    }
    return $mods ? array_values(array_unique($mods)) : null;
}

/**
 * @return array{
 *   enabled: bool,
 *   provider: string,
 *   model: string,
 *   timeout_ms: int,
 *   available: bool,
 *   availability_reason: string
 * }
 */
function st_ai_operator_runtime(): array {
    $enabled = st_config('ai_enrichment_enabled', '0') === '1';
    $provider = strtolower(trim((string)st_config('ai_provider', 'ollama')));
    $model = trim((string)st_config('ai_model', 'phi3:mini'));
    if ($model === '') {
        $model = 'phi3:mini';
    }
    $timeout_ms = max(100, min(5000, (int)st_config('ai_timeout_ms', '700')));

    $reason = '';
    if (!$enabled) {
        $reason = 'ai_disabled';
    } elseif ($provider !== 'ollama') {
        $reason = 'unsupported_provider';
    } elseif ($model === '') {
        $reason = 'no_model';
    }

    $tags = null;
    if ($reason === '') {
        $tags = st_ai_ollama_api_tags(1.5);
        if ($tags === null) {
            $reason = 'runtime_unreachable';
        }
    }

    $available = $enabled && $provider === 'ollama' && $model !== '' && $tags !== null;

    return [
        'enabled' => $enabled,
        'provider' => $provider,
        'model' => $model,
        'timeout_ms' => $timeout_ms,
        'available' => $available,
        'availability_reason' => $available ? '' : ($reason !== '' ? $reason : 'runtime_unreachable'),
    ];
}

/**
 * POST JSON to Ollama using the system curl binary (same path as `sudo -u www-data curl`).
 * Used when PHP's libcurl returns an empty body under php-fpm.
 *
 * @return array{raw: string, stderr: string, exit: int}
 */
function st_ai_ollama_post_via_cli_curl(string $url, string $jsonBody, int $timeoutSec): array {
    $out = ['raw' => '', 'stderr' => '', 'exit' => -1];
    if (!function_exists('proc_open')) {
        $out['stderr'] = 'proc_open unavailable';
        return $out;
    }
    $curlBin = '';
    foreach (['/usr/bin/curl', '/bin/curl', '/usr/local/bin/curl'] as $c) {
        if (@is_executable($c)) {
            $curlBin = $c;
            break;
        }
    }
    if ($curlBin === '') {
        $out['stderr'] = 'curl binary not found (checked /usr/bin, /bin, /usr/local/bin)';
        return $out;
    }
    $tmp = @tempnam(sys_get_temp_dir(), 'stol_');
    if ($tmp === false) {
        $out['stderr'] = 'tempnam failed';
        return $out;
    }
    if (@file_put_contents($tmp, $jsonBody) === false) {
        @unlink($tmp);
        $out['stderr'] = 'could not write temp JSON body';
        return $out;
    }
    @chmod($tmp, 0600);
    $m = (string)max(1, min(180, $timeoutSec));
    $cmd = [
        $curlBin,
        '-sS',
        '-m', $m,
        '-X', 'POST',
        '-H', 'Content-Type: application/json',
        '-d', '@' . $tmp,
        $url,
    ];
    $desc = [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']];
    $proc = @proc_open($cmd, $desc, $pipes, null, null, ['bypass_shell' => true]);
    if (!is_resource($proc)) {
        @unlink($tmp);
        $out['stderr'] = 'proc_open failed';
        return $out;
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $out['exit'] = proc_close($proc);
    @unlink($tmp);
    $out['raw'] = is_string($stdout) ? $stdout : '';
    $out['stderr'] = is_string($stderr) ? trim($stderr) : '';
    return $out;
}

/**
 * @return array{ok: bool, text: string, err: string}
 */
function st_ai_ollama_generate(string $model, string $prompt, float $timeout_s): array {
    $url = 'http://127.0.0.1:11434/api/generate';
    $body = json_encode([
        'model' => $model,
        'prompt' => $prompt,
        'stream' => false,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($body === false) {
        return ['ok' => false, 'text' => '', 'err' => 'json_encode_failed'];
    }

    $raw = '';
    // Whole-second timeouts + CURLOPT_NOSIGNAL: under php-fpm, CURLOPT_TIMEOUT_MS without
    // CURLOPT_NOSIGNAL can make libcurl return an empty body (alarm/signal vs threads).
    $timeoutSec = max(1, min(180, (int)ceil($timeout_s)));
    $connectSec = max(2, min(30, (int)ceil($timeout_s / 4)));
    if ($connectSec > $timeoutSec) {
        $connectSec = min($connectSec, $timeoutSec);
    }
    $curlNote = '';
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        if (defined('CURLOPT_NOSIGNAL')) {
            curl_setopt($ch, CURLOPT_NOSIGNAL, true);
        }
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $connectSec);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeoutSec);
        $res = curl_exec($ch);
        $errno = (int)curl_errno($ch);
        $cerr = trim((string)curl_error($ch));
        $httpCode = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($res === false) {
            $curlNote = $errno !== 0 ? "curl errno {$errno}: {$cerr}" : ($cerr !== '' ? $cerr : 'curl_exec returned false');
        } elseif (is_string($res)) {
            $raw = $res;
            if ($raw === '' && $httpCode >= 400) {
                $curlNote = "HTTP {$httpCode} from Ollama (empty body)";
            }
        }
    }
    if ($raw === '') {
        if (!ini_get('allow_url_fopen')) {
            $curlNote = trim($curlNote . ' allow_url_fopen=0 (cannot fall back to HTTP stream)');
        }
        $ctx = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n",
                'content' => $body,
                'timeout' => max(1, (int)ceil($timeout_s)),
            ],
        ]);
        $res = @file_get_contents($url, false, $ctx);
        if (is_string($res) && $res !== '') {
            $raw = $res;
            $curlNote = '';
        }
    }
    if ($raw === '') {
        $cli = st_ai_ollama_post_via_cli_curl($url, $body, $timeoutSec);
        if ($cli['raw'] !== '') {
            $raw = $cli['raw'];
        } else {
            $cliHint = '';
            if ($cli['stderr'] !== '') {
                $cliHint = 'cli_curl: ' . $cli['stderr'];
            } elseif ($cli['exit'] !== 0 && $cli['exit'] !== -1) {
                $cliHint = 'cli_curl exit ' . (string)$cli['exit'];
            }
            if ($cliHint !== '') {
                $curlNote = trim($curlNote . ' ' . $cliHint);
            }
        }
    }
    if ($raw === '') {
        $hint = $curlNote !== '' ? $curlNote : 'no data from 127.0.0.1:11434';
        return ['ok' => false, 'text' => '', 'err' => 'empty_response: ' . substr($hint, 0, 220)];
    }
    $doc = json_decode($raw, true);
    if (!is_array($doc)) {
        return ['ok' => false, 'text' => '', 'err' => 'bad_json: ' . substr(trim($raw), 0, 160)];
    }
    $apiErr = trim((string)($doc['error'] ?? ''));
    if ($apiErr !== '') {
        return ['ok' => false, 'text' => '', 'err' => 'ollama: ' . substr($apiErr, 0, 300)];
    }
    $out = trim((string)($doc['response'] ?? ''));
    if ($out === '') {
        return ['ok' => false, 'text' => '', 'err' => 'empty_model_output (check model is pulled: ollama pull ' . $model . ')'];
    }
    return ['ok' => true, 'text' => $out, 'err' => ''];
}

function st_ai_extract_json_object(string $text): ?array {
    if (!preg_match('/\{.*\}/s', $text, $m)) {
        return null;
    }
    $doc = json_decode($m[0], true);
    return is_array($doc) ? $doc : null;
}

function st_ai_iso_utc(): string {
    return gmdate('c');
}

function st_ai_json_decode_assoc(string $raw): ?array {
    $raw = trim($raw);
    if ($raw === '') {
        return null;
    }
    $flags = defined('JSON_INVALID_UTF8_SUBSTITUTE') ? JSON_INVALID_UTF8_SUBSTITUTE : 0;
    $doc = json_decode($raw, true, 512, $flags);
    if (is_array($doc)) {
        return $doc;
    }
    if ($flags !== 0) {
        $doc = json_decode($raw, true);
        return is_array($doc) ? $doc : null;
    }
    return null;
}

function st_ai_save_asset_cache(PDO $db, int $assetId, string $column, array $envelope): void {
    if (!in_array($column, ['ai_findings_guidance_cache', 'ai_host_explain_cache'], true)) {
        return;
    }
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    $json = json_encode($envelope, $flags);
    if ($json === false) {
        $json = '{"status":"failed","detail":"json_encode_failed","fp":"","ts":"","doc":null}';
    }
    $stmt = $db->prepare("UPDATE assets SET {$column} = ? WHERE id = ?");
    $stmt->execute([$json, $assetId]);
}

function st_ai_findings_fingerprint(array $openFindings): string {
    if (!$openFindings) {
        return sha1('');
    }
    usort($openFindings, static function ($a, $b) {
        $ca = (string)($a['cve_id'] ?? '');
        $cb = (string)($b['cve_id'] ?? '');
        return strcmp($ca, $cb);
    });
    $parts = [];
    foreach ($openFindings as $f) {
        $parts[] = implode('|', [
            (string)($f['cve_id'] ?? ''),
            (string)($f['cvss'] ?? ''),
            (string)($f['severity'] ?? ''),
            (string)(int)($f['resolved'] ?? 0),
        ]);
    }
    return sha1(implode("\n", $parts));
}

function st_ai_explain_fingerprint(array $asset, array $ports, array $banners, int $openFindingCount, array $topCves): string {
    $portList = array_values(array_unique(array_map(static function ($p) {
        return (int)$p;
    }, $ports)));
    sort($portList);
    $bannerDigest = [];
    $n = 0;
    foreach ($banners as $k => $v) {
        if ($n++ >= 8) {
            break;
        }
        $vs = substr((string)preg_replace('/\s+/', ' ', trim((string)$v)), 0, 120);
        $bannerDigest[] = (string)$k . '=' . $vs;
    }
    $blob = implode('|', [
        (string)($asset['ip'] ?? ''),
        (string)($asset['hostname'] ?? ''),
        (string)($asset['category'] ?? ''),
        (string)($asset['vendor'] ?? ''),
        json_encode($portList, JSON_UNESCAPED_UNICODE),
        (string)$openFindingCount,
        implode(',', $topCves),
        implode(';', $bannerDigest),
    ]);
    return sha1($blob);
}

function st_ai_normalize_findings_doc(?array $doc): array {
    if (!$doc) {
        return [];
    }
    $risk = trim((string)($doc['risk_summary'] ?? ''));
    $bullets = $doc['remediation_bullets'] ?? [];
    if (!is_array($bullets)) {
        $bullets = [];
    }
    $clean = [];
    foreach ($bullets as $b) {
        $s = trim((string)$b);
        if ($s !== '' && count($clean) < 8) {
            $clean[] = substr($s, 0, 400);
        }
    }
    $prior = trim((string)($doc['prioritize'] ?? ''));
    $note = trim((string)($doc['note'] ?? ''));
    $out = [];
    if ($risk !== '') {
        $out['risk_summary'] = substr($risk, 0, 2000);
    }
    if ($clean) {
        $out['remediation_bullets'] = $clean;
    }
    if ($prior !== '') {
        $out['prioritize'] = substr($prior, 0, 1200);
    }
    if ($note !== '') {
        $out['note'] = substr($note, 0, 800);
    }
    return $out;
}

function st_ai_normalize_explain_doc(?array $doc): array {
    if (!$doc) {
        return [];
    }
    $overview = trim((string)($doc['overview'] ?? ''));
    $roles = $doc['likely_roles'] ?? [];
    $tips = $doc['hardening_tips'] ?? [];
    $qs = $doc['owner_questions'] ?? [];
    if (!is_array($roles)) {
        $roles = [];
    }
    if (!is_array($tips)) {
        $tips = [];
    }
    if (!is_array($qs)) {
        $qs = [];
    }
    $nr = [];
    foreach ($roles as $x) {
        $s = trim((string)$x);
        if ($s !== '' && count($nr) < 5) {
            $nr[] = substr($s, 0, 200);
        }
    }
    $nt = [];
    foreach ($tips as $x) {
        $s = trim((string)$x);
        if ($s !== '' && count($nt) < 6) {
            $nt[] = substr($s, 0, 400);
        }
    }
    $nq = [];
    foreach ($qs as $x) {
        $s = trim((string)$x);
        if ($s !== '' && count($nq) < 4) {
            $nq[] = substr($s, 0, 300);
        }
    }
    $out = [];
    if ($overview !== '') {
        $out['overview'] = substr($overview, 0, 2000);
    }
    if ($nr) {
        $out['likely_roles'] = $nr;
    }
    if ($nt) {
        $out['hardening_tips'] = $nt;
    }
    if ($nq) {
        $out['owner_questions'] = $nq;
    }
    return $out;
}

st_auth();
st_require_role(['scan_editor', 'admin']);
st_method('POST');

$body = st_input();
$action = strtolower(trim((string)($body['action'] ?? '')));
$force = !empty($body['force']);

if ($action === '') {
    st_json(['error' => 'action required'], 400);
}

$db = st_db();
$rt = st_ai_operator_runtime();

try {
    if ($action === 'findings_guidance' || $action === 'explain_host') {
        $assetId = (int)($body['asset_id'] ?? 0);
        if ($assetId <= 0) {
            st_json(['error' => 'asset_id required'], 400);
        }
        $stmt = $db->prepare('SELECT * FROM assets WHERE id = ?');
        $stmt->execute([$assetId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            st_json(['error' => 'Asset not found'], 404);
        }

        $fstmt = $db->prepare('
            SELECT cve_id, cvss, severity, description, resolved
            FROM findings
            WHERE asset_id = ?
            ORDER BY (CASE WHEN cvss IS NULL THEN 1 ELSE 0 END) ASC, cvss DESC, cve_id ASC
        ');
        $fstmt->execute([$assetId]);
        $allFindings = $fstmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
        $openFindings = array_values(array_filter($allFindings, static function ($f) {
            return (int)($f['resolved'] ?? 0) === 0;
        }));

        $ports = json_decode((string)($row['open_ports'] ?? '[]'), true);
        if (!is_array($ports)) {
            $ports = [];
        }
        $banners = json_decode((string)($row['banners'] ?? '{}'), true);
        if (!is_array($banners)) {
            $banners = [];
        }

        if ($action === 'findings_guidance') {
            $cacheCol = 'ai_findings_guidance_cache';
            $cachedRaw = (string)($row[$cacheCol] ?? '');
            $cached = $cachedRaw !== '' ? (json_decode($cachedRaw, true) ?: null) : null;
            $fp = st_ai_findings_fingerprint($openFindings);

            if (!$force && is_array($cached) && ($cached['fp'] ?? '') === $fp && ($cached['status'] ?? '') === 'ok') {
                st_json([
                    'ok' => true,
                    'cached' => true,
                    'fingerprint' => $fp,
                    'envelope' => $cached,
                ]);
            }

            if (!$openFindings) {
                $envelope = [
                    'fp' => $fp,
                    'ts' => st_ai_iso_utc(),
                    'status' => 'skipped',
                    'detail' => 'no_open_findings',
                    'doc' => null,
                ];
                st_ai_save_asset_cache($db, $assetId, $cacheCol, $envelope);
                st_json(['ok' => true, 'cached' => false, 'fingerprint' => $fp, 'envelope' => $envelope]);
            }

            if (!$rt['available']) {
                st_json([
                    'ok' => false,
                    'error' => 'AI runtime unavailable',
                    'detail' => $rt['availability_reason'] ?: 'unavailable',
                ], 503);
            }

            $lines = [];
            foreach (array_slice($openFindings, 0, 18) as $f) {
                $desc = substr((string)preg_replace('/\s+/', ' ', trim((string)($f['description'] ?? ''))), 0, 220);
                $lines[] = sprintf(
                    '%s cvss=%s sev=%s — %s',
                    (string)($f['cve_id'] ?? ''),
                    (string)($f['cvss'] ?? ''),
                    (string)($f['severity'] ?? ''),
                    $desc
                );
            }
            $prompt = "You help network operators triage CVE findings. Output is NON-AUTHORITATIVE suggestions only.\n"
                . "Return ONLY JSON with keys: risk_summary (string, <=800 chars), remediation_bullets (array of <=8 short strings), "
                . "prioritize (string: what to patch or verify first), note (optional string: uncertainty/limitations).\n"
                . "Use practical language; do not claim exploitability without evidence.\n\n"
                . 'Host: ' . ($row['ip'] ?? '') . ' category=' . ($row['category'] ?? '') . ' hostname=' . ($row['hostname'] ?? '') . "\n"
                . "Open findings (CVE rows):\n" . implode("\n", $lines) . "\n";

            @set_time_limit(240);
            @ignore_user_abort(true);
            // Host CVE triage: long prompts + local CPU can exceed 60s. Do not tie wall clock to
            // ai_timeout_ms (that knob is for daemon per-host enrichment, 100–5000 ms).
            $timeoutS = 180.0;
            // PDOStatement keeps a reference to PDO — drop it so release actually closes SQLite.
            $stmt = null;
            $fstmt = null;
            // Release SQLite before Ollama so the worker does not hold DB state for minutes.
            st_db_release_connection();
            $db = null;
            $gen = st_ai_ollama_generate($rt['model'], $prompt, $timeoutS);
            $db = st_db();
            if (!$gen['ok']) {
                $envelope = [
                    'fp' => $fp,
                    'ts' => st_ai_iso_utc(),
                    'status' => 'failed',
                    'detail' => substr($gen['err'], 0, 200),
                    'doc' => null,
                ];
                st_ai_save_asset_cache($db, $assetId, $cacheCol, $envelope);
                st_json(['ok' => false, 'error' => 'Model call failed', 'detail' => $gen['err'], 'envelope' => $envelope], 502);
            }

            $parsed = st_ai_extract_json_object($gen['text']);
            $doc = st_ai_normalize_findings_doc($parsed);
            if (!$doc) {
                $envelope = [
                    'fp' => $fp,
                    'ts' => st_ai_iso_utc(),
                    'status' => 'failed',
                    'detail' => 'no_json',
                    'doc' => null,
                ];
                st_ai_save_asset_cache($db, $assetId, $cacheCol, $envelope);
                st_json(['ok' => false, 'error' => 'Could not parse model JSON', 'envelope' => $envelope], 502);
            }

            $envelope = [
                'fp' => $fp,
                'ts' => st_ai_iso_utc(),
                'status' => 'ok',
                'detail' => '',
                'doc' => $doc,
            ];
            st_ai_save_asset_cache($db, $assetId, $cacheCol, $envelope);
            st_json(['ok' => true, 'cached' => false, 'fingerprint' => $fp, 'envelope' => $envelope]);
        }

        // explain_host
        $cacheCol = 'ai_host_explain_cache';
        $cachedRaw = (string)($row[$cacheCol] ?? '');
        $cached = $cachedRaw !== '' ? (json_decode($cachedRaw, true) ?: null) : null;
        $topCves = [];
        foreach (array_slice($openFindings, 0, 5) as $f) {
            $cid = trim((string)($f['cve_id'] ?? ''));
            if ($cid !== '') {
                $topCves[] = $cid;
            }
        }
        $openCount = count($openFindings);
        $fp = st_ai_explain_fingerprint($row, $ports, $banners, $openCount, $topCves);

        if (!$force && is_array($cached) && ($cached['fp'] ?? '') === $fp && ($cached['status'] ?? '') === 'ok') {
            st_json([
                'ok' => true,
                'cached' => true,
                'fingerprint' => $fp,
                'envelope' => $cached,
            ]);
        }

        if (!$rt['available']) {
            st_json([
                'ok' => false,
                'error' => 'AI runtime unavailable',
                'detail' => $rt['availability_reason'] ?: 'unavailable',
            ], 503);
        }

        $portStr = implode(',', array_slice(array_map('intval', $ports), 0, 32));
        $bannerLines = [];
        $bn = 0;
        foreach ($banners as $k => $v) {
            if ($bn++ >= 6) {
                break;
            }
            $vs = substr((string)preg_replace('/\s+/', ' ', trim((string)$v)), 0, 160);
            $bannerLines[] = (string)$k . ':' . $vs;
        }

        $prompt = "You summarize a single discovered host for a network inventory operator.\n"
            . "Return ONLY JSON with keys: overview (string <=900 chars), likely_roles (array <=5 short strings), "
            . "hardening_tips (array <=6 short strings), owner_questions (array <=4 short questions an operator could ask the asset owner).\n"
            . "Ground answers in the evidence; mark uncertainty in the overview if signals are weak.\n\n"
            . 'IP=' . ($row['ip'] ?? '') . ' hostname=' . ($row['hostname'] ?? '') . ' category=' . ($row['category'] ?? '')
            . ' vendor=' . ($row['vendor'] ?? '') . ' model=' . ($row['model'] ?? '') . "\n"
            . 'open_ports=' . $portStr . " open_findings=" . $openCount . ' top_cves=' . implode(',', $topCves) . "\n"
            . "banner_snippets:\n" . implode("\n", $bannerLines) . "\n";

        @set_time_limit(240);
        @ignore_user_abort(true);
        $timeoutS = 180.0;
        $stmt = null;
        $fstmt = null;
        st_db_release_connection();
        $db = null;
        $gen = st_ai_ollama_generate($rt['model'], $prompt, $timeoutS);
        $db = st_db();
        if (!$gen['ok']) {
            $envelope = [
                'fp' => $fp,
                'ts' => st_ai_iso_utc(),
                'status' => 'failed',
                'detail' => substr($gen['err'], 0, 200),
                'doc' => null,
            ];
            st_ai_save_asset_cache($db, $assetId, $cacheCol, $envelope);
            st_json(['ok' => false, 'error' => 'Model call failed', 'detail' => $gen['err'], 'envelope' => $envelope], 502);
        }

        $parsed = st_ai_extract_json_object($gen['text']);
        $doc = st_ai_normalize_explain_doc($parsed);
        if (!$doc) {
            $envelope = [
                'fp' => $fp,
                'ts' => st_ai_iso_utc(),
                'status' => 'failed',
                'detail' => 'no_json',
                'doc' => null,
            ];
            st_ai_save_asset_cache($db, $assetId, $cacheCol, $envelope);
            st_json(['ok' => false, 'error' => 'Could not parse model JSON', 'envelope' => $envelope], 502);
        }

        $envelope = [
            'fp' => $fp,
            'ts' => st_ai_iso_utc(),
            'status' => 'ok',
            'detail' => '',
            'doc' => $doc,
        ];
        st_ai_save_asset_cache($db, $assetId, $cacheCol, $envelope);
        st_json(['ok' => true, 'cached' => false, 'fingerprint' => $fp, 'envelope' => $envelope]);
    }

    if ($action === 'refresh_scan_summary') {
        $jobId = (int)($body['job_id'] ?? 0);
        if ($jobId <= 0) {
            st_json(['error' => 'job_id required'], 400);
        }
        $jstmt = $db->prepare('SELECT id, status, summary_json, deleted_at FROM scan_jobs WHERE id = ?');
        $jstmt->execute([$jobId]);
        $job = $jstmt->fetch(PDO::FETCH_ASSOC);
        if (!$job) {
            st_json(['error' => 'Job not found'], 404);
        }
        if (!empty($job['deleted_at'])) {
            st_json(['error' => 'Job is deleted'], 400);
        }
        if (($job['status'] ?? '') !== 'done') {
            st_json(['error' => 'AI refresh is only available for completed (done) scans'], 400);
        }
        $rawSum = trim((string)($job['summary_json'] ?? ''));
        if ($rawSum === '') {
            st_json(['error' => 'This job has no stored summary to refresh'], 400);
        }
        $summary = st_ai_json_decode_assoc($rawSum);
        if (!is_array($summary)) {
            st_json(['error' => 'Could not decode stored summary_json'], 400);
        }

        if (!$rt['available']) {
            st_json([
                'ok' => false,
                'error' => 'AI runtime unavailable',
                'detail' => $rt['availability_reason'] ?: 'unavailable',
            ], 503);
        }

        $compact = [
            'profile' => $summary['profile'] ?? null,
            'scan_mode' => $summary['scan_mode'] ?? null,
            'target_cidr' => $summary['target_cidr'] ?? null,
            'assets_catalogued' => (int)($summary['assets_catalogued'] ?? 0),
            'hosts_found' => (int)($summary['hosts_found'] ?? 0),
            'open_findings' => (int)($summary['open_findings'] ?? 0),
            'severity_breakdown' => is_array($summary['severity_breakdown'] ?? null)
                ? $summary['severity_breakdown'] : [],
            'categories' => is_array($summary['categories'] ?? null) ? $summary['categories'] : [],
            'top_ports' => is_array($summary['top_ports'] ?? null) ? $summary['top_ports'] : [],
            'ai_enrichment_attempts' => (int)($summary['ai_enrichment_attempts'] ?? 0),
            'ai_enrichment_applied' => (int)($summary['ai_enrichment_applied'] ?? 0),
            'routed_net_overrides' => (int)($summary['routed_net_overrides'] ?? 0),
        ];

        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
        if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
            $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
        }
        $compactJson = json_encode($compact, $flags);
        if ($compactJson === false) {
            st_json(['error' => 'Could not encode scan compact summary'], 500);
        }

        $prompt = "You are writing an operator summary for a network scan.\n"
            . "Return ONLY JSON with keys: overview (string), concerns (array of <=5 strings), "
            . "next_steps (array of <=5 strings).\n"
            . "Be concise, practical, and avoid alarmist language.\n\n"
            . "Scan data JSON:\n{$compactJson}\n";

        @set_time_limit(240);
        @ignore_user_abort(true);
        $timeoutS = 180.0;
        $jstmt = null;
        st_db_release_connection();
        $db = null;
        $gen = st_ai_ollama_generate($rt['model'], $prompt, $timeoutS);
        $db = st_db();
        if (!$gen['ok']) {
            $summary['ai_scan_summary_status'] = 'failed';
            $summary['ai_scan_summary_detail'] = substr($gen['err'], 0, 200);
            $upd = json_encode($summary, $flags);
            if ($upd !== false) {
                $db->prepare('UPDATE scan_jobs SET summary_json = ? WHERE id = ?')->execute([$upd, $jobId]);
            }
            st_json(['ok' => false, 'error' => 'Model call failed', 'detail' => $gen['err']], 502);
        }

        $parsed = st_ai_extract_json_object($gen['text']);
        if (!is_array($parsed)) {
            $summary['ai_scan_summary_status'] = 'failed';
            $summary['ai_scan_summary_detail'] = 'no_json';
            $upd = json_encode($summary, $flags);
            if ($upd !== false) {
                $db->prepare('UPDATE scan_jobs SET summary_json = ? WHERE id = ?')->execute([$upd, $jobId]);
            }
            st_json(['ok' => false, 'error' => 'Could not parse model JSON'], 502);
        }

        $overview = trim((string)($parsed['overview'] ?? ''));
        $concerns = $parsed['concerns'] ?? [];
        $next = $parsed['next_steps'] ?? [];
        if (!is_array($concerns)) {
            $concerns = [];
        }
        if (!is_array($next)) {
            $next = [];
        }
        $concerns = array_values(array_filter(array_map(static function ($x) {
            return substr(trim((string)$x), 0, 400);
        }, $concerns), static function ($s) {
            return $s !== '';
        }));
        $concerns = array_slice($concerns, 0, 5);
        $next = array_values(array_filter(array_map(static function ($x) {
            return substr(trim((string)$x), 0, 400);
        }, $next), static function ($s) {
            return $s !== '';
        }));
        $next = array_slice($next, 0, 5);

        $aiDoc = [
            'overview' => substr($overview, 0, 2000),
            'concerns' => $concerns,
            'next_steps' => $next,
        ];
        if ($aiDoc['overview'] === '' && !$aiDoc['concerns'] && !$aiDoc['next_steps']) {
            $summary['ai_scan_summary_status'] = 'failed';
            $summary['ai_scan_summary_detail'] = 'empty_model_fields';
        } else {
            $summary['ai_summary'] = $aiDoc;
            $summary['ai_scan_summary_status'] = 'ok';
            $summary['ai_scan_summary_detail'] = '';
        }

        $upd = json_encode($summary, $flags);
        if ($upd === false) {
            st_json(['error' => 'Could not serialize updated summary'], 500);
        }
        $db->prepare('UPDATE scan_jobs SET summary_json = ? WHERE id = ?')->execute([$upd, $jobId]);

        st_json([
            'ok' => true,
            'summary' => $summary,
        ]);
    }

    st_json(['error' => 'Unknown action'], 400);
} catch (Throwable $e) {
    @error_log('SurveyTrace ai_actions: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    $detail = $e->getMessage();
    $hint = '';
    if (stripos($detail, 'no such column') !== false) {
        $hint = 'SQLite schema is missing AI cache columns — open any SurveyTrace page once (runs migrations) or redeploy api/db.php.';
    }
    st_json([
        'ok' => false,
        'error' => 'AI action failed',
        'detail' => $detail,
        'exception' => get_class($e),
        'hint' => $hint,
    ], 500);
}
