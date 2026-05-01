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
 * On-demand AI for operators (Ollama or cloud: OpenAI, Anthropic, Google Gemini, Open WebUI). Body:
 *   { "action": "findings_guidance" | "explain_host" | "refresh_scan_summary",
 *     "asset_id"?: int, "job_id"?: int, "force"?: bool }
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/lib_ai_cloud.php';

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
    $model = trim((string)st_config('ai_model', ''));
    if ($model === '') {
        $model = match ($provider) {
            'openai' => 'gpt-4o-mini',
            'anthropic' => 'claude-3-5-haiku-20241022',
            'google' => 'gemini-2.0-flash',
            'openwebui' => 'llama3.2',
            default => 'phi3:mini',
        };
    }
    $timeout_ms = max(100, min(5000, (int)st_config('ai_timeout_ms', '700')));

    $reason = '';
    if (!$enabled) {
        $reason = 'ai_disabled';
    } elseif (!in_array($provider, ['ollama', 'openai', 'anthropic', 'google', 'openwebui'], true)) {
        $reason = 'unsupported_provider';
    }

    $tags = null;
    $available = false;
    if ($reason === '') {
        if ($provider === 'ollama') {
            $tags = st_ai_ollama_api_tags(1.5);
            if ($tags === null) {
                $reason = 'runtime_unreachable';
            } else {
                $available = true;
            }
        } elseif (st_ai_cloud_provider_ready($provider)) {
            $available = true;
        } else {
            $reason = 'missing_api_key';
        }
    }

    return [
        'enabled' => $enabled,
        'provider' => $provider,
        'model' => $model,
        'timeout_ms' => $timeout_ms,
        'available' => $available,
        'availability_reason' => $available ? '' : ($reason !== '' ? $reason : 'unavailable'),
    ];
}

/**
 * @param array{provider: string, model: string, ...} $rt from st_ai_operator_runtime()
 * @return array{ok: bool, text: string, err: string}
 */
function st_ai_operator_completion(array $rt, string $prompt, float $timeout_s): array {
    $p = strtolower(trim((string)($rt['provider'] ?? 'ollama')));
    if ($p === 'ollama') {
        return st_ai_ollama_generate((string)($rt['model'] ?? 'phi3:mini'), $prompt, $timeout_s);
    }
    return st_ai_cloud_completion($p, (string)($rt['model'] ?? ''), $prompt, $timeout_s);
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
    $cap = st_ai_operator_ollama_timeout_cap();
    $m = (string)max(1, min($cap, $timeoutSec));
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
 * Ollama /api/generate runner options. num_predict caps output tokens (lower = faster completions).
 *
 * @return array<string,int|float>
 */
function st_ai_operator_ollama_generate_options(): array {
    $opts = [];
    $np = (int)st_config('ai_operator_ollama_num_predict', '768');
    if ($np > 0 && $np <= 8192) {
        $opts['num_predict'] = $np;
    }
    $temp = (float)st_config('ai_operator_ollama_temperature', '0.25');
    if ($temp >= 0.0 && $temp <= 2.0) {
        $opts['temperature'] = $temp;
    }
    $nth = (int)st_config('ai_operator_ollama_num_thread', '0');
    if ($nth > 0 && $nth <= 256) {
        $opts['num_thread'] = $nth;
    }
    $nctx = (int)st_config('ai_operator_ollama_num_ctx', '0');
    if ($nctx >= 512 && $nctx <= 131072) {
        $opts['num_ctx'] = $nctx;
    }
    return $opts;
}

/**
 * @return array{ok: bool, text: string, err: string}
 */
function st_ai_ollama_generate(string $model, string $prompt, float $timeout_s): array {
    $url = 'http://127.0.0.1:11434/api/generate';
    $payload = [
        'model' => $model,
        'prompt' => $prompt,
        'stream' => false,
    ];
    $genOpts = st_ai_operator_ollama_generate_options();
    if ($genOpts !== []) {
        $payload['options'] = $genOpts;
    }
    $body = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($body === false) {
        return ['ok' => false, 'text' => '', 'err' => 'json_encode_failed'];
    }

    $raw = '';
    // Whole-second timeouts + CURLOPT_NOSIGNAL: under php-fpm, CURLOPT_TIMEOUT_MS without
    // CURLOPT_NOSIGNAL can make libcurl return an empty body (alarm/signal vs threads).
    $cap = st_ai_operator_ollama_timeout_cap();
    $timeoutSec = max(1, min($cap, (int)ceil($timeout_s)));
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

/**
 * Remove common model preambles so the first "{" is more likely to be answer JSON.
 */
function st_ai_strip_model_noise(string $text): string {
    $text = trim($text);
    // Reasoning wrappers (built without embedding raw tags in this source file).
    $pairs = [
        ["\x3C" . 'think' . "\x3E", "\x3C\x2F" . 'think' . "\x3E"],
        ["\x3C" . 'redacted' . '_' . 'think' . "\x3E", "\x3C\x2F" . 'redacted' . '_' . 'think' . "\x3E"],
    ];
    foreach ($pairs as [$o, $c]) {
        $text = preg_replace('#' . preg_quote($o, '#') . '[\s\S]*?' . preg_quote($c, '#') . '#i', '', $text) ?? $text;
    }
    $text = preg_replace('/<redacted_reasoning>[\s\S]*?<\/redacted_reasoning>/i', '', $text) ?? $text;
    return trim($text);
}

/**
 * True when this decoded object is the scan "compact" blob we embed in the prompt,
 * not the operator summary JSON (overview / concerns / next_steps).
 */
function st_ai_json_looks_like_scan_compact_echo(array $d): bool {
    if (!isset($d['profile'], $d['assets_catalogued'], $d['hosts_found'])) {
        return false;
    }
    if (array_key_exists('overview', $d) || isset($d['concerns']) || isset($d['next_steps'])) {
        return false;
    }
    return true;
}

/**
 * @param 'scan_summary'|'explain_host'|'findings'|'' $role '' = first non-scan-echo object
 */
function st_ai_json_object_matches_role(array $d, string $role): bool {
    if ($role === 'scan_summary') {
        if (st_ai_json_looks_like_scan_compact_echo($d)) {
            return false;
        }
        return array_key_exists('overview', $d)
            || (isset($d['concerns']) && is_array($d['concerns']))
            || (isset($d['next_steps']) && is_array($d['next_steps']));
    }
    if ($role === 'explain_host') {
        return array_key_exists('overview', $d)
            || (isset($d['likely_roles']) && is_array($d['likely_roles']))
            || (isset($d['hardening_tips']) && is_array($d['hardening_tips']))
            || (isset($d['owner_questions']) && is_array($d['owner_questions']));
    }
    if ($role === 'findings') {
        $rs = trim((string)($d['risk_summary'] ?? ''));
        $pr = trim((string)($d['prioritize'] ?? ''));
        $note = trim((string)($d['note'] ?? ''));
        $rb = $d['remediation_bullets'] ?? [];
        if ($rs !== '' || $pr !== '' || $note !== '') {
            return true;
        }
        if (!is_array($rb)) {
            return false;
        }
        foreach ($rb as $x) {
            if (trim((string)$x) !== '') {
                return true;
            }
        }
        return false;
    }
    return !st_ai_json_looks_like_scan_compact_echo($d);
}

/**
 * Slice one JSON object starting at $start (byte index of "{") using string/escape rules.
 * Returns null if braces are unbalanced (truncated output, etc.).
 */
function st_ai_json_slice_balanced(string $s, int $start): ?string {
    $len = strlen($s);
    if ($start < 0 || $start >= $len || $s[$start] !== '{') {
        return null;
    }
    $depth = 0;
    $inString = false;
    $escape = false;
    for ($i = $start; $i < $len; $i++) {
        $c = $s[$i];
        if (!$inString) {
            if ($c === '{') {
                $depth++;
            } elseif ($c === '}') {
                $depth--;
                if ($depth === 0) {
                    return substr($s, $start, $i - $start + 1);
                }
            } elseif ($c === '"') {
                $inString = true;
                $escape = false;
            }
        } else {
            if ($escape) {
                $escape = false;
                continue;
            }
            if ($c === '\\') {
                $escape = true;
                continue;
            }
            if ($c === '"') {
                $inString = false;
            }
        }
    }
    return null;
}

/**
 * Short previews for API/debug (avoids megabyte model dumps in JSON or logs).
 *
 * @return array{len: int, head: string, tail: string}
 */
function st_ai_parse_debug_preview(string $s, int $headMax = 700, int $tailMax = 240): array {
    $s = str_replace(["\r\n", "\r"], "\n", $s);
    $len = strlen($s);
    $head = $len <= $headMax ? $s : substr($s, 0, $headMax) . "\n…(" . ($len - $headMax) . " more bytes)";
    $tail = '';
    if ($len > $tailMax) {
        $tail = substr($s, -$tailMax);
    }
    return ['len' => $len, 'head' => $head, 'tail' => $tail];
}

/**
 * Parse model output into a JSON object plus diagnostics when parsing fails.
 *
 * @param 'scan_summary'|'explain_host'|'findings'|'' $role
 * @return array{doc: ?array<string,mixed>, debug: array<string,mixed>}
 */
function st_ai_extract_json_object_with_debug(string $text, string $role = ''): array {
    $debug = [
        'role' => $role,
        'outcome' => 'unknown',
        'candidates' => [],
        'model_char_count' => strlen(trim($text)),
    ];
    $debug['raw_preview'] = st_ai_parse_debug_preview(trim($text), 500, 180);

    $text = st_ai_strip_model_noise(trim($text));
    if ($text === '') {
        $debug['outcome'] = 'empty_after_strip';
        return ['doc' => null, 'debug' => $debug];
    }
    if (str_starts_with($text, "\xEF\xBB\xBF")) {
        $text = trim(substr($text, 3));
    }
    $fencePasses = 0;
    for ($guard = 0; $guard < 6 && str_starts_with($text, '```'); $guard++) {
        $text = preg_replace('/^```[a-zA-Z0-9]*\s*\R?/', '', $text) ?? $text;
        $text = preg_replace('/\R```\s*$/', '', $text) ?? $text;
        $text = trim($text);
        $fencePasses++;
    }
    $debug['fence_passes'] = $fencePasses;
    $debug['normalized_preview'] = st_ai_parse_debug_preview($text, 700, 240);
    $debug['brace_count'] = substr_count($text, '{');

    $flags = defined('JSON_INVALID_UTF8_SUBSTITUTE') ? JSON_INVALID_UTF8_SUBSTITUTE : 0;
    $depth = 2048;

    $recordCandidate = static function (int $at, ?string $slice, ?array $doc, string $role, string $jsonErr = '') use (&$debug): void {
        $row = ['offset' => $at];
        if ($slice === null) {
            $row['balanced'] = false;
            $row['note'] = 'unbalanced_or_truncated';
            $debug['candidates'][] = $row;
            return;
        }
        $row['balanced'] = true;
        $row['slice_len'] = strlen($slice);
        $row['slice_head'] = substr($slice, 0, 140);
        if (!is_array($doc)) {
            $row['decoded'] = false;
            if ($jsonErr !== '') {
                $row['json_error'] = $jsonErr;
            } else {
                $row['json_error'] = function_exists('json_last_error_msg') ? json_last_error_msg() : 'json_decode_failed';
            }
            $debug['candidates'][] = $row;
            return;
        }
        $row['decoded'] = true;
        $row['keys'] = array_slice(array_keys($doc), 0, 24);
        $row['is_scan_compact_echo'] = st_ai_json_looks_like_scan_compact_echo($doc);
        $row['role_match'] = $role === '' ? null : st_ai_json_object_matches_role($doc, $role);
        $debug['candidates'][] = $row;
    };

    $tryDecode = static function (?string $slice) use ($flags, $depth): array {
        if ($slice === null || $slice === '') {
            return ['doc' => null, 'err' => 'empty_slice'];
        }
        $doc = json_decode($slice, true, $depth, $flags);
        if (is_array($doc)) {
            return ['doc' => $doc, 'err' => ''];
        }
        $msg = function_exists('json_last_error_msg') ? json_last_error_msg() : 'json_decode_failed';
        return ['doc' => null, 'err' => $msg];
    };

    if ($text !== '' && $text[0] === '{') {
        $slice = $text;
        $td = $tryDecode($slice);
        $doc = $td['doc'];
        $recordCandidate(0, $slice, $doc, $role, (string)($td['err'] ?? ''));
        if (is_array($doc) && ($role === '' || st_ai_json_object_matches_role($doc, $role))) {
            $debug['outcome'] = 'ok_whole_string';
            return ['doc' => $doc, 'debug' => $debug];
        }
    }

    $pos = 0;
    $fallback = null;
    $candidateBudget = 14;
    while (($j = strpos($text, '{', $pos)) !== false) {
        $slice = st_ai_json_slice_balanced($text, $j);
        $td = $tryDecode($slice);
        $doc = $td['doc'];
        if (count($debug['candidates']) < $candidateBudget) {
            $recordCandidate($j, $slice, $doc, $role, (string)($td['err'] ?? ''));
        }
        if ($slice !== null && !is_array($doc)) {
            $pos = $j + 1;
            continue;
        }
        if (!is_array($doc)) {
            $pos = $j + 1;
            continue;
        }
        if ($role !== '') {
            if (st_ai_json_object_matches_role($doc, $role)) {
                $debug['outcome'] = 'ok_balanced_scan';
                return ['doc' => $doc, 'debug' => $debug];
            }
            if ($fallback === null && !st_ai_json_looks_like_scan_compact_echo($doc)) {
                $fallback = $doc;
            }
        } else {
            if (!st_ai_json_looks_like_scan_compact_echo($doc)) {
                $debug['outcome'] = 'ok_balanced_no_role';
                return ['doc' => $doc, 'debug' => $debug];
            }
            if ($fallback === null) {
                $fallback = $doc;
            }
        }
        $pos = $j + 1;
    }
    if ($role !== '' && $fallback !== null && st_ai_json_object_matches_role($fallback, $role)) {
        $debug['outcome'] = 'ok_fallback';
        return ['doc' => $fallback, 'debug' => $debug];
    }

    if ($debug['brace_count'] === 0) {
        $debug['outcome'] = 'no_open_brace';
    } elseif ($debug['candidates'] === []) {
        $debug['outcome'] = 'no_candidates';
    } else {
        $last = $debug['candidates'][count($debug['candidates']) - 1];
        if (($last['balanced'] ?? false) && ($last['decoded'] ?? false) && ($last['role_match'] ?? null) === false) {
            $debug['outcome'] = 'decoded_but_role_mismatch';
        } elseif (($last['decoded'] ?? false) === false && ($last['balanced'] ?? false)) {
            $debug['outcome'] = 'json_syntax_error';
        } else {
            $debug['outcome'] = 'no_matching_object';
        }
    }
    return ['doc' => null, 'debug' => $debug];
}

/**
 * @param 'scan_summary'|'explain_host'|'findings'|'' $role
 */
function st_ai_extract_json_object(string $text, string $role = ''): ?array {
    return st_ai_extract_json_object_with_debug($text, $role)['doc'];
}

/**
 * One-line hint for UI / summary_json (no multi-kilobyte model dump).
 */
function st_ai_parse_debug_client_hint(array $debug): string {
    $outcome = (string)($debug['outcome'] ?? 'unknown');
    foreach ($debug['candidates'] ?? [] as $c) {
        if (!is_array($c)) {
            continue;
        }
        if (($c['decoded'] ?? false) && array_key_exists('role_match', $c) && $c['role_match'] === false) {
            $keys = isset($c['keys']) && is_array($c['keys']) ? implode(',', $c['keys']) : '';
            return $outcome . ' wrong_shape keys=' . substr($keys, 0, 160);
        }
    }
    foreach ($debug['candidates'] ?? [] as $c) {
        if (!is_array($c)) {
            continue;
        }
        if (($c['balanced'] ?? false) && ($c['decoded'] ?? false) === false && !empty($c['json_error'])) {
            $off = (string)($c['offset'] ?? '?');
            return $outcome . ' @' . $off . ': ' . substr((string)$c['json_error'], 0, 140);
        }
    }
    if (($debug['brace_count'] ?? 0) === 0) {
        return $outcome . ' (no { in model text after cleanup)';
    }
    return $outcome . ' braces=' . (string)($debug['brace_count'] ?? 0);
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

/**
 * Union of current open_ports and ports seen in port_history snapshots (deduped, sorted).
 *
 * @param array<int|string,mixed> $basePorts
 * @param list<array{ports?:string}> $historyRows
 * @return list<int>
 */
function st_ai_merge_ports_with_history(array $basePorts, array $historyRows): array {
    $set = [];
    foreach ($basePorts as $p) {
        $i = (int)$p;
        if ($i >= 1 && $i <= 65535) {
            $set[$i] = true;
        }
    }
    foreach ($historyRows as $r) {
        $raw = $r['ports'] ?? '[]';
        $arr = is_string($raw) ? (json_decode($raw, true) ?: []) : (is_array($raw) ? $raw : []);
        if (!is_array($arr)) {
            continue;
        }
        foreach ($arr as $p) {
            $i = (int)$p;
            if ($i >= 1 && $i <= 65535) {
                $set[$i] = true;
            }
        }
    }
    $out = array_keys($set);
    sort($out, SORT_NUMERIC);
    return $out;
}

/**
 * All banner/title keys for the model, size-capped (not only the first N keys).
 *
 * @param array<string|int,string> $banners
 * @return list<string>
 */
function st_ai_banner_lines_for_prompt(array $banners, int $maxLines = 140, int $valMax = 120, int $maxTotalChars = 12000): array {
    if ($banners === []) {
        return [];
    }
    $keys = array_map('strval', array_keys($banners));
    sort($keys, SORT_NATURAL);
    $lines = [];
    $total = 0;
    foreach ($keys as $k) {
        if (count($lines) >= $maxLines) {
            break;
        }
        $v = $banners[$k] ?? '';
        $s = substr((string)preg_replace('/\s+/', ' ', trim((string)$v)), 0, $valMax);
        $line = $k . ':' . $s;
        if ($total + strlen($line) + 1 > $maxTotalChars) {
            break;
        }
        $lines[] = $line;
        $total += strlen($line) + 1;
    }
    return $lines;
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
            (string)($f['risk_score'] ?? ''),
            (string)($f['confidence'] ?? ''),
            (string)($f['detection_method'] ?? ''),
        ]);
    }
    return sha1(implode("\n", $parts));
}

function st_ai_explain_fingerprint(array $asset, array $ports, array $banners, int $openFindingCount, array $topCves): string {
    $portList = array_values(array_unique(array_map(static function ($p) {
        return (int)$p;
    }, $ports)));
    sort($portList, SORT_NUMERIC);
    $bcopy = $banners;
    ksort($bcopy, SORT_STRING);
    $bj = json_encode($bcopy, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($bj === false) {
        $bj = '';
    }
    $blob = implode('|', [
        (string)($asset['ip'] ?? ''),
        (string)($asset['hostname'] ?? ''),
        (string)($asset['category'] ?? ''),
        (string)($asset['vendor'] ?? ''),
        json_encode($portList, JSON_UNESCAPED_UNICODE),
        (string)$openFindingCount,
        implode(',', $topCves),
        sha1($bj),
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
        if (is_array($x)) {
            $role = trim((string)($x['role'] ?? ''));
            $conf = strtolower(trim((string)($x['confidence'] ?? '')));
            $evi = trim((string)($x['evidence'] ?? ''));
            if ($role === '') {
                continue;
            }
            if (!in_array($conf, ['high', 'medium', 'low'], true)) {
                $conf = '';
            }
            $parts = [$role];
            if ($conf !== '') {
                $parts[] = '(' . $conf . ')';
            }
            $s = implode(' ', $parts);
            if ($evi !== '') {
                $s .= ' — ' . $evi;
            }
        } else {
            $s = trim((string)$x);
        }
        if ($s !== '' && count($nr) < 4) {
            $nr[] = substr($s, 0, 100);
        }
    }
    $nt = [];
    foreach ($tips as $x) {
        $s = trim((string)$x);
        if ($s !== '' && count($nt) < 4) {
            $nt[] = substr($s, 0, 220);
        }
    }
    $nq = [];
    foreach ($qs as $x) {
        $s = trim((string)$x);
        if ($s !== '' && count($nq) < 3) {
            $nq[] = substr($s, 0, 180);
        }
    }
    $out = [];
    if ($overview !== '') {
        $out['overview'] = substr($overview, 0, 420);
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
// st_require_csrf() re-opened the session; release before DB + Ollama so other tabs/polls are not
// blocked for minutes on the session file lock (same pattern as api/feeds.php long POST paths).
st_release_session_lock();

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
            SELECT cve_id, cvss, severity, description, resolved,
                   risk_score, confidence, detection_method, evidence_json
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

        $portsForExplain = $ports;
        if ($action === 'explain_host') {
            try {
                $ph = $db->prepare(
                    'SELECT ports FROM port_history WHERE asset_id = ? ORDER BY seen_at DESC LIMIT 80'
                );
                $ph->execute([$assetId]);
                $portsForExplain = st_ai_merge_ports_with_history($ports, $ph->fetchAll(PDO::FETCH_ASSOC) ?: []);
            } catch (Throwable $e) {
                $portsForExplain = $ports;
            }
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
                $ev = '';
                if (!empty($f['evidence_json'])) {
                    $ej = json_decode((string)$f['evidence_json'], true);
                    if (is_array($ej) && !empty($ej['matched_cpe'])) {
                        $ev = ' cpe=' . substr((string)$ej['matched_cpe'], 0, 120);
                    }
                }
                $lines[] = sprintf(
                    '%s cvss=%s sev=%s risk_score=%s confidence=%s method=%s%s — %s',
                    (string)($f['cve_id'] ?? ''),
                    (string)($f['cvss'] ?? ''),
                    (string)($f['severity'] ?? ''),
                    (string)($f['risk_score'] ?? ''),
                    (string)($f['confidence'] ?? ''),
                    (string)($f['detection_method'] ?? ''),
                    $ev,
                    $desc
                );
            }
            $prompt = "You help network operators triage CVE findings. Output is NON-AUTHORITATIVE suggestions only.\n"
                . "Return ONLY JSON with keys: risk_summary (string, <=800 chars), remediation_bullets (array of <=8 short strings), "
                . "prioritize (string: what to patch or verify first), note (optional string: uncertainty/limitations).\n"
                . "Use practical language; do not claim exploitability without evidence.\n\n"
                . 'Host: ' . ($row['ip'] ?? '') . ' category=' . ($row['category'] ?? '') . ' hostname=' . ($row['hostname'] ?? '') . "\n"
                . "Open findings (CVE rows):\n" . implode("\n", $lines) . "\n";

            @set_time_limit(st_ai_operator_ollama_timeout_cap() + 120);
            @ignore_user_abort(true);
            // Host CVE triage: long prompts + local CPU can exceed 60s. Do not tie wall clock to
            // ai_timeout_ms (that knob is for daemon per-host enrichment, 100–5000 ms).
            $timeoutS = (float)st_ai_operator_ollama_timeout_cap();
            // Close PDO during Ollama so this Apache worker does not hold SQLite open for minutes.
            // st_db() reconnect is cheap after the first connect in this worker (migrations run once per worker).
            $stmt = null;
            $fstmt = null;
            st_db_release_connection();
            $db = null;
            $gen = st_ai_operator_completion($rt, $prompt, $timeoutS);
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

            $parse = st_ai_extract_json_object_with_debug($gen['text'], 'findings');
            $parsed = $parse['doc'];
            $parseDebug = $parse['debug'];
            $doc = st_ai_normalize_findings_doc($parsed);
            if (!$doc) {
                $hint = st_ai_parse_debug_client_hint($parseDebug);
                $envelope = [
                    'fp' => $fp,
                    'ts' => st_ai_iso_utc(),
                    'status' => 'failed',
                    'detail' => substr('no_json: ' . $hint, 0, 400),
                    'doc' => null,
                ];
                st_ai_save_asset_cache($db, $assetId, $cacheCol, $envelope);
                $logLine = json_encode(
                    ['ai_parse' => 'findings_guidance', 'asset_id' => $assetId, 'debug' => $parseDebug],
                    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
                );
                if (is_string($logLine)) {
                    @error_log('SurveyTrace ai_actions: ' . substr($logLine, 0, 12000));
                }
                st_json([
                    'ok' => false,
                    'error' => 'Could not parse model JSON',
                    'detail' => $hint,
                    'parse_debug' => $parseDebug,
                    'envelope' => $envelope,
                ], 502);
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
        $fp = st_ai_explain_fingerprint($row, $portsForExplain, $banners, $openCount, $topCves);

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

        $portInts = array_map('intval', $portsForExplain);
        $portOverflow = '';
        if (count($portInts) > 640) {
            $extra = count($portInts) - 640;
            $portInts = array_slice($portInts, 0, 640);
            $portOverflow = "\nNote: " . $extra . " additional open ports exist beyond the list above; mention that inventory is large if relevant.\n";
        }
        $portStr = implode(',', $portInts);
        $bMaxLines = max(12, min(200, (int)st_config('ai_operator_prompt_banner_max_lines', '72')));
        $bValMax = max(40, min(240, (int)st_config('ai_operator_prompt_banner_val_max', '96')));
        $bMaxChars = max(2000, min(20000, (int)st_config('ai_operator_prompt_banner_max_chars', '8000')));
        $bannerLines = st_ai_banner_lines_for_prompt($banners, $bMaxLines, $bValMax, $bMaxChars);
        $bannerTail = '';
        if ($bannerLines === []) {
            $bannerBlock = "(no banner/title strings stored)\n";
        } else {
            $bannerBlock = "Per-port banners and HTTP titles (use ALL lines; do not infer only from fingerprint category):\n"
                . implode("\n", $bannerLines) . "\n";
            $kcount = count(array_keys($banners));
            if ($kcount > count($bannerLines)) {
                $bannerTail = "(Some banner keys omitted from prompt due to size cap; still ground summary in listed evidence.)\n";
            }
        }
        $cpes = json_decode((string)($row['nmap_cpes'] ?? '[]'), true);
        if (!is_array($cpes)) {
            $cpes = [];
        }
        $cpes = array_values(array_filter(array_map('strval', $cpes), static function ($s) {
            return $s !== '';
        }));
        $cpesStr = implode(', ', array_slice($cpes, 0, 24));
        if (count($cpes) > 24) {
            $cpesStr .= ' …(+' . (string)(count($cpes) - 24) . ' more)';
        }
        $osGuess = trim((string)($row['os_guess'] ?? ''));
        $cpeGuess = trim((string)($row['cpe'] ?? ''));

        $prompt = "You analyze ONE discovered host for a network inventory operator.\n"
            . "Output STRICT JSON only with keys:\n"
            . "- overview: string (<=380 chars, single concise paragraph)\n"
            . "- likely_roles: array (<=4 objects with keys: role, confidence, evidence)\n"
            . "- hardening_tips: array (<=4 strings, each <=200 chars)\n"
            . "- owner_questions: array (<=3 short questions)\n\n"
            . "For likely_roles:\n"
            . "- role: short label\n"
            . "- confidence: one of [high, medium, low]\n"
            . "- evidence: brief justification using ports, banners, titles, or metadata\n"
            . "- Use HIGH only when multiple strong signals agree (ports + banners + model/vendor)\n"
            . "- Use MEDIUM when evidence is partial\n"
            . "- Use LOW when evidence is weak or conflicting\n\n"
            . "Prioritize evidence from open ports AND ALL banner/title lines. Use metadata (vendor/model/category/OS/CPE) only as supporting signals.\n"
            . "Do NOT infer services or roles without evidence. If evidence is weak or conflicting, explicitly say so in overview.\n"
            . "Be concrete, avoid fluff, no repetition.\n\n"
            . "HOST DATA\n"
            . "ip=" . ($row['ip'] ?? '')
            . " hostname=" . ($row['hostname'] ?? '')
            . " category=" . ($row['category'] ?? '')
            . " vendor=" . ($row['vendor'] ?? '')
            . " model=" . ($row['model'] ?? '') . "\n"
            . "os_guess=" . $osGuess
            . " cpe=" . $cpeGuess
            . " nmap_cpes=" . ($cpesStr !== '' ? $cpesStr : '—') . "\n"
            . "open_ports(all,current+history)=" . $portStr . $portOverflow . "\n"
            . "open_findings=" . $openCount
            . " top_cves=" . implode(',', $topCves) . "\n\n"
            . "BANNERS\n"
            . $bannerBlock
            . $bannerTail;

        @set_time_limit(st_ai_operator_ollama_timeout_cap() + 120);
        @ignore_user_abort(true);
        $timeoutS = (float)st_ai_operator_ollama_timeout_cap();
        $stmt = null;
        $fstmt = null;
        st_db_release_connection();
        $db = null;
        $gen = st_ai_operator_completion($rt, $prompt, $timeoutS);
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

        $parse = st_ai_extract_json_object_with_debug($gen['text'], 'explain_host');
        $parsed = $parse['doc'];
        $parseDebug = $parse['debug'];
        $doc = st_ai_normalize_explain_doc($parsed);
        if (!$doc) {
            $hint = st_ai_parse_debug_client_hint($parseDebug);
            $envelope = [
                'fp' => $fp,
                'ts' => st_ai_iso_utc(),
                'status' => 'failed',
                'detail' => substr('no_json: ' . $hint, 0, 400),
                'doc' => null,
            ];
            st_ai_save_asset_cache($db, $assetId, $cacheCol, $envelope);
            $logLine = json_encode(
                ['ai_parse' => 'explain_host', 'asset_id' => $assetId, 'debug' => $parseDebug],
                JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            );
            if (is_string($logLine)) {
                @error_log('SurveyTrace ai_actions: ' . substr($logLine, 0, 12000));
            }
            st_json([
                'ok' => false,
                'error' => 'Could not parse model JSON',
                'detail' => $hint,
                'parse_debug' => $parseDebug,
                'envelope' => $envelope,
            ], 502);
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

        $phasesRaw = $summary['phases'] ?? null;
        $phasesArr = null;
        if (is_array($phasesRaw)) {
            $phasesArr = $phasesRaw;
        } elseif (is_string($phasesRaw) && $phasesRaw !== '') {
            $pd = json_decode($phasesRaw, true);
            $phasesArr = is_array($pd) ? $pd : null;
        }
        $compact = [
            'profile' => $summary['profile'] ?? null,
            'scan_mode' => $summary['scan_mode'] ?? null,
            'target_cidr' => $summary['target_cidr'] ?? null,
            'phases' => $phasesArr,
            'assets_catalogued' => (int)($summary['assets_catalogued'] ?? 0),
            'hosts_found' => (int)($summary['hosts_found'] ?? 0),
            'open_ports_total' => (int)($summary['open_ports_total'] ?? 0),
            'open_findings' => (int)($summary['open_findings'] ?? 0),
            'severity_breakdown' => is_array($summary['severity_breakdown'] ?? null)
                ? $summary['severity_breakdown'] : [],
            'categories' => is_array($summary['categories'] ?? null) ? $summary['categories'] : [],
            'top_ports' => is_array($summary['top_ports'] ?? null) ? $summary['top_ports'] : [],
            'ai_enrichment_attempts' => (int)($summary['ai_enrichment_attempts'] ?? 0),
            'ai_enrichment_applied' => (int)($summary['ai_enrichment_applied'] ?? 0),
            'ai_reason_counts' => is_array($summary['ai_reason_counts'] ?? null) ? $summary['ai_reason_counts'] : [],
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

        $prompt = "You write a short executive brief for a completed network inventory scan (SurveyTrace). "
            . "The reader is an operator who already has the dashboard — interpret the JSON facts; do not repeat them as a table.\n\n"
            . "Return ONLY JSON with keys: overview (string, max 3 sentences), concerns (array, max 5 strings), "
            . "next_steps (array, max 5 strings).\n"
            . "Tone: practical and neutral; only use urgent language if severity_breakdown shows critical/high issues.\n\n"
            . "Content rules:\n"
            . "- Ground every point in the scan JSON (hosts_found vs assets_catalogued, categories, top_ports, open_findings, phases, "
            . "routed_net_overrides, ai_reason_counts).\n"
            . "- concerns: skip vague filler. If open_findings is 0, you may still flag exposure from top_ports, host/catalogue gaps, "
            . "or category skew (e.g. many srv/unk).\n"
            . "- next_steps: each string must be a concrete operational follow-up for THIS network (verify a segment, rescan with a "
            . "specific phase, reconcile host count, validate a port/service class, document an exception). "
            . "Do NOT tell the operator to review or tune AI features, models, or SurveyTrace AI settings.\n"
            . "- If ai_enrichment_attempts is 0 and ai_reason_counts is non-empty, briefly acknowledge why per-host relabel was skipped "
            . "(e.g. not_ambiguous) and name one inventory action that still adds value.\n"
            . "- Do not mention 'network overrides' or similar unless routed_net_overrides is greater than 0.\n\n"
            . "Scan data JSON:\n{$compactJson}\n";

        @set_time_limit(st_ai_operator_ollama_timeout_cap() + 120);
        @ignore_user_abort(true);
        $timeoutS = (float)st_ai_operator_ollama_timeout_cap();
        $jstmt = null;
        st_db_release_connection();
        $db = null;
        $gen = st_ai_operator_completion($rt, $prompt, $timeoutS);
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

        $parse = st_ai_extract_json_object_with_debug($gen['text'], 'scan_summary');
        $parsed = $parse['doc'];
        $parseDebug = $parse['debug'];
        if (!is_array($parsed)) {
            $hint = st_ai_parse_debug_client_hint($parseDebug);
            $summary['ai_scan_summary_status'] = 'failed';
            $summary['ai_scan_summary_detail'] = substr('no_json: ' . $hint, 0, 200);
            $upd = json_encode($summary, $flags);
            if ($upd !== false) {
                $db->prepare('UPDATE scan_jobs SET summary_json = ? WHERE id = ?')->execute([$upd, $jobId]);
            }
            $logLine = json_encode(
                ['ai_parse' => 'refresh_scan_summary', 'job_id' => $jobId, 'debug' => $parseDebug],
                JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            );
            if (is_string($logLine)) {
                @error_log('SurveyTrace ai_actions: ' . substr($logLine, 0, 12000));
            }
            st_json([
                'ok' => false,
                'error' => 'Could not parse model JSON',
                'detail' => $hint,
                'parse_debug' => $parseDebug,
            ], 502);
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
