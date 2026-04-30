<?php

/**
 * SurveyTrace — OpenAI / Anthropic / Google (Gemini) / Open WebUI completions for operator AI.
 * Env overrides DB: OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY or GOOGLE_API_KEY,
 * OPENWEBUI_BASE_URL, OPENWEBUI_API_KEY.
 */

declare(strict_types=1);

/**
 * @return array{ok: bool, text: string, err: string}
 */
function st_ai_cloud_http_post_json(string $url, array $headers, string $jsonBody, float $timeout_s): array {
    $cap = st_ai_operator_ollama_timeout_cap();
    $timeoutSec = max(1, min($cap, (int)ceil($timeout_s)));
    $connectSec = max(2, min(30, (int)ceil($timeout_s / 4)));
    if ($connectSec > $timeoutSec) {
        $connectSec = min($connectSec, $timeoutSec);
    }
    $raw = '';
    $curlNote = '';
    $httpCode = 0;
    $hdrLines = [];
    foreach ($headers as $k => $v) {
        $hdrLines[] = $k . ': ' . $v;
    }
    if (!function_exists('curl_init')) {
        return ['ok' => false, 'text' => '', 'err' => 'curl extension required for cloud AI'];
    }
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonBody);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $hdrLines);
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
    }
    if ($raw === '') {
        $hint = $curlNote !== '' ? $curlNote : ('HTTP ' . (string)$httpCode . ' empty body');
        return ['ok' => false, 'text' => '', 'err' => 'empty_response: ' . substr($hint, 0, 220)];
    }
    $doc = json_decode($raw, true);
    if ($httpCode >= 400) {
        $msg = '';
        if (is_array($doc)) {
            if (isset($doc['error']) && is_array($doc['error'])) {
                $msg = trim((string)($doc['error']['message'] ?? ''));
            }
            if ($msg === '') {
                $msg = trim((string)($doc['error'] ?? ''));
            }
        }
        if ($msg === '') {
            $msg = 'HTTP ' . (string)$httpCode . ' ' . substr(trim($raw), 0, 200);
        }
        return ['ok' => false, 'text' => '', 'err' => 'api_error: ' . substr($msg, 0, 400)];
    }
    if (!is_array($doc)) {
        return ['ok' => false, 'text' => '', 'err' => 'bad_json: ' . substr(trim($raw), 0, 200)];
    }
    return ['ok' => true, 'text' => $raw, 'err' => ''];
}

function st_ai_resolve_openai_key(): string {
    $e = trim((string)(getenv('OPENAI_API_KEY') ?: ''));
    if ($e !== '') {
        return $e;
    }
    return trim((string)st_config('ai_openai_api_key', ''));
}

function st_ai_resolve_anthropic_key(): string {
    $e = trim((string)(getenv('ANTHROPIC_API_KEY') ?: ''));
    if ($e !== '') {
        return $e;
    }
    return trim((string)st_config('ai_anthropic_api_key', ''));
}

function st_ai_resolve_gemini_key(): string {
    foreach (['GEMINI_API_KEY', 'GOOGLE_API_KEY'] as $ek) {
        $e = trim((string)(getenv($ek) ?: ''));
        if ($e !== '') {
            return $e;
        }
    }
    return trim((string)st_config('ai_gemini_api_key', ''));
}

function st_ai_resolve_openwebui_base(): string {
    $e = trim((string)(getenv('OPENWEBUI_BASE_URL') ?: ''));
    if ($e !== '') {
        return rtrim($e, '/');
    }
    return rtrim(trim((string)st_config('ai_openwebui_base_url', '')), '/');
}

function st_ai_resolve_openwebui_key(): string {
    $e = trim((string)(getenv('OPENWEBUI_API_KEY') ?: ''));
    if ($e !== '') {
        return $e;
    }
    return trim((string)st_config('ai_openwebui_api_key', ''));
}

function st_ai_openwebui_base_url_valid(string $base): bool {
    if ($base === '' || !preg_match('#^https?://#i', $base)) {
        return false;
    }
    $u = filter_var($base, FILTER_VALIDATE_URL);
    return is_string($u) && $u !== '';
}

/**
 * @return array{ok: bool, text: string, err: string}
 */
function st_ai_parse_openai_style_chat_response(string $raw, string $ctxLabel): array {
    $doc = json_decode($raw, true);
    if (!is_array($doc)) {
        return ['ok' => false, 'text' => '', 'err' => $ctxLabel . '_bad_json'];
    }
    $txt = trim((string)($doc['choices'][0]['message']['content'] ?? ''));
    if ($txt === '') {
        return ['ok' => false, 'text' => '', 'err' => $ctxLabel . '_empty_content'];
    }
    return ['ok' => true, 'text' => $txt, 'err' => ''];
}

function st_ai_cloud_provider_ready(string $provider): bool {
    $p = strtolower(trim($provider));
    return match ($p) {
        'openai' => st_ai_resolve_openai_key() !== '',
        'anthropic' => st_ai_resolve_anthropic_key() !== '',
        'google' => st_ai_resolve_gemini_key() !== '',
        'openwebui' => st_ai_openwebui_base_url_valid(st_ai_resolve_openwebui_base())
            && st_ai_resolve_openwebui_key() !== '',
        default => false,
    };
}

function st_ai_cloud_max_out_tokens(): int {
    $n = (int)st_config('ai_operator_ollama_num_predict', '768');
    if ($n <= 0) {
        return 2048;
    }
    return max(256, min(8192, $n));
}

/**
 * @return array{ok: bool, text: string, err: string}
 */
function st_ai_cloud_completion(string $provider, string $model, string $prompt, float $timeout_s): array {
    $model = trim($model);
    if ($model === '') {
        return ['ok' => false, 'text' => '', 'err' => 'empty_model'];
    }
    $temp = max(0.0, min(2.0, (float)st_config('ai_operator_ollama_temperature', '0.25')));
    $maxTok = st_ai_cloud_max_out_tokens();
    $p = strtolower(trim($provider));

    if ($p === 'openai') {
        $key = st_ai_resolve_openai_key();
        if ($key === '') {
            return ['ok' => false, 'text' => '', 'err' => 'missing_openai_api_key'];
        }
        $body = [
            'model' => $model,
            'messages' => [
                ['role' => 'user', 'content' => $prompt],
            ],
            'temperature' => $temp,
            'max_tokens' => $maxTok,
        ];
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
        if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
            $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
        }
        $json = json_encode($body, $flags);
        if ($json === false) {
            return ['ok' => false, 'text' => '', 'err' => 'json_encode_failed'];
        }
        $res = st_ai_cloud_http_post_json(
            'https://api.openai.com/v1/chat/completions',
            [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $key,
            ],
            $json,
            $timeout_s
        );
        if (!$res['ok']) {
            return $res;
        }
        $parsed = st_ai_parse_openai_style_chat_response($res['text'], 'openai');
        return $parsed['ok'] ? ['ok' => true, 'text' => $parsed['text'], 'err' => ''] : $parsed;
    }

    if ($p === 'openwebui') {
        $base = st_ai_resolve_openwebui_base();
        $key = st_ai_resolve_openwebui_key();
        if (!st_ai_openwebui_base_url_valid($base)) {
            return ['ok' => false, 'text' => '', 'err' => 'missing_or_invalid_openwebui_base_url'];
        }
        if ($key === '') {
            return ['ok' => false, 'text' => '', 'err' => 'missing_openwebui_api_key'];
        }
        $body = [
            'model' => $model,
            'messages' => [
                ['role' => 'user', 'content' => $prompt],
            ],
            'temperature' => $temp,
            'max_tokens' => $maxTok,
        ];
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
        if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
            $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
        }
        $json = json_encode($body, $flags);
        if ($json === false) {
            return ['ok' => false, 'text' => '', 'err' => 'json_encode_failed'];
        }
        $url = $base . '/api/chat/completions';
        $res = st_ai_cloud_http_post_json(
            $url,
            [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $key,
            ],
            $json,
            $timeout_s
        );
        if (!$res['ok']) {
            return $res;
        }
        $parsed = st_ai_parse_openai_style_chat_response($res['text'], 'openwebui');
        return $parsed['ok'] ? ['ok' => true, 'text' => $parsed['text'], 'err' => ''] : $parsed;
    }

    if ($p === 'anthropic') {
        $key = st_ai_resolve_anthropic_key();
        if ($key === '') {
            return ['ok' => false, 'text' => '', 'err' => 'missing_anthropic_api_key'];
        }
        $body = [
            'model' => $model,
            'max_tokens' => $maxTok,
            'temperature' => $temp,
            'messages' => [
                ['role' => 'user', 'content' => $prompt],
            ],
        ];
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
        if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
            $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
        }
        $json = json_encode($body, $flags);
        if ($json === false) {
            return ['ok' => false, 'text' => '', 'err' => 'json_encode_failed'];
        }
        $res = st_ai_cloud_http_post_json(
            'https://api.anthropic.com/v1/messages',
            [
                'Content-Type' => 'application/json',
                'x-api-key' => $key,
                'anthropic-version' => '2023-06-01',
            ],
            $json,
            $timeout_s
        );
        if (!$res['ok']) {
            return $res;
        }
        $doc = json_decode($res['text'], true);
        if (!is_array($doc)) {
            return ['ok' => false, 'text' => '', 'err' => 'anthropic_bad_json'];
        }
        $blocks = $doc['content'] ?? [];
        $txt = '';
        if (is_array($blocks)) {
            foreach ($blocks as $b) {
                if (is_array($b) && ($b['type'] ?? '') === 'text') {
                    $txt .= (string)($b['text'] ?? '');
                }
            }
        }
        $txt = trim($txt);
        if ($txt === '') {
            return ['ok' => false, 'text' => '', 'err' => 'anthropic_empty_content'];
        }
        return ['ok' => true, 'text' => $txt, 'err' => ''];
    }

    if ($p === 'google') {
        $key = st_ai_resolve_gemini_key();
        if ($key === '') {
            return ['ok' => false, 'text' => '', 'err' => 'missing_gemini_api_key'];
        }
        $mid = rawurlencode($model);
        $url = 'https://generativelanguage.googleapis.com/v1beta/models/' . $mid . ':generateContent?key=' . rawurlencode($key);
        $body = [
            'contents' => [
                ['parts' => [['text' => $prompt]]],
            ],
            'generationConfig' => [
                'temperature' => $temp,
                'maxOutputTokens' => $maxTok,
            ],
        ];
        $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
        if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
            $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
        }
        $json = json_encode($body, $flags);
        if ($json === false) {
            return ['ok' => false, 'text' => '', 'err' => 'json_encode_failed'];
        }
        $res = st_ai_cloud_http_post_json(
            $url,
            ['Content-Type' => 'application/json'],
            $json,
            $timeout_s
        );
        if (!$res['ok']) {
            return $res;
        }
        $doc = json_decode($res['text'], true);
        if (!is_array($doc)) {
            return ['ok' => false, 'text' => '', 'err' => 'gemini_bad_json'];
        }
        if (!empty($doc['error'])) {
            $em = is_array($doc['error']) ? trim((string)($doc['error']['message'] ?? '')) : trim((string)$doc['error']);
            return ['ok' => false, 'text' => '', 'err' => 'gemini_api: ' . substr($em !== '' ? $em : json_encode($doc['error']), 0, 300)];
        }
        $parts = $doc['candidates'][0]['content']['parts'] ?? [];
        $txt = '';
        if (is_array($parts)) {
            foreach ($parts as $pt) {
                if (is_array($pt)) {
                    $txt .= (string)($pt['text'] ?? '');
                }
            }
        }
        $txt = trim($txt);
        if ($txt === '') {
            $fb = trim((string)($doc['promptFeedback']['blockReason'] ?? ''));
            $hint = $fb !== '' ? ('blocked: ' . $fb) : 'gemini_empty_content';
            return ['ok' => false, 'text' => '', 'err' => $hint];
        }
        return ['ok' => true, 'text' => $txt, 'err' => ''];
    }

    return ['ok' => false, 'text' => '', 'err' => 'unsupported_cloud_provider'];
}
