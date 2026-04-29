<?php
/**
 * SurveyTrace — shared Ollama /api/generate helpers for operator AI endpoints.
 */

/**
 * @return list<string>|null model names when API responds; null if unreachable
 */
function st_ai_ollama_api_tags(float $timeout_s = 1.5): ?array {
    $url = 'http://127.0.0.1:11434/api/tags';
    $raw = '';
    $ms = (int)max(200, min(5000, (int)($timeout_s * 1000)));
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, $ms);
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
    $ms = (int)max(500, min(120000, (int)($timeout_s * 1000)));
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, $ms);
        $res = curl_exec($ch);
        if (is_string($res)) {
            $raw = $res;
        }
        curl_close($ch);
    }
    if ($raw === '') {
        $ctx = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n",
                'content' => $body,
                'timeout' => max(1, (int)ceil($timeout_s)),
            ],
        ]);
        $res = @file_get_contents($url, false, $ctx);
        if (is_string($res)) {
            $raw = $res;
        }
    }
    if ($raw === '') {
        return ['ok' => false, 'text' => '', 'err' => 'empty_response'];
    }
    $doc = json_decode($raw, true);
    if (!is_array($doc)) {
        return ['ok' => false, 'text' => '', 'err' => 'bad_json'];
    }
    $out = trim((string)($doc['response'] ?? ''));
    if ($out === '') {
        return ['ok' => false, 'text' => '', 'err' => 'empty_model_output'];
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
