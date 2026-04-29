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

/**
 * Decode JSON for operator AI / scan summary paths (UTF-8 tolerant when supported).
 */
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
