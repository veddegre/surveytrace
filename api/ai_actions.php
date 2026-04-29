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
    if (stripos($msg, 'lib_ai_ollama') !== false || stripos($msg, 'Failed opening required') !== false) {
        $hint = 'Deploy api/lib_ai_ollama.php next to api/ai_actions.php (see deploy.sh).';
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
require_once __DIR__ . '/lib_ai_ollama.php';

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

            @set_time_limit(120);
            @ignore_user_abort(true);
            $timeoutS = max(8.0, min(90.0, ($rt['timeout_ms'] / 1000.0) * 10.0));
            $gen = st_ai_ollama_generate($rt['model'], $prompt, $timeoutS);
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

        @set_time_limit(120);
        @ignore_user_abort(true);
        $timeoutS = max(8.0, min(90.0, ($rt['timeout_ms'] / 1000.0) * 10.0));
        $gen = st_ai_ollama_generate($rt['model'], $prompt, $timeoutS);
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

        @set_time_limit(120);
        @ignore_user_abort(true);
        $timeoutS = max(5.0, min(90.0, ($rt['timeout_ms'] / 1000.0) * 8.0));
        $gen = st_ai_ollama_generate($rt['model'], $prompt, $timeoutS);
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
