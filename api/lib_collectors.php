<?php
/**
 * SurveyTrace collector control-plane helpers.
 */
declare(strict_types=1);

require_once __DIR__ . '/db.php';

function st_collector_bootstrap_schema(): void {
    $db = st_db();
    $db->exec(
        "CREATE TABLE IF NOT EXISTS collectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            site_label TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            version TEXT DEFAULT '',
            capabilities_json TEXT DEFAULT '{}',
            token_issued_at DATETIME,
            token_expires_at DATETIME,
            revoked_at DATETIME,
            last_seen_at DATETIME,
            last_ip TEXT,
            last_error TEXT,
            max_rps REAL DEFAULT 5,
            max_submit_mbps REAL DEFAULT 8,
            allowed_cidrs_json TEXT DEFAULT '[]',
            schedule_ids_json TEXT DEFAULT '[]',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );
    $collectorCols = array_column($db->query("PRAGMA table_info(collectors)")->fetchAll(), 'name');
    if (!in_array('allowed_cidrs_json', $collectorCols, true)) {
        $db->exec("ALTER TABLE collectors ADD COLUMN allowed_cidrs_json TEXT DEFAULT '[]'");
    }
    $db->exec("CREATE INDEX IF NOT EXISTS idx_collectors_status ON collectors(status, last_seen_at DESC)");

    $db->exec(
        "CREATE TABLE IF NOT EXISTS collector_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            collector_id INTEGER NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            token_hint TEXT,
            scopes_json TEXT NOT NULL,
            issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            revoked_at DATETIME
        )"
    );
    $db->exec("CREATE INDEX IF NOT EXISTS idx_collector_tokens_collector ON collector_tokens(collector_id, revoked_at)");

    $db->exec(
        "CREATE TABLE IF NOT EXISTS collector_job_leases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL UNIQUE REFERENCES scan_jobs(id) ON DELETE CASCADE,
            collector_id INTEGER NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
            lease_token TEXT NOT NULL,
            leased_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            lease_expires_at DATETIME NOT NULL,
            last_heartbeat_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    );
    $db->exec("CREATE INDEX IF NOT EXISTS idx_collector_job_leases_collector ON collector_job_leases(collector_id, lease_expires_at)");

    $db->exec(
        "CREATE TABLE IF NOT EXISTS collector_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            collector_id INTEGER NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
            job_id INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
            submission_id TEXT NOT NULL,
            chunk_count INTEGER NOT NULL DEFAULT 1,
            received_chunks INTEGER NOT NULL DEFAULT 0,
            processed_chunks INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'receiving',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(collector_id, job_id, submission_id)
        )"
    );
    $db->exec("CREATE INDEX IF NOT EXISTS idx_collector_submissions_job ON collector_submissions(job_id, status)");

    $db->exec(
        "CREATE TABLE IF NOT EXISTS collector_ingest_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            collector_id INTEGER NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
            job_id INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
            submission_id TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            chunk_count INTEGER NOT NULL,
            content_sha256 TEXT NOT NULL,
            local_relpath TEXT NOT NULL,
            artifact_uri TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at DATETIME,
            error_msg TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            processed_at DATETIME,
            UNIQUE(collector_id, job_id, submission_id, chunk_index)
        )"
    );
    $db->exec("CREATE INDEX IF NOT EXISTS idx_collector_ingest_pending ON collector_ingest_queue(status, next_attempt_at, created_at)");

    $db->exec(
        "CREATE TABLE IF NOT EXISTS collector_rate_limits (
            collector_id INTEGER NOT NULL,
            endpoint_key TEXT NOT NULL,
            window_start INTEGER NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (collector_id, endpoint_key, window_start)
        )"
    );

    foreach ([
        'collector_install_token' => '',
        'collector_token_ttl_hours' => '720',
        'collector_lease_seconds' => '600',
        'collector_rate_default_rps' => '5',
        'collector_submit_max_mb' => '8',
        'collector_artifact_store' => 's3',
        'collector_artifact_s3_endpoint' => '',
        'collector_artifact_s3_bucket' => '',
        'collector_artifact_s3_region' => 'us-east-1',
        'collector_artifact_s3_access_key' => '',
        'collector_artifact_s3_secret_key' => '',
        'collector_artifact_s3_prefix' => 'surveytrace/collector-artifacts',
        'collector_artifact_s3_path_style' => '1',
        'collector_artifact_s3_tls_verify' => '1',
    ] as $k => $v) {
        $db->prepare("INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)")->execute([$k, $v]);
    }
}

function st_collector_token_hash(string $token): string {
    return hash('sha256', $token);
}

function st_collector_new_token(): string {
    return 'stc_' . bin2hex(random_bytes(32));
}

function st_collector_bearer_token(): string {
    $hdr = trim((string)($_SERVER['HTTP_AUTHORIZATION'] ?? ''));
    if ($hdr === '' || stripos($hdr, 'bearer ') !== 0) {
        return '';
    }
    return trim(substr($hdr, 7));
}

/**
 * @return array{collector_id:int,scopes:array,token_id:int}
 */
function st_collector_auth_required(string $requiredScope): array {
    st_collector_bootstrap_schema();
    $tok = st_collector_bearer_token();
    if ($tok === '') {
        st_json(['ok' => false, 'error' => 'Collector bearer token required'], 401);
    }
    $hash = st_collector_token_hash($tok);
    $stmt = st_db()->prepare(
        "SELECT t.id AS token_id, t.collector_id, t.scopes_json, t.expires_at, t.revoked_at,
                c.status, c.revoked_at AS collector_revoked_at
         FROM collector_tokens t
         JOIN collectors c ON c.id = t.collector_id
         WHERE t.token_hash = ?
         LIMIT 1"
    );
    $stmt->execute([$hash]);
    $row = $stmt->fetch();
    if (!$row) {
        st_json(['ok' => false, 'error' => 'Invalid collector token'], 401);
    }
    if (!empty($row['revoked_at']) || !empty($row['collector_revoked_at']) || (string)($row['status'] ?? '') === 'revoked') {
        st_json(['ok' => false, 'error' => 'Collector token revoked'], 401);
    }
    $exp = trim((string)($row['expires_at'] ?? ''));
    if ($exp !== '' && strtotime($exp) !== false && strtotime($exp) < time()) {
        st_json(['ok' => false, 'error' => 'Collector token expired'], 401);
    }
    $scopes = json_decode((string)($row['scopes_json'] ?? '[]'), true);
    if (!is_array($scopes)) {
        $scopes = [];
    }
    if (!in_array($requiredScope, $scopes, true)) {
        st_json(['ok' => false, 'error' => 'Collector scope denied', 'required_scope' => $requiredScope], 403);
    }
    return [
        'collector_id' => (int)$row['collector_id'],
        'scopes' => $scopes,
        'token_id' => (int)$row['token_id'],
    ];
}

/**
 * @return array{token:string,expires_at:string}
 */
function st_collector_issue_token(int $collectorId, array $scopes): array {
    $ttl = max(1, min(24 * 365, (int)st_config('collector_token_ttl_hours', '720')));
    $token = st_collector_new_token();
    $tokenHash = st_collector_token_hash($token);
    $hint = substr($token, 0, 8) . '...' . substr($token, -6);
    $expiresAt = gmdate('Y-m-d H:i:s', time() + ($ttl * 3600));
    st_db()->prepare(
        "INSERT INTO collector_tokens (collector_id, token_hash, token_hint, scopes_json, expires_at)
         VALUES (?, ?, ?, ?, ?)"
    )->execute([$collectorId, $tokenHash, $hint, json_encode(array_values(array_unique($scopes))), $expiresAt]);
    st_db()->prepare(
        "UPDATE collectors
         SET token_issued_at=datetime('now'), token_expires_at=?, revoked_at=NULL, status='online', updated_at=datetime('now')
         WHERE id=?"
    )->execute([$expiresAt, $collectorId]);
    return ['token' => $token, 'expires_at' => $expiresAt];
}

function st_collector_rate_limit(int $collectorId, string $endpointKey, float $maxRps): void {
    $db = st_db();
    $nowWindow = (int)floor(time());
    $maxReq = max(1, (int)ceil($maxRps));
    $db->prepare(
        "INSERT INTO collector_rate_limits (collector_id, endpoint_key, window_start, request_count)
         VALUES (?, ?, ?, 1)
         ON CONFLICT(collector_id, endpoint_key, window_start)
         DO UPDATE SET request_count = request_count + 1"
    )->execute([$collectorId, $endpointKey, $nowWindow]);
    $stmt = $db->prepare(
        "SELECT request_count
         FROM collector_rate_limits
         WHERE collector_id=? AND endpoint_key=? AND window_start=?"
    );
    $stmt->execute([$collectorId, $endpointKey, $nowWindow]);
    $count = (int)$stmt->fetchColumn();
    if ($count > $maxReq) {
        st_json(['ok' => false, 'error' => 'Collector rate limit exceeded'], 429);
    }
    // Light cleanup to keep table compact.
    $db->prepare("DELETE FROM collector_rate_limits WHERE window_start < ?")->execute([$nowWindow - 120]);
}

function st_collector_data_dir(): string {
    $dir = ST_DATA_DIR . '/collector_ingest';
    if (!is_dir($dir)) {
        @mkdir($dir, 0770, true);
    }
    return $dir;
}

function st_collector_parse_cidrs(string $raw): array {
    $out = [];
    $parts = preg_split('/[\s,]+/', trim($raw));
    if (!is_array($parts)) {
        return [];
    }
    foreach ($parts as $p) {
        $p = trim((string)$p);
        if ($p === '') {
            continue;
        }
        if (filter_var($p, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $out[] = $p . '/32';
            continue;
        }
        if (!preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/', $p, $m)) {
            continue;
        }
        $ip = $m[1];
        $prefix = (int)$m[2];
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            continue;
        }
        if ($prefix < 0 || $prefix > 32) {
            continue;
        }
        $out[] = $ip . '/' . $prefix;
    }
    return array_values(array_unique($out));
}

function st_collector_cidrs_overlap(string $a, string $b): bool {
    $pa = explode('/', $a);
    $pb = explode('/', $b);
    if (count($pa) !== 2 || count($pb) !== 2) return false;
    $aIp = ip2long($pa[0]);
    $bIp = ip2long($pb[0]);
    $aPre = (int)$pa[1];
    $bPre = (int)$pb[1];
    if ($aIp === false || $bIp === false) return false;
    $aMask = $aPre === 0 ? 0 : (~((1 << (32 - $aPre)) - 1) & 0xFFFFFFFF);
    $bMask = $bPre === 0 ? 0 : (~((1 << (32 - $bPre)) - 1) & 0xFFFFFFFF);
    $aNet = ((int)$aIp) & $aMask;
    $bNet = ((int)$bIp) & $bMask;
    return ($aNet <= ($bNet | (~$bMask & 0xFFFFFFFF))) && ($bNet <= ($aNet | (~$aMask & 0xFFFFFFFF)));
}

function st_collector_target_allowed(int $collectorId, string $targetRaw): bool {
    if ($collectorId <= 0) {
        return true;
    }
    $stmt = st_db()->prepare("SELECT allowed_cidrs_json FROM collectors WHERE id=? LIMIT 1");
    $stmt->execute([$collectorId]);
    $allowRaw = (string)($stmt->fetchColumn() ?? '');
    $allow = json_decode($allowRaw, true);
    if (!is_array($allow)) {
        $allow = [];
    }
    $allow = array_values(array_filter(array_map('strval', $allow)));
    if (!$allow) {
        return true;
    }
    $targets = st_collector_parse_cidrs($targetRaw);
    if (!$targets) {
        return false;
    }
    foreach ($targets as $t) {
        $ok = false;
        foreach ($allow as $a) {
            if (st_collector_cidrs_overlap($t, $a)) {
                $ok = true;
                break;
            }
        }
        if (!$ok) {
            return false;
        }
    }
    return true;
}

function st_s3_sigv4_put(
    string $endpoint,
    string $bucket,
    string $region,
    string $accessKey,
    string $secretKey,
    string $objectKey,
    string $body,
    bool $pathStyle = true,
    bool $tlsVerify = true
): bool {
    if (!function_exists('curl_init')) {
        return false;
    }
    $ep = rtrim($endpoint, '/');
    $host = parse_url($ep, PHP_URL_HOST);
    $scheme = parse_url($ep, PHP_URL_SCHEME);
    if (!is_string($host) || $host === '' || !in_array($scheme, ['http', 'https'], true)) {
        return false;
    }
    $encodedKey = implode('/', array_map('rawurlencode', explode('/', ltrim($objectKey, '/'))));
    $path = $pathStyle ? '/' . rawurlencode($bucket) . '/' . $encodedKey : '/' . $encodedKey;
    $url = $pathStyle ? ($ep . $path) : ($scheme . '://' . rawurlencode($bucket) . '.' . $host . $path);
    $t = gmdate('Ymd\THis\Z');
    $d = gmdate('Ymd');
    $service = 's3';
    $payloadHash = hash('sha256', $body);
    $signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
    $canonicalHeaders = "host:$host\nx-amz-content-sha256:$payloadHash\nx-amz-date:$t\n";
    $canonicalRequest = "PUT\n$path\n\n$canonicalHeaders\n$signedHeaders\n$payloadHash";
    $scope = "$d/$region/$service/aws4_request";
    $stringToSign = "AWS4-HMAC-SHA256\n$t\n$scope\n" . hash('sha256', $canonicalRequest);
    $kDate = hash_hmac('sha256', $d, 'AWS4' . $secretKey, true);
    $kRegion = hash_hmac('sha256', $region, $kDate, true);
    $kService = hash_hmac('sha256', $service, $kRegion, true);
    $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
    $signature = hash_hmac('sha256', $stringToSign, $kSigning);
    $auth = "AWS4-HMAC-SHA256 Credential=$accessKey/$scope, SignedHeaders=$signedHeaders, Signature=$signature";

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: ' . $auth,
        'x-amz-date: ' . $t,
        'x-amz-content-sha256: ' . $payloadHash,
        'Content-Type: application/json',
    ]);
    if (!$tlsVerify) {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    }
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    $res = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return $res !== false && $code >= 200 && $code < 300;
}

/**
 * @return array{local_relpath:string,artifact_uri:string,sha256:string}
 */
function st_collector_store_artifact(string $submissionId, int $chunkIndex, string $payloadJson): array {
    $sha = hash('sha256', $payloadJson);
    $datePart = gmdate('Y/m/d');
    $baseName = preg_replace('/[^A-Za-z0-9._-]/', '_', $submissionId) ?: 'submission';
    $rel = $datePart . '/' . $baseName . '-chunk' . $chunkIndex . '.json';
    $abs = st_collector_data_dir() . '/' . $rel;
    $dir = dirname($abs);
    if (!is_dir($dir)) {
        @mkdir($dir, 0770, true);
    }
    file_put_contents($abs, $payloadJson, LOCK_EX);

    $artifactUri = 'file://' . $rel;
    if (st_config('collector_artifact_store', 's3') === 's3') {
        $endpoint = trim(st_config('collector_artifact_s3_endpoint', ''));
        $bucket = trim(st_config('collector_artifact_s3_bucket', ''));
        $region = trim(st_config('collector_artifact_s3_region', 'us-east-1'));
        $ak = trim(st_config('collector_artifact_s3_access_key', ''));
        $sk = trim(st_config('collector_artifact_s3_secret_key', ''));
        $prefix = trim(st_config('collector_artifact_s3_prefix', 'surveytrace/collector-artifacts'), '/');
        $pathStyle = st_config('collector_artifact_s3_path_style', '1') === '1';
        $tlsVerify = st_config('collector_artifact_s3_tls_verify', '1') === '1';
        if ($endpoint !== '' && $bucket !== '' && $ak !== '' && $sk !== '') {
            $key = ($prefix !== '' ? ($prefix . '/') : '') . $rel;
            $ok = st_s3_sigv4_put($endpoint, $bucket, $region, $ak, $sk, $key, $payloadJson, $pathStyle, $tlsVerify);
            if ($ok) {
                $artifactUri = 's3://' . $bucket . '/' . $key;
            }
        }
    }
    return ['local_relpath' => $rel, 'artifact_uri' => $artifactUri, 'sha256' => $sha];
}
